#include "../Common/CarbonWindows.h"

#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
import <fstream>;
import <thread>;
import <vector>;
import <map>;
import <filesystem>;
import <mutex>;

import Luau;
import Logger;
import Console;
import FunctionMarker;
import GlobalSettings;
import LuaEnv;
import HookHandler;
import Pipes;
import SharedAddresses;
import StringUtils;
import RiblixStructures;
import CarbonLuaApiLibs.closurelib;
import TaskList;
import DataModelWatcher;
import Formatter;
import Exception;
import GlobalState;

lua_State* lua_newstate_hook(void* allocator, void* userdata)
{
	auto original = hookHandler.getHook(HookId::lua_newstate).getOriginal();
	auto result = reinterpret_cast<decltype(luaApiAddresses.lua_newstate)>(original)(allocator, userdata);

	dataModelWatcher.stateWatcher.onGlobalStateCreated(result);

	return result;
}

void flog1_hook(void* junk, const char* formatString, void* object)
{
	if (!strcmp(formatString, "[FLog::CloseDataModel] doCloseDataModel - %p"))
	{
		dataModelWatcher.onDataModelClosing((DataModel*)object);
	}

	auto original = hookHandler.getHook(HookId::FLOG1).getOriginal();
	reinterpret_cast<decltype(riblixAddresses.FLOG1)>(original)(junk, formatString, object);
}

HMODULE ghModule;
SharedMemoryContentDeserialized sharedMemoryContent;

void realMain()
{
	basicTryWrapper("realMain", [&]() {
		try
		{
			hookHandler.getHook(HookId::DispatchMessageW).remove();
			globalState.init(ghModule, sharedMemoryContent.settingsPath, sharedMemoryContent.userDirectoryPath);

			hookHandler.getHook(HookId::growCI)
				.setTarget(luaApiAddresses.luaD_growCI)
				.setHook(luaD_growCI_hook)
				.setup();

			hookHandler.getHook(HookId::FLOG1)
				.setTarget(riblixAddresses.FLOG1)
				.setHook(flog1_hook)
				.setup();

			taskListProcessor.createRunThread();

			globalState.startPipesReading();
		}
		catch (lua_exception& e)
		{
			logger.log(e.what());
		}
	});
}

LRESULT WINAPI DispatchMessageW_Hook(void* msg)
{
	static std::once_flag mainInitFlag;
	std::call_once(mainInitFlag, [&]() {
		std::thread mainThread(realMain);
		mainThread.detach();
	});

	auto original = hookHandler.getHook(HookId::DispatchMessageW).getOriginal();
	using DispatchMessageW_t = LRESULT(__stdcall*)(void*);
	return reinterpret_cast<DispatchMessageW_t>(original)(msg);
}

SharedMemoryContentDeserialized deserializeSharedMemory()
{
	HandleScope mapFile = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, sharedMemoryName);
	if (!mapFile)
		raise("failed to open shared memory", formatLastError());

	auto data = (char*)MapViewOfFile(mapFile, FILE_MAP_ALL_ACCESS, 0, 0, sharedMemorySize);
	auto content = (SharedMemoryContent*)data;
	if (!content)
		raise("failed map view shared memory", formatLastError());

	return content->deserialize();
}

std::string getStackTrace(CONTEXT* context)
{
	auto process = GetCurrentProcess();
	auto thread = GetCurrentThread();

	SymInitialize(process, NULL, TRUE);

	STACKFRAME64 stackFrame;
	memset(&stackFrame, 0, sizeof(STACKFRAME64));

	stackFrame.AddrPC.Offset = context->Rip;
	stackFrame.AddrPC.Mode = AddrModeFlat;
	stackFrame.AddrFrame.Offset = context->Rbp;
	stackFrame.AddrFrame.Mode = AddrModeFlat;
	stackFrame.AddrStack.Offset = context->Rsp;
	stackFrame.AddrStack.Mode = AddrModeFlat;

	std::ostringstream result;
	result << "call Stack:\n";

	int frameIndex = 0;
	while (StackWalk64(
		IMAGE_FILE_MACHINE_AMD64,
		process,
		thread,
		&stackFrame,
		context,
		0,
		SymFunctionTableAccess64,
		SymGetModuleBase64,
		0
	))
	{
		uintptr_t address = stackFrame.AddrPC.Offset;
		if (!address)
			break;

		const int nameMaxSize = 40;
		char buffer[sizeof(SYMBOL_INFO) + nameMaxSize * sizeof(TCHAR)];
		PSYMBOL_INFO symbol = (PSYMBOL_INFO)buffer;
		symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		symbol->MaxNameLen = nameMaxSize;

		result << '[' << frameIndex++ << "] ";

		DWORD64 displacement = 0;
		if (SymFromAddr(process, address, &displacement, symbol))
		{
			std::string_view symbolName(symbol->Name, nameMaxSize);
			result << symbolName << " at " << (void*)symbol->Address;

			IMAGEHLP_LINE64 line;
			DWORD lineDisplacement = 0;
			if (SymGetLineFromAddr64(process, address, &lineDisplacement, &line))
			{

				std::string_view fullPath = line.FileName;
				std::string_view shortPath = fullPath;

				// qwe\asd\ { Carbon\Main.cpp } ";
				size_t lastBackslashPos = fullPath.rfind('\\');
				if (lastBackslashPos != std::string::npos)
				{
					size_t secondLastBackslashPos = fullPath.rfind('\\', lastBackslashPos - 1);
					shortPath = fullPath.substr(secondLastBackslashPos + 1);
				}

				result << " in " << shortPath << " line " << line.LineNumber << " + " << lineDisplacement;
			}

		}
		else
			result << "unknown at " << (void*)address;

		result << '\n';
	}

	SymCleanup(process);
	return result.str();
}

LONG panic(_EXCEPTION_POINTERS* ep)
{
	std::string result = "AAAAAAAAAAAAAAA PANIC AAAAAAAAAAAAAAAA\n";
	result.reserve(1000);
	result += "ExceptionCode: " + defaultFormatter.format(ep->ExceptionRecord->ExceptionCode) + '\n';
	result += "ExceptionFlags: " + defaultFormatter.format(ep->ExceptionRecord->ExceptionFlags) + '\n';
	result += "ExceptionAddress: " + Formatter::pointerToString(ep->ExceptionRecord->ExceptionAddress) + '\n';

	result += "Rip: " + Formatter::pointerToString((void*)ep->ContextRecord->Rax) + '\n';

	result += getStackTrace(ep->ContextRecord);
	Console::getInstance() << result << std::endl;
	logger.log(result);

	Sleep(-1);
	abort();
	return EXCEPTION_EXECUTE_HANDLER;
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		ghModule = hModule;
		SetUnhandledExceptionFilter(panic);

		basicTryWrapper("DllMain", [&]() {

			sharedMemoryContent = deserializeSharedMemory();
			logger.initialize(sharedMemoryContent.logPath);
			luaApiAddresses = sharedMemoryContent.offsets.luaApiAddresses;
			riblixAddresses = sharedMemoryContent.offsets.riblixAddresses;
			riblixOffsets = sharedMemoryContent.offsets.riblixOffsets;

			hookHandler.getHook(HookId::lua_newstate)
				.setTarget(luaApiAddresses.lua_newstate)
				.setHook(lua_newstate_hook)
				.setup();

			HMODULE user32 = GetModuleHandleW(L"user32.dll");
			FARPROC dispatchMessageW = GetProcAddress(user32, "DispatchMessageW");
			hookHandler.getHook(HookId::DispatchMessageW)
				.setTarget(dispatchMessageW)
				.setHook(DispatchMessageW_Hook)
				.setup();
		});

		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

