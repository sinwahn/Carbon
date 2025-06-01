#include "../Common/CarbonWindows.h"

import <iostream>;
import <string>;
import <filesystem>;

import Pipes;
import SharedAddresses;
import ExceptionBase;
import DumpValidator;

bool terminateCrashHandler(DWORD parentProcessId)
{
	auto id = ::getProcessIdWithParent(L"RobloxCrashHandler.exe", parentProcessId);
	if (!id)
		return false;

	HandleScope process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);
	if (process == INVALID_HANDLE_VALUE)
		raise("failed to terminate crash handler");

	TerminateProcess(process, 0);
	return true;
}

bool inject(const std::filesystem::path& dllPath, HandleScope& process)
{
	auto absoluteDllPath = std::filesystem::absolute(dllPath);
	auto absoluteDllPathString = absoluteDllPath.string();

	auto remoteMemory = VirtualAllocEx(
		process,
		NULL,
		absoluteDllPathString.size(),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	if (!remoteMemory)
		raise("failed to allocate memory");

	std::cout << "allocation address: " << remoteMemory << std::endl;

	BOOL writeResult = WriteProcessMemory(
		process,
		remoteMemory,
		(LPVOID)absoluteDllPathString.c_str(),
		absoluteDllPathString.size(),
		NULL
	);

	if (!writeResult)
		raise("failed to write process memory");

	HandleScope remoteThread = CreateRemoteThread(
		process,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)LoadLibraryA,
		remoteMemory,
		0,
		NULL
	);

	if (!remoteThread)
		raise("failed to create remote thread");

	WaitForSingleObject(remoteThread, INFINITE);
	VirtualFreeEx(process, remoteMemory, 0, MEM_RELEASE);

	return true;
}

#define API __declspec(dllexport)

extern "C" API const char* Inject(DWORD processId, size_t dataSize, const char* paths);

static HandleScope sharedMemoryMapFile;

void createOffsetsSharedMemory(const std::wstring& settingsPath,
	const std::wstring& userDirectoryPath, const std::wstring& logPath)
{
	SharedMemoryContentDeserialized sharedData;
	sharedData.offsets.luaApiAddresses = luaApiAddresses;
	sharedData.offsets.riblixAddresses = riblixAddresses;
	sharedData.settingsPath = settingsPath;
	sharedData.userDirectoryPath = userDirectoryPath;
	sharedData.logPath = logPath;

	sharedMemoryMapFile.assign(CreateFileMappingW(
		INVALID_HANDLE_VALUE,
		0,
		PAGE_READWRITE,
		0,
		sizeof(SharedMemoryOffsets),
		sharedMemoryName
	));

	if (!sharedMemoryMapFile)
		raise("failed to create shared memory", formatLastError());

	auto sharedMemory = (char*)MapViewOfFile(
		sharedMemoryMapFile,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		sharedMemorySize
	);

	if (!sharedMemory)
		raise("failed to map view shared memory", formatLastError());

	auto serialized = sharedData.serialize();
	memcpy(sharedMemory, serialized.c_str(), serialized.size());
}

const char* Inject(DWORD processId, size_t dataSize, const char* paths)
{
	try
	{
		terminateCrashHandler(processId);

		ReadBuffer reader(std::string(paths, dataSize));
		
		// keep in sync with TryInject()
		auto readwstring = [&]() {
			auto size = reader.readU64();
			auto string = reader.readArray<wchar_t>(size);
			return std::wstring(string, size);
		};

		auto dllPath = readwstring();
		auto settingsPath = readwstring();
		auto dumpPath = readwstring();
		auto dumperPath = readwstring();
		auto userDirectoryPath = readwstring();
		auto logPath = readwstring();

		HandleScope process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
		if (process == INVALID_HANDLE_VALUE)
			raise("failed to open process");

		DumpValidator dumpValidator(process, getFirstModule(processId, L"RobloxStudioBeta.exe").modBaseAddr);
		dumpValidator.initAddressesFromFile(dumpPath, dumperPath);

		createOffsetsSharedMemory(settingsPath, userDirectoryPath, logPath);

		if (!inject(dllPath, process))
			raise("failed to inject");

		return nullptr;
	}
	catch (const std::exception& exception)
	{
		static std::string errorMessage;
		errorMessage.assign(exception.what());
		return errorMessage.c_str();
	}
}