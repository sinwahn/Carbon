#include "../Common/CarbonWindows.h"

#include <psapi.h>
#include <inttypes.h>
#include <lua.h>
#include <luacode.h>
#include <lualib.h>

extern "C"
{
	#include "Zydis.h"
}

import <vector>;
import <fstream>;
import <string>;
import <functional>;
import <map>;
import <iostream>;
import <mutex>;

import StringUtils;
import Memory;
import ExceptionBase;
import Formatter;
import Lua.Address;
import InputFile;
import Api;
import Lua.FunctionData;
import Lua.ByteArray;
import Lua.Registrar;
import Lua.DumpInfo;
import Lua.Section;
import Lua.BaseLib;
import Section;
import FunctionCallAnalyzer;
import Disassembler;
import LuaLib;

struct MainInfo
{
	MODULEENTRY32 module;
	IMAGE_SECTION_HEADER text;
	IMAGE_SECTION_HEADER rdata;
	IMAGE_SECTION_HEADER data;
};

MainInfo getCodeSection(HANDLE hProcess, DWORD processId, const std::wstring& moduleName)
{
	MODULEENTRY32 module = getFirstModule(processId, moduleName);
	if (module.modBaseSize == 0)
		raise("failed to get first module");

	IMAGE_DOS_HEADER dosHeader;
	if (!ReadProcessMemory(hProcess, module.modBaseAddr, &dosHeader, sizeof(dosHeader), nullptr))
		raise("failed to read DOS header; error code:", formatLastError());

	IMAGE_NT_HEADERS ntHeaders;
	if (!ReadProcessMemory(
		hProcess,
		reinterpret_cast<LPVOID>(uintptr_t(module.modBaseAddr) + dosHeader.e_lfanew),
		&ntHeaders,
		sizeof(ntHeaders),
		nullptr
	))
		raise("failed to read to read NT headers; error code:", formatLastError());

	IMAGE_SECTION_HEADER sectionHeaders[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	if (!ReadProcessMemory(hProcess,
		reinterpret_cast<LPVOID>(uintptr_t(module.modBaseAddr)
			+ dosHeader.e_lfanew
			+ sizeof(DWORD)
			+ sizeof(IMAGE_FILE_HEADER)
			+ ntHeaders.FileHeader.SizeOfOptionalHeader
		),
		&sectionHeaders,
		sizeof(sectionHeaders),
		nullptr
	))
		raise("failed to read to read section headers; error code:", formatLastError());

	MainInfo result{ module };

	for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {
		auto& section = sectionHeaders[i];

		if (strcmp((char*)section.Name, ".text") == 0)
			result.text = section;
		else if (strcmp((char*)section.Name, ".rdata") == 0)
			result.rdata = section;
		else if (strcmp((char*)section.Name, ".data") == 0)
			result.data = section;
	}

	return result;
}

struct getInstructionResult
{
	ZydisDisassembledInstruction instruction;
	ExternalAddress runtimeAddress;
	Offset offset;
};

bool isInstanceBridge_push(const FunctionData& functionData, ExternalAddress pushnilAddress)
{
	DisassemblerState state(functionData);

	// instanceBridge_push has 3 funcs
	// if (a()) b(); else pushnil();

	int calls = 0;
	int jumps = 0;

	int pointsToPushNil = 0;

	do
	{
		if (!state.next())
			raise("getInstruction disassemble failed");

		auto& instruction = state.getInstruction();
		if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL)
		{
			calls++;
			if (state.getCurrentJumpAddress(0) == pushnilAddress)
				pointsToPushNil++;
		}

		if (instruction.info.mnemonic == ZYDIS_MNEMONIC_JMP)
		{
			jumps++;
			if (state.getCurrentJumpAddress(0) == pushnilAddress)
				pointsToPushNil++;
		}

		state.post();

	} while (!state.isPrologue());

	return (calls + jumps == 3) && (pointsToPushNil == 1);
}

getInstructionResult getInstruction(const FunctionData& functionData,
	std::function<bool(const ZydisDisassembledInstruction&)> callback)
{
	DisassemblerState state(functionData);

	do
	{
		if (!state.next())
			raise("getInstruction disassemble failed");

		auto& instruction = state.getInstruction();
		if (callback(instruction))
			return { instruction, state.getRuntimeAddress(), state.getOffset() };

		state.post();

	} while (!state.isPrologue());

	raise("getInstruction disassemble failed");
}

class Dumper
{
public:
	using LuaLibItems = std::map<std::string, ExternalAddress>;

	std::vector<Address> getCallingFunctions(const FunctionData& functionData) const {
		return ::getCallingFunctions(functionData);
	}

	std::vector<Address> getCallingFunctions(ExternalAddress inFunction) const {
		return ::getCallingFunctions(text.createFunctionData(inFunction));
	}

	std::vector<Address> getLeaTargets(const FunctionData& functionData) const {
		return ::getLeaTargets(functionData);
	}

	std::vector<Address> getLeaTargets(ExternalAddress inFunction) const {
		return ::getLeaTargets(text.createFunctionData(inFunction));
	}

	bool isInstanceBridge_push(const ExternalAddress& inFunction, ExternalAddress pushnil) const {
		return ::isInstanceBridge_push(text.createFunctionData(inFunction), pushnil);
	}

	FunctionData getNextFunction(ExternalAddress firstFunction) const {
		return ::getNextFunction(text.createFunctionData(firstFunction));
	}

	ExternalAddress getFirstJumpDestination(const FunctionData& functionData) const
	{
		auto [instruction, runtimeAddress, offset] = getInstruction(functionData,
			[&](const ZydisDisassembledInstruction& instruction) {
				return instruction.info.mnemonic == ZYDIS_MNEMONIC_JMP;
			});

		ExternalAddress result;
		ZydisCalcAbsoluteAddress(&instruction.info, &instruction.operands[0], runtimeAddress, &result.value);
		return result;
	}

	ExternalAddress getFirstJumpDestination(ExternalAddress inFunction) const {
		return getFirstJumpDestination(text.createFunctionData(inFunction));
	}

	ExternalAddress getCallingFunctionAt(ExternalAddress inFunction, size_t index) const {
		return ::getCallingFunctionAt(text.createFunctionData(inFunction), index);
	}

	const LuaLibItems& registerLibItems(const std::string& libName)
	{
		auto& lib = getLib(libName);
		lib.items = parseLuaLib(lib.address, libName);

		for (auto& [itemName, funcAddress] : lib.items)
			dumpInfo.add(libName, libName + '_' + itemName, funcAddress);

		return lib.items;
	}

	DisassemblerState createCodeDisasmState()
	{
		DisassemblerState state(text.newBuffer(), text.address, 0);
		return state;
	}

	void run()
	{
		setupMemoryData();

		auto _VERSION_possibleAddresses = getPossibleAddresses_VERSION();
		dumpLuauFromVersion(_VERSION_possibleAddresses);
		findAllLibs();
		identifyUnnamedLibs();
		runDumpFromLibs();
		dumpFlog1();
	}

	

	void writeToFile(const std::string& fileName) const
	{
		std::ofstream outFile(fileName);
		if (!outFile)
			raise("unable to open file", fileName, "for writing");

		for (auto& info : dumpInfo.getResult())
			printAddress(outFile, info);

		outFile.close();
	}

	void print() const
	{
		for (auto& info : dumpInfo.getResult())
			printAddress(std::cout, info);
	}

	void printAddress(std::ostream& stream, const std::pair<std::string, ExternalAddress>& info) const
	{
		// name=address|value
		stream << info.first <<
			"=" << (void*)(info.second - imageStart) <<
			"|" << *(void**)translateExternalPointer(info.second) << std::endl;
	}

private:

	const void parseLuaLibTo(ExternalAddress start, const std::string& debugName, LuaLibItems& items)
	{
		std::cout << defaultFormatter.format("parsing", debugName, "at", (void*)start, '\n');

		LocalAddress currentPtr = translateExternalPointer(start);

		// luaL_Reg uses nullptrs as array terminating element
		while (currentPtr.deref())
		{
			std::string name = (const char*)translateExternalPointer(currentPtr.getStoredPointer());
			currentPtr += 8;
			auto funcAddress = currentPtr.getStoredPointer();
			items[name] = funcAddress;
			currentPtr += 8;
		}
	}

	const LuaLibItems parseLuaLib(ExternalAddress start, const std::string& debugName)
	{
		LuaLibItems result;
		parseLuaLibTo(start, debugName, result);
		return result;
	}

	void setupMemoryData()
	{
		std::wstring processName(L"RobloxStudioBeta.exe");

		auto processId = getProcessId(processName);
		if (!processId)
			raise(processName.c_str(), "not found");

		HandleScope process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
		if (!process)
			raise("failed to open processId", processId, "; error code:", formatLastError());

		auto [module, textHeader, rdataHeader, dataHeader] = getCodeSection(process, processId, processName);

		imageStart = ExternalAddress((uintptr_t)module.modBaseAddr);
		dumpInfo.setImageStart(imageStart);

		text = { textHeader, imageStart, process, ".text" };
		rdata = { rdataHeader, imageStart, process, ".rdata" };
		data = { dataHeader, imageStart, process, ".data" };
	}

	std::vector<ExternalAddress> getPossibleAddresses_VERSION() const
	{
		const BYTE toFind[] = "_VERSION";
		std::vector<Offset> offsets = findSequences(rdata.newBuffer(), {toFind, sizeof(toFind) - 1});
		
		if (offsets.empty())
			raise("unable to find _VERSION");

		std::vector<ExternalAddress> result;
		result.reserve(offsets.size());

		for (auto offset : offsets)
		{
			result.push_back(ExternalAddress(rdata.address + offset));
		}

		return result;
	}

	class DumpInfo
	{
	public:
		friend class Registrar;

		DumpInfo()
		{

		}

		void add(const std::string& source, const std::string& name, ExternalAddress object)
		{
			Name key{ source, name };
			auto containingIter = registered.find(key);
			if (containingIter != registered.end())
			{
				if (containingIter->second != object)
				{
					std::string discoveredName;
					for (auto& [key, val] : registered)
						if (val == object)
							discoveredName = key.name;

					raise(
						"registered function", name,
						"differs from new address"
						"\n\tlast source:", containingIter->first.source,
						"\n\tat", (void*)containingIter->second, (void*)(containingIter->second - imageStart),
						"\n\tnew source:", source,
						"\n\tat", (void*)object, (void*)(object - imageStart),
						(discoveredName.empty() ? "" : "\n\tnew address was already discovered as " + discoveredName)
					);
				}
			}
			else
			{
				std::cout << defaultFormatter.format("added", name, "from", source, "at", (void*)object, (void*)(object - imageStart)) << std::endl;
				registered[key] = object;
			}
		}

		ExternalAddress get(const std::string& name) const
		{
			for (auto& [key, address] : registered)
				if (key.name == name)
					return address;

			raise("function", name, "was not registered");
		}

		std::map<std::string, ExternalAddress> getResult() const
		{
			std::map<std::string, ExternalAddress> result;

			for (auto& [key, address] : registered)
				result[key.name] = address;

			return result;
		}

		void setImageStart(ExternalAddress imageStart_)
		{
			imageStart = imageStart_;
		}

	private:

		class Registrar
		{
			friend class DumpInfo;

		public:

			Registrar& add(const std::string& name, ExternalAddress address)
			{
				self->add(source, name, address);
				return *this;
			}

		private:

			Registrar(const std::string& name, DumpInfo* self)
				: source(name)
				, self(self)
			{

			}

			std::string source;
			DumpInfo* self;
		};

	public:

		Registrar newRegistrar(const std::string& name)
		{
			return Registrar(name, this);
		}

	private:

		struct Name
		{
			std::string source;
			std::string name;

			bool operator<(const Name& other) const
			{
				return name < other.name;
			}
		};

		ExternalAddress imageStart;
		std::map<Name, ExternalAddress> registered;
	};

	DumpInfo dumpInfo;

	LuaLib* findLib(const std::string& name) const
	{
		for (auto& [_, lib] : libs)
			if (lib.libName == name)
				return const_cast<LuaLib*>(&lib);

		return nullptr;
	}

	const LuaLib& getLib(const std::string& name) const
	{
		if (auto lib = findLib(name))
			return *lib;

		raise("attempt to get unknown lib", name);
	}

	LuaLib& getLib(const std::string& name)
	{
		if (auto lib = findLib(name))
			return *lib;

		raise("attempt to get unknown lib", name);
	}

	Section text;
	Section rdata;
	Section data;

	ExternalAddress imageStart;
	std::map<ExternalAddress, LuaLib> libs;
};

lua_State* initLua()
{
	auto L = luaL_newstate();
	luaL_openlibs(L);
	lua_pushvalue(L, LUA_GLOBALSINDEX);
	luaL_register(L, nullptr, baseLibrary);
	AddressBridge::registerLib(L);
	ByteArrayBridge::registerLib(L);
	DumpInfoBridge::registerLib(L);
	FunctionDataBridge::registerLib(L);
	RegistrarBridge::registerLib(L);
	SectionBridge::registerLib(L);
	lua_pop(L, 1); // pop globals
	return L;
}

int main(int argc, char** argv)
{
	// Assume if no arguments are provided
	bool launchedFromExplorer = argc == 1;

	try
	{
		lua_State* L = initLua();

		InputFile dumperScript("Dumper.lua");
		dumperScript.load();
		dumperScript.getSource();

		size_t bytecodeSize;
		char* bytecode = luau_compile(dumperScript.getSource().c_str(), dumperScript.getSize(), NULL, &bytecodeSize);
		int fail = luau_load(L, dumperScript.getName().c_str(), bytecode, bytecodeSize, 0);
		free(bytecode);

		if (fail)
		{
			std::cout << "Luau error: " << lua_tostring(L, -1);
			return 1;
		}

		int status = lua_pcall(L, 0, LUA_MULTRET, 0);
		if (status != LUA_OK)
		{
			std::cout << "Luau error: " << lua_tostring(L, -1);
			lua_pop(L, 1);
		}

		//Dumper dumper;
		//dumper.run();
		//dumper.print();
		//std::string filename = (argc > 1) ? argv[1] : "dumpresult.txt";
		//dumper.writeToFile(filename);
	}
	catch (const std::exception& exception)
	{
		std::cout << exception.what() << std::endl;
		if (launchedFromExplorer)
			getchar();
	}

	return 0;
}