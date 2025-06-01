module;
#include "../Common/CarbonWindows.h"
export module DumpValidator;

import <iostream>;
import <string>;
import <filesystem>;
import <fstream>;
import <map>;

import SharedAddresses;
import ExceptionBase;
import Formatter;

export class DumpValidator
{
public:
	DumpValidator(HandleScope& process, void* moduleBaseAddress)
		: process(process)
		, moduleBaseAddress((uintptr_t)moduleBaseAddress)
	{

	}

	uintptr_t getAddressFromOffset(uintptr_t offset)
	{
		return moduleBaseAddress + offset;
	}

	struct OffsetInfo
	{
		uintptr_t address;
		uintptr_t value;
	};

	using dumpInfo = std::map<std::string, OffsetInfo>;

	dumpInfo parseAddressDumpFile(const std::wstring& filePath)
	{
		dumpInfo result;

		std::ifstream file(filePath);

		std::string line;
		while (std::getline(file, line)) {
			size_t posAddressDelim = line.find('=');
			size_t posValueDelim = line.find('|');
			if (posAddressDelim != std::string::npos && posValueDelim != std::string::npos) {
				std::string name = line.substr(0, posAddressDelim);
				std::string parsedAddress = line.substr(posAddressDelim + 1, posValueDelim);
				std::string parsedValue = line.substr(posValueDelim + 1);

				try
				{
					uintptr_t address = std::stoull(parsedAddress, nullptr, 16);
					uintptr_t storedValue = strtoull(parsedValue.c_str(), nullptr, 16);

					result[name] = { address, storedValue };
				}
				catch (const std::exception& exception)
				{
					std::cout << defaultFormatter.format("failed to parse", line, ':', exception.what()) << std::endl;
				}
			}
		}

		file.close();

		return result;
	}

	void initAddressesFromFile(const std::wstring& dumpPath, const std::wstring& dumperPath)
	{
		auto map = parseAddressDumpFile(dumpPath);

		if (checkDifferentValue(map))
		{
			redidDump = true;
			redoDump(map, dumpPath, dumperPath);
		}

		bool hasMissingAddress = false;

		auto get = [&](const auto& name) -> uintptr_t {
			auto pos = map.find(name);
			if (pos == map.end())
			{
				std::cout << "missing " << name << std::endl;
				hasMissingAddress = true;
				return invalidAddress;
			}
			else
				return pos->second.address;
			};

	addressInit:

#define setLuaAddr(item) luaApiAddresses.item = (decltype(luaApiAddresses.item))((void*)getAddressFromOffset(get(#item)))
#define setRiblixAddr(item) riblixAddresses.item = (decltype(riblixAddresses.item))((void*)getAddressFromOffset(get(#item)))

		setRiblixAddr(InstanceBridge_pushshared);

		setRiblixAddr(getCurrentContext);
		setRiblixAddr(luau_load);
		setRiblixAddr(FLOG1);

		setLuaAddr(luaO_nilobject);
		setLuaAddr(lua_rawget);
		setLuaAddr(lua_rawset);
		setLuaAddr(lua_next);

		setLuaAddr(luaD_call);
		setLuaAddr(luaD_pcall);

		setLuaAddr(lua_getinfo);

		setLuaAddr(luaL_typeerrorL);
		setLuaAddr(luaL_errorL);
		setLuaAddr(luaL_typename);

		setLuaAddr(lua_pushlstring);
		setLuaAddr(lua_pushvalue);

		setLuaAddr(lua_tolstring);

		setLuaAddr(lua_settable);
		setLuaAddr(lua_getfield);
		setLuaAddr(lua_setfield);

		setLuaAddr(lua_createtable);
		setLuaAddr(luaH_clone);
		setLuaAddr(lua_setmetatable);
		setLuaAddr(lua_getmetatable);

		setLuaAddr(lua_pushcclosurek);
		setLuaAddr(luaF_newLclosure);
		setLuaAddr(luaF_newproto);

		setLuaAddr(luaD_reallocCI);
		setLuaAddr(luaD_growCI);
		setLuaAddr(lua_concat);
		setLuaAddr(lua_newuserdatatagged);
		setLuaAddr(luaH_get);
		setLuaAddr(lua_newthread);
		setLuaAddr(task_defer);
		setLuaAddr(lua_newstate);

#undef setLuaAddr
#undef setRiblixAddr

		if (hasMissingAddress)
		{
			if (redidDump)
				std::cout << "did dump and missing values -> unapdated dumper?" << std::endl;
			else
			{
				std::cout << "has missing address" << std::endl;
				redoDump(map, dumpPath, dumperPath);
				goto addressInit;
			}
		}

		validateAddresses();
	}

private:

	void redoDump(dumpInfo& result, const std::wstring& dumpPath, const std::wstring& dumperPath)
	{
		redidDump = true;
		std::cout << "redoing dump" << std::endl;

		STARTUPINFO startupInfo;
		PROCESS_INFORMATION processInfo;

		ZeroMemory(&startupInfo, sizeof(startupInfo));
		startupInfo.cb = sizeof(startupInfo);
		ZeroMemory(&processInfo, sizeof(processInfo));

		std::filesystem::path dumpFilePath(dumpPath);
		std::wstring directory = dumpFilePath.parent_path().wstring();
		std::string fileName = dumpFilePath.filename().string();
		std::wstring commandLine = L"\"" + dumperPath + L"\" " + std::wstring(fileName.begin(), fileName.end());

		if (CreateProcessW(
			nullptr,               // path to the executable
			const_cast<wchar_t*>(commandLine.c_str()),  // command line arguments (NULL if none)
			nullptr,               // process security attributes (NULL for default)
			nullptr,               // thread security attributes (NULL for default)
			false,                 // handle inheritance option
			0,                     // creation flags
			nullptr,               // environment block (NULL to use the parent's environment)
			directory.c_str(),     // current directory
			&startupInfo,          // pointer to STARTUPINFO structure
			&processInfo           // pointer to PROCESS_INFORMATION structure
		))
		{
			WaitForSingleObject(processInfo.hProcess, INFINITE);

			CloseHandle(processInfo.hProcess);
			CloseHandle(processInfo.hThread);

			result = parseAddressDumpFile(dumpPath);

			if (checkDifferentValue(result))
				std::cout << "still has different value for some reason" << std::endl;
		}
		else
		{
			raise("failed to start process:", formatLastError());
		}
	}

	// returns true if theres difference
	bool checkDifferentValue(const dumpInfo& info)
	{
		bool hasDifference = false;
		for (auto& [name, offset] : info)
		{
			uintptr_t value;
			if (!ReadProcessMemory(process,
				(void*)getAddressFromOffset(offset.address),
				&value,
				sizeof(value),
				nullptr
			))
				raise("failed to read to value by address of", name, "at", offset.address, formatLastError());

			if (value != offset.value)
			{
				std::cout << defaultFormatter.format(name, "differs, stored:", offset.value, "actual:", value) << std::endl;
				hasDifference = true;
				break;
			}
		}

		return hasDifference;
	}

	void validateAddresses()
	{
		auto validateCategory = [&](auto& addresses) {
			size_t numAddresses = sizeof(addresses) / sizeof(void*);
			void** addressArray = reinterpret_cast<void**>(&addresses);

			for (int i = 0; i < numAddresses; i++)
				if (addressArray[i] == nullptr)
					std::cout << defaultFormatter.format("unhandled address in Offsets at index", i) << std::endl;
			};

		validateCategory(luaApiAddresses);
		validateCategory(riblixAddresses);
	}

	HandleScope& process;
	uintptr_t moduleBaseAddress;
	bool redidDump = false;
	static const uintptr_t invalidAddress = 1;
};