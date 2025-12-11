module;
#include "../Common/CarbonWindows.h"
export module ApplicationSections;

import <string>;

import Memory;
import Section;
import ExceptionBase;
import Utils.UnorderedMap;

export class ApplicationSections
{
public:
	ApplicationSections(const std::wstring& processName)
		: processName(processName)
	{

	}

	void initialize()
	{
		auto processId = getProcessId(processName);
		if (!processId)
			raise(processName.c_str(), "not found");

		HandleScope process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
		if (!process)
			raise("failed to open processId", processId, "; error code:", formatLastError());

		fetchAllSection(process, processId, processName);
		copyAllSections(process);
	}

	void fetchAllSection(HANDLE hProcess, DWORD processId, const std::wstring& moduleName)
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

		for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {
			auto& sectionHeader = sectionHeaders[i];

			auto name = (char*)sectionHeader.Name;
			sections.create(name, Section(sectionHeader, imageStart, name));
		}
	}

	Section& copySection(const std::string& sectionName, HANDLE processHandle)
	{
		auto& section = sections.get(sectionName);
		section.copy(processHandle);
		return section;
	}

	void copyAllSections(HANDLE processHandle)
	{
		for (auto& [_, section] : sections)
			section.copy(processHandle);
	}

	Address getImageStart() const { return imageStart; }

	const std::wstring& getProcessNameW() const { return processName; }
	std::string getProcessName() const { return {}; }


	LocalAddress translateExternalPointerNoThrow(ExternalAddress original) const
	{
		for (auto& [_, section] : sections)
		{
			if (section.address.value <= original && original < section.address.value + section.header.Misc.VirtualSize)
			{
				ptrdiff_t offset = original - section.address;
				return LocalAddress((uintptr_t)section.data.get() + offset);
			}
		}

		return {};
	};

	LocalAddress translateExternalPointer(ExternalAddress original) const
	{
		if (auto result = translateExternalPointerNoThrow(original))
			return result;

		raise("pointer does not point to a valid section");
	};

private:
	const std::wstring& processName;
	Address imageStart;

	UnorderedMap<std::string, Section> sections;
};