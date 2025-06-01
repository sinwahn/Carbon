module;
#include "../Common/CarbonWindows.h"
#include <psapi.h>
export module FunctionMarker;

import Luau;

export class FunctionMarker
{
public:
	FunctionMarker(HMODULE ourModule);

	bool isOurClosure(Closure* func) const;
	void setOurProto(Proto* proto) const;

	uintptr_t textStart = 0;
	uintptr_t textEnd = 0;
private:

	void setTextSectionRegion();

	int ourLuaFunctionLineMarker;
	HMODULE ourModule;
};

// TODO: check nice way
export inline FunctionMarker* functionMarker = nullptr;

FunctionMarker::FunctionMarker(HMODULE ourModule)
{
	this->ourModule = ourModule;
	ourLuaFunctionLineMarker = (413254432);
	setTextSectionRegion();
}

bool FunctionMarker::isOurClosure(Closure* func) const
{
	if (func->isC)
	{
		return (uintptr_t)func->c.f >= textStart
			&& (uintptr_t)func->c.f < textEnd;
	}
	else
	{
		return func->l.p->linedefined == ourLuaFunctionLineMarker;
	}
}

void FunctionMarker::setOurProto(Proto* proto) const
{
	proto->linedefined = ourLuaFunctionLineMarker;
}


void FunctionMarker::setTextSectionRegion()
{
	auto modBaseAddr = (uintptr_t)ourModule;

	auto dosHeader = (IMAGE_DOS_HEADER*)modBaseAddr;
	auto ntHeaders = (IMAGE_NT_HEADERS*)(modBaseAddr + dosHeader->e_lfanew);
	auto sectionHeaders = (IMAGE_SECTION_HEADER*)(modBaseAddr + dosHeader->e_lfanew
		+ sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeaders->FileHeader.SizeOfOptionalHeader);

	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		auto& section = sectionHeaders[i];
		if (strcmp((char*)section.Name, ".text") == 0)
		{
			textStart = modBaseAddr + section.VirtualAddress;
			textEnd = textStart + section.Misc.VirtualSize;
			return;
		}
	}
}