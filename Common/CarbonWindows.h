#pragma once

// without this thing it will complain about
// some freaking define shenanigans in windows headers
#define __SPECSTRINGS_STRICT_LEVEL 0

#define WIN32_LEAN_AND_MEAN
#define NOGDICAPMASKS
#define NOVIRTUALKEYCODES
#define NOWINMESSAGES
#define NOWINSTYLES
#define NOSYSMETRICS
#define NOMENUS
#define NOICONS
#define NOKEYSTATES
#define NOSYSCOMMANDS
#define NORASTEROPS
#define NOSHOWWINDOW
#define OEMRESOURCE
#define NOATOM
#define NOCLIPBOARD
#define NOCOLOR
#define NOCTLMGR
#define NODRAWTEXT
#define NOGDI
#define NOKERNEL
#define NOUSER
#define NONLS
#define NOMB
#define NOMEMMGR
#define NOMETAFILE
#define NOMINMAX
#define NOMSG
#define NOOPENFILE
#define NOSCROLL
#define NOSERVICE
#define NOSOUND
#define NOTEXTMETRIC
#define NOWH
#define NOWINOFFSETS
#define NOCOMM
#define NOKANJI
#define NOHELP
#define NOPROFILER
#define NODEFERWINDOWPOS
#define NOMCX

#define STRICT

#include <Windows.h>
#include <tlhelp32.h>

import <string>;
import <optional>;
import <functional>;

class HandleScope
{
public:
	HandleScope(HANDLE handle)
		: handle(handle)
		, containsHandle(true)
	{

	}

	HandleScope() {}

	~HandleScope()
	{
		close();
	}

	void operator=(const HandleScope&) = delete;
	void operator=(const HandleScope&&) = delete;

	operator HANDLE() const
	{
		return handle;
	}

	void assign(HANDLE handle_)
	{
		if (containsHandle || isClosed)
			throw std::exception("cannot assign to already assigned or closed scope");
		containsHandle = true;
		handle = handle_;
	}

	void close()
	{
		if (isClosed)
			return;
		isClosed = true;
		if (containsHandle)
			CloseHandle(handle);
	}

	void free()
	{
		handle = 0;
		isClosed = false;
		containsHandle = false;
	}

	bool inline hasHandle() const
	{
		return containsHandle;
	}
private:
	HANDLE handle = 0;
	bool isClosed = false;
	bool containsHandle = false;
};

// notice: format message does not apply arguments
inline std::wstring formatLastError()
{
	DWORD errorId = GetLastError();
	LPWSTR messageBuffer = nullptr;
	size_t size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorId, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, NULL);

	std::wstring message(messageBuffer, size);

	if (message.back() == L'\n')
	{
		message.pop_back();
		if (message.back() == L'\r')
			message.pop_back();
	}

	message += L"(GetLastError = " + std::to_wstring(errorId) + L")";
	LocalFree(messageBuffer);

	return message;
}


inline std::optional<PROCESSENTRY32> getProcess(
	std::function<bool(const PROCESSENTRY32&)> predicate)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HandleScope snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry))
	{
		do
		{
			if (predicate(entry))
				return entry;
		} while (Process32Next(snapshot, &entry));
	}

	return std::nullopt;
}

inline DWORD getProcessId(std::function<bool(const PROCESSENTRY32&)> predicate)
{
	auto result = getProcess(predicate);
	if (result.has_value())
		return result->th32ProcessID;
	return 0;
}

inline DWORD getProcessId(const std::wstring& processName)
{
	return getProcessId([&](const PROCESSENTRY32& entry) -> bool {
		return lstrcmpW(entry.szExeFile, processName.c_str()) == 0;
	});
}

inline DWORD getProcessIdWithParent(const std::wstring& processName, DWORD parentProcessId)
{
	return getProcessId([&](const PROCESSENTRY32& entry) -> bool {
		return lstrcmpW(entry.szExeFile, processName.c_str()) == 0
			&& entry.th32ParentProcessID == parentProcessId;
	});
}

inline MODULEENTRY32 getFirstModule(DWORD processId, const std::wstring& moduleName) {
	HandleScope snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
	if (snapshot == INVALID_HANDLE_VALUE)
		return {};

	MODULEENTRY32 moduleEntry;
	moduleEntry.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(snapshot, &moduleEntry))
		return {};

	do
	{
		if (moduleName == moduleEntry.szModule)
			return moduleEntry;
	} while (Module32Next(snapshot, &moduleEntry));

	return {};
}