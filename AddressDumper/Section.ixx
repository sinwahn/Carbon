module;
#include "../Common/CarbonWindows.h"
export module Section;

import <memory>;
import Memory;
import ExceptionBase;

export class Section
{
public:
	Section() = default;

	Section(
		const IMAGE_SECTION_HEADER& header,
		Address imageStart,
		const char* name
	)
		: header(header)
		, name(name)
		, size(header.Misc.VirtualSize)
		, address(imageStart + header.VirtualAddress)
	{
	}

	void copy(HANDLE processHandle)
	{
		if (isCopied)
			raise("section", name, "already fetched");
		
		data = std::make_unique<BYTE[]>(size);

		if (!ReadProcessMemory(processHandle,
			(LPVOID)address,
			data.get(),
			size,
			nullptr
		))
			raise("failed to read", name, "segment; error code:", formatLastError());
		isCopied = true;
	}

	ByteArray newBuffer() const {
		return { data.get(), size };
	}

	Address offsetToAddress(Offset what) const {
		return address + what;
	}

	Address addressToOffset(Address what) const {
		return what - address;
	}

	FunctionData createFunctionData(Address from) const
	{
		FunctionData result;
		result.buffer = newBuffer();
		result.prologueRuntimeAddress = from;
		result.prologueOffset = from - address;
		return result;
	}

	std::unique_ptr<BYTE[]> data;
	const IMAGE_SECTION_HEADER header;
	const size_t size;
	const Address address;
	const std::string name;
private:
	bool isCopied = false;
};