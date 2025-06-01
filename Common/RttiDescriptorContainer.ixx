module;
#include "CarbonWindows.h"
#include <dbghelp.h>
export module RttiDescriptorContainer;

#pragma comment(lib, "dbghelp.lib")

import <map>;
import <optional>;

export std::optional<uintptr_t> tryDereference(uintptr_t address, int offset = 0)
{
	uintptr_t pointerAddress = address + offset;

	uintptr_t pointerValue;
	if (!ReadProcessMemory(GetCurrentProcess(), (void*)pointerAddress, &pointerValue, sizeof(pointerValue), nullptr))
		return std::nullopt;

	return pointerValue;
}

export bool isValidAddress(uintptr_t address)
{
	char a;
	return ReadProcessMemory(GetCurrentProcess(), (void*)address, &a, 1, nullptr);
}

export uintptr_t dereference(uintptr_t address, int offset = 0)
{
	if (auto result = tryDereference(address, offset))
		return result.value();

	throw std::exception("address or offset is wrong");
	return address;
}

export class RttiDescriptorContainer
{
public:

	const std::string* tryGetName(uintptr_t object)
	{
		if (!object)
			return nullptr;

		auto vftable = tryDereference(object);
		if (!vftable)
			return nullptr;

		uintptr_t locatorVftableAddress = vftable.value() - sizeof(uintptr_t);

		auto locatorAddress = tryDereference(locatorVftableAddress);
		if (!locatorAddress)
			return nullptr;

		auto pos = locatorToName.find(locatorAddress.value());
		if (pos != locatorToName.end())
			return &pos->second;

		return tryRegisterNewLocator(locatorAddress.value());
	}

	const std::string* tryRegisterNewLocator(uintptr_t locatorAddress)
	{
		RTTICompleteObjectLocator locator;
		if (!ReadProcessMemory(GetCurrentProcess(), (void*)locatorAddress, &locator, sizeof(locator), nullptr))
			return nullptr;

		auto descriptorAddress = locator.getTypeDescriptorAddress();

		TypeDescriptor descriptor;
		if (!ReadProcessMemory(GetCurrentProcess(), (void*)descriptorAddress, &descriptor, sizeof(descriptor), nullptr))
			return nullptr;

		auto name = descriptor.getName();
		auto pos = locatorToName.emplace(locatorAddress, name);
		return &pos.first->second;
	}

private:

	struct TypeDescriptor;

	struct RTTICompleteObjectLocator
	{
		unsigned signature;
		unsigned offset;
		unsigned cdOffset;

		int typeDescriptorOffset;
		int classDescriptorOffset;
		int selfOffset;

		uintptr_t getTypeDescriptorAddress() {
			return (uintptr_t)GetModuleHandle(NULL) + typeDescriptorOffset;
		}
	};

	struct TypeDescriptor
	{
		static constexpr int nameMaxSize = 400; // varies, may be not even full

		void* vftable;
		void* spare;
		char name[nameMaxSize];

		std::string getName()
		{
			int i = 0;
			while (i < nameMaxSize && name[i] != '\0')
				i++;

			auto mangled = std::string(name, i);

			if (auto pos = mangled.find("AV"); pos != std::string::npos)
				mangled.erase(pos, 2);

			char result[nameMaxSize];
			UnDecorateSymbolName(mangled.c_str() + 1, result, sizeof(result), UNDNAME_NAME_ONLY);

			return result;
		}

	};

	std::map<uintptr_t, std::string> locatorToName;
};
