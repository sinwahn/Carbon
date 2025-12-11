module;
#include "../Common/CarbonWindows.h"
export module Memory;

import <vector>;
import <string>;
import <vector>;
import <functional>;
import <map>;
import <mutex>;
import <iostream>;

import StringUtils;
import ExceptionBase;
export import Address;

typedef unsigned char BYTE;

export 
{
	struct Offset : Address
	{
		constexpr Offset() = default;
		constexpr Offset(const Address& other) { value = other.value; }
		constexpr Offset(uintptr_t v) : Address(v) {}
	};

	struct _ContextualAddress : Address
	{
		constexpr _ContextualAddress() = default;
		constexpr _ContextualAddress(uintptr_t v) : Address(v) {}
	};

	struct ExternalAddress : _ContextualAddress
	{
		constexpr ExternalAddress() = default;
		constexpr ExternalAddress(const Address& other) { value = other.value; }
		explicit constexpr ExternalAddress(uintptr_t v) : _ContextualAddress(v) {}

		constexpr Offset operator+(ExternalAddress v) { return Offset(value + v.value); }
		constexpr Offset operator-(ExternalAddress v) { return Offset(value - v.value); }

		constexpr ExternalAddress operator+(auto v) { return ExternalAddress(value + v); }
		constexpr ExternalAddress operator-(auto v) { return ExternalAddress(value - v); }

		constexpr ExternalAddress operator+(Offset v) { return ExternalAddress(value + v.value); }
		constexpr ExternalAddress operator-(Offset v) { return ExternalAddress(value - v.value); }
	};

	struct LocalAddress : _ContextualAddress
	{
		constexpr LocalAddress() = default;
		constexpr LocalAddress(const Address& other) { value = other.value; }
		explicit constexpr LocalAddress(uintptr_t v) : _ContextualAddress(v) {}

		constexpr Offset operator+(LocalAddress v) { return Offset(value + v.value); }
		constexpr Offset operator-(LocalAddress v) { return Offset(value - v.value); }

		constexpr LocalAddress operator+(auto v) { return LocalAddress(value + v); }
		constexpr LocalAddress operator-(auto v) { return LocalAddress(value - v); }

		constexpr LocalAddress operator+(Offset v) { return LocalAddress(value + v.value); }
		constexpr LocalAddress operator-(Offset v) { return LocalAddress(value - v.value); }

		ExternalAddress getStoredPointer() const { return ExternalAddress(deref()); }
	};

	struct ByteArray
	{
		const BYTE* array = nullptr;
		size_t size = 0;
	};

	struct FunctionData
	{
		ByteArray buffer;
		Address prologueRuntimeAddress;
		Offset prologueOffset;
	};
}
