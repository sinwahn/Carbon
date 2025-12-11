module;
#include <lualib.h>
export module Lua.Address;

import <utility>;

import Address;
import Lua.Bridge;

int lua_Address(lua_State* L);

int address_get(lua_State* L);
int address_read(lua_State* L);

int address_deref(lua_State* L);
int address_derefAt(lua_State* L);

int address_isLocalValid(lua_State* L);

int address_add(lua_State* L);
int address_sub(lua_State* L);
int address_eq(lua_State* L);
int address_lt(lua_State* L);
int address_le(lua_State* L);
int dumpInfo_tostring(lua_State* L);

int address_isNullptr(lua_State* L);

void register_ByteArray(BridgeRegistrar& registrar)
{
	registrar.registerFieldPushed("__index", -2);
}

export
{
	class AddressBridge : public Bridge<AddressBridge, Address, register_ByteArray>
	{
	public:
		static constexpr const char* className = "Address";
		static inline const luaL_Reg library[] = {
			{"new", lua_Address},
			
			{"__add", address_add},
			{"__sub", address_sub},
			{"__eq", address_eq},
			{"__lt", address_lt},
			{"__le", address_le},
			{"__tostring", dumpInfo_tostring},

			// methods
			{"get", address_get},
			{"read", address_read},
			{"deref", address_deref},
			{"derefat", address_derefAt},
			{"islvalid", address_isLocalValid},
			{"isNullptr", address_isNullptr},

			{nullptr, nullptr}
		};
	};

	Address& luaL_checkAddress(lua_State* L, int idx) {
		return *AddressBridge::checkInstance(L, idx);
	}

	Address lua_toAddress(lua_State* L, int idx)
	{
		if (lua_isuserdata(L, idx))
			return luaL_checkAddress(L, idx);
		return (uintptr_t)luaL_checkinteger(L, idx);
	}
}

int lua_Address(lua_State* L) {

	auto parse_hex_string = [](const char* s) {
		uintptr_t value = 0;

		// skip optional "0x" or "0X"
		if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
			s++;

		while (*s) {
			unsigned char c = *s++;

			if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
				continue;

			uint8_t half;
			if (c >= '0' && c <= '9')
				half = c - '0';
			else if (c >= 'a' && c <= 'f')
				half = c - 'a' + 10;
			else if (c >= 'A' && c <= 'F')
				half = c - 'A' + 10;
			else
				break;

			value = (value << 4) | half;
		}
		return value;
	};

	uintptr_t value = 0;
	int argc = lua_gettop(L);
	if (argc > 0) {
		if (lua_isnumber(L, 1)) {
			value = lua_tointeger(L, 1);
		}
		else if (lua_isstring(L, 1)) {
			value = parse_hex_string(lua_tolstring(L, 1, nullptr));
		}
		else {
			luaL_typeerror(L, 1, "Address");
		}
	}
	AddressBridge::push(L, value);
	return 1;
}

int address_deref(lua_State* L) {
	auto& self = luaL_checkAddress(L, 1);
	auto [success, value] = self.tryDeref();
	
	lua_pushboolean(L, success);

	if (success)
		AddressBridge::push(L, Address(value));
	else
		lua_pushnil(L);

	return 2;
}

int address_derefAt(lua_State* L) {
	auto& self = luaL_checkAddress(L, 1);
	ptrdiff_t offset = luaL_optinteger(L, 2, 0);

	auto [success, value] = self.tryDerefAt(offset);

	lua_pushboolean(L, success);

	if (success)
		AddressBridge::push(L, Address(value));
	else
		lua_pushnil(L);

	return 2;
}

int address_add(lua_State* L) {
	auto& self = luaL_checkAddress(L, 1);
	uintptr_t other = lua_toAddress(L, 2);
	AddressBridge::push(L, self + other);
	return 1;
}

int address_sub(lua_State* L) {
	auto& self = luaL_checkAddress(L, 1);
	uintptr_t other = lua_toAddress(L, 2);
	AddressBridge::push(L, self - other);
	return 1;
}

int address_eq(lua_State* L) {
	auto& self = luaL_checkAddress(L, 1);
	uintptr_t other = lua_toAddress(L, 2);
	lua_pushboolean(L, self.get() == other);
	return 1;
}

int address_lt(lua_State* L) {
	auto& self = luaL_checkAddress(L, 1);
	uintptr_t other = lua_toAddress(L, 2);
	lua_pushboolean(L, self < other);
	return 1;
}

int address_le(lua_State* L) {
	auto& self = luaL_checkAddress(L, 1);
	uintptr_t other = lua_toAddress(L, 2);
	lua_pushboolean(L, self <= other);
	return 1;
}

int dumpInfo_tostring(lua_State* L) {
	auto& self = luaL_checkAddress(L, 1);
	lua_pushfstring(L, "Address: %llx", (unsigned long long)self.get());
	return 1;
}

int address_isLocalValid(lua_State* L) {
	auto& self = luaL_checkAddress(L, 1);
	return self.isLocalValid();
}

int address_isNullptr(lua_State* L) {
	auto& self = luaL_checkAddress(L, 1);
	lua_pushboolean(L, self.isNullptr());
	return 1;
}

int address_get(lua_State* L) {
	auto& self = luaL_checkAddress(L, 1);
	lua_pushfstring(L, "%llx", (unsigned long long)self.get());
	return 1;
}

template <typename T>
void push_read_value(lua_State* L, T val) {
	if constexpr (std::is_integral_v<T>) {
		lua_pushinteger(L, (lua_Integer)val);
	}
	else if constexpr (std::is_floating_point_v<T>) {
		lua_pushnumber(L, (lua_Number)val);
	}
}

int address_read(lua_State* L) {
	auto& self = luaL_checkAddress(L, 1);
	ptrdiff_t offset = luaL_optinteger(L, 2, 0);
	const char* type_str = luaL_optstring(L, 3, "uintptr");

	uintptr_t ptr = self + offset;

	if (!strcmp(type_str, "uint8")) {
		push_read_value(L, *(uint8_t*)ptr);
	}
	else if (!strcmp(type_str, "int8")) {
		push_read_value(L, *(int8_t*)ptr);
	}
	else if (!strcmp(type_str, "uint16")) {
		push_read_value(L, *(uint16_t*)ptr);
	}
	else if (!strcmp(type_str, "int16")) {
		push_read_value(L, *(int16_t*)ptr);
	}
	else if (!strcmp(type_str, "uint32")) {
		push_read_value(L, *(uint32_t*)ptr);
	}
	else if (!strcmp(type_str, "int32")) {
		push_read_value(L, *(int32_t*)ptr);
	}
	else if (!strcmp(type_str, "uint64") || !strcmp(type_str, "uintptr")) {
		push_read_value(L, *(uint64_t*)ptr);
	}
	else if (!strcmp(type_str, "int64")) {
		push_read_value(L, *(int64_t*)ptr);
	}
	else if (!strcmp(type_str, "float")) {
		push_read_value(L, *(float*)ptr);
	}
	else if (!strcmp(type_str, "double")) {
		push_read_value(L, *(double*)ptr);
	}
	else if (!strcmp(type_str, "string")) {
		lua_pushstring(L, (const char*)ptr);
	}
	else
	{
		luaL_error(L, "Unsupported type: %s", type_str);
	}

	return 1;
}