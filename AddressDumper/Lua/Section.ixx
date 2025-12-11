module;
#include <lualib.h>
export module Lua.Section;

import <utility>;

import Address;
import Memory;
import Section;
import Lua.Bridge;
export import Lua.Address;
export import Lua.ByteArray;
export import Lua.FunctionData;

struct SectionReference
{
	Section* value;
	auto operator->() { return value; }
};

int section_tostring(lua_State* L);
int section_getName(lua_State* L);
int section_createByteArray(lua_State* L);
int section_createFunctionDataFromAddress(lua_State* L);

int section_getBaseAddress(lua_State* L);
int section_addressToOffset(lua_State* L);
int section_offsetToAddress(lua_State* L);

void register_Section(BridgeRegistrar& registrar)
{
	registrar.registerFieldPushed("__index", -2);
}

export
{
	class SectionBridge : public Bridge<SectionBridge, SectionReference, register_Section>
	{
	public:
		static constexpr const char* className = "Section";
		static inline const luaL_Reg library[] = {
			{ "__tostring", section_tostring },

			{ "getName", section_getName },
			{ "createByteArray", section_createByteArray },
			{ "createFunctionDataFromAddress", section_createFunctionDataFromAddress },

			{ "getBaseAddress", section_getBaseAddress },
			{ "addressToOffset", section_addressToOffset },
			{ "offsetToAddress", section_offsetToAddress },

			{ nullptr, nullptr }
		};
	};

	SectionReference& luaL_checkSection(lua_State* L, int idx) {
		return *SectionBridge::checkInstance(L, idx);
	}
}

int section_tostring(lua_State* L) {
	auto& self = luaL_checkSection(L, 1);
	lua_pushfstring(L, "Section{name=%s}",
		(const char*)self->header.Name
	);
	return 1;
}

int section_getName(lua_State* L)
{
	auto& self = luaL_checkSection(L, 1);
	lua_pushstring(L, (const char*)self->header.Name);
	return 1;
}

int section_getAddress(lua_State* L)
{
	auto& self = luaL_checkSection(L, 1);
	ByteArrayBridge::push(L, ByteArray(self->data.get(), self->size));
	return 1;
}

int section_createByteArray(lua_State* L)
{
	auto& self = luaL_checkSection(L, 1);
	ByteArrayBridge::push(L, ByteArray(self->data.get(), self->size));
	return 1;
}

int section_createFunctionDataFromAddress(lua_State* L)
{
	auto& self = luaL_checkSection(L, 1);
	auto function = luaL_checkAddress(L, 2);
	FunctionDataBridge::push(L, self->createFunctionData(function));
	return 1;
}

int section_getBaseAddress(lua_State* L)
{
	auto& self = luaL_checkSection(L, 1);
	AddressBridge::push(L, self->address);
	return 1;
}

int section_addressToOffset(lua_State* L)
{
	auto& self = luaL_checkSection(L, 1);
	auto& address = luaL_checkAddress(L, 2);
	ByteArrayBridge::push(L, self->addressToOffset(address));
	return 1;
}

int section_offsetToAddress(lua_State* L)
{
	auto& self = luaL_checkSection(L, 1);
	auto& offset = luaL_checkAddress(L, 2);
	ByteArrayBridge::push(L, self->offsetToAddress(offset));
	return 1;
}