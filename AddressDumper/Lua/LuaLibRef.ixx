module;
#include <lualib.h>
export module Lua.LuaLibRef;

import <utility>;

import Address;
import Lua.Address;
import Lua.Bridge;
import Lua.Registrar;
import Lua.ApplicationSections;

import Memory;
import LuaLib;

struct LuaLibReference
{
	LuaLib* value;
	auto operator->() { return value; }
};

int LuaLib_tostring(lua_State* L);

int LuaLib_isNamed(lua_State* L);
int LuaLib_setName(lua_State* L);
int LuaLib_getName(lua_State* L);
int LuaLib_parseItems(lua_State* L);

int LuaLib_hasItem(lua_State* L);
int LuaLib_getItem(lua_State* L);
int LuaLib_getLastLoadedFromFunction(lua_State* L);

void register_LuaLib(BridgeRegistrar& registrar)
{
	registrar.registerFieldPushed("__index", -2);
}

export
{
	class LuaLibBridge : public Bridge<LuaLibBridge, LuaLibReference, register_LuaLib>
	{
	public:
		static constexpr const char* className = "LuaLib";
		static inline const luaL_Reg library[] = {
			{"__tostring", LuaLib_tostring},
			{"isNamed", LuaLib_isNamed},
			{"setName", LuaLib_setName},
			{"getName", LuaLib_getName},
			{"parseItems", LuaLib_parseItems},

			{"hasItem", LuaLib_hasItem},
			{"getItem", LuaLib_getItem},
			{"getLastLoadedFromFunction", LuaLib_getLastLoadedFromFunction},

			{nullptr, nullptr}
		};
	};

	LuaLibReference& luaL_checkLuaLib(lua_State* L, int idx) {
		return *LuaLibBridge::checkInstance(L, idx);
	}
}

int LuaLib_tostring(lua_State* L) {
	auto& self = luaL_checkLuaLib(L, 1);
	lua_pushstring(L, LuaLibBridge::className);
	return 1;
}

int LuaLib_isNamed(lua_State* L)
{
	auto& self = luaL_checkLuaLib(L, 1);
	lua_pushboolean(L, self->)
	return 1;
}

int LuaLib_setName(lua_State* L)
{
	auto& self = luaL_checkLuaLib(L, 1);
	auto name = luaL_checkstring(L, 1);
	self->setName(name);
	return 0;
}

int LuaLib_getName(lua_State* L)
{
	auto& self = luaL_checkLuaLib(L, 1);
	lua_pushstring(L, self->getName());
	return 1;
}

int LuaLib_parseItems(lua_State* L)
{
	auto& self = luaL_checkLuaLib(L, 1);
	auto& sections = luaL_checkApplicationSections(L, 2);
	auto& result = self->parseItems(sections);

	luaL_pusharraylike(L, result, [](auto L, const Offset& offset) {
		AddressBridge::push(L, offset);
	});

	return 0;
}

int LuaLib_hasItem(lua_State* L)
{
	auto& self = luaL_checkLuaLib(L, 1);
	return 1;
}

int LuaLib_getItem(lua_State* L)
{
	auto& self = luaL_checkLuaLib(L, 1);
	return 1;
}


int LuaLib_getLastLoadedFromFunction(lua_State* L)
{
	auto& self = luaL_checkLuaLib(L, 1);
	AddressBridge::push(L, self->lastLoadedFromFunction);
	return 1;
}