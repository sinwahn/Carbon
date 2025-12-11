module;
#include <lualib.h>
export module Lua.Registrar;

import <utility>;

import Address;
import DumpInfo;
import Lua.Bridge;
import Lua.Address;
import Memory;

int registrar_tostring(lua_State* L);

int registrar_add(lua_State* L);
int registrar_getSource(lua_State* L);

void register_Registrar(BridgeRegistrar& registrar)
{
	registrar.registerDestructor([](lua_State* L, void* userdata) {
		auto dumpInfo = (Registrar*)userdata;
		dumpInfo->~Registrar();
	});

	registrar.registerFieldPushed("__index", -2);
}

export
{
	class RegistrarBridge : public Bridge<RegistrarBridge, Registrar, register_Registrar>
	{
	public:
		static constexpr const char* className = "Registrar";
		static inline const luaL_Reg library[] = {
			{"__tostring", registrar_tostring},
			{"add", registrar_add},
			{"getSource", registrar_getSource},
			{nullptr, nullptr}
		};
	};

	Registrar& luaL_checkRegistrar(lua_State* L, int idx) {
		return *RegistrarBridge::checkInstance(L, idx);
	}
}

int registrar_tostring(lua_State* L) {
	auto& self = luaL_checkRegistrar(L, 1);
	lua_pushfstring(L, "Registrar{source=%s}", (uintptr_t)self.getSource().c_str());
	return 1;
}

int registrar_add(lua_State* L)
{
	auto& self = luaL_checkRegistrar(L, 1);
	auto name = luaL_checkstring(L, 2);
	auto address = luaL_checkAddress(L, 3);
	self.add(name, address);
	lua_pushvalue(L, 1);
	return 1;
}

int registrar_getSource(lua_State* L)
{
	auto& self = luaL_checkRegistrar(L, 1);
	lua_pushstring(L, self.getSource().c_str());
	return 1;
}