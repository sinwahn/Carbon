module;
#include <lualib.h>
export module Lua.DumpInfo;

import <utility>;

import Address;
import Lua.Bridge;
import Lua.Registrar;

import Memory;
import DumpInfo;

int lua_DumpInfo(lua_State* L);

int dumpInfo_tostring(lua_State* L);

int dumpInfo_newRegistrar(lua_State* L);
int dumpInfo_export(lua_State* L);

void register_DumpInfo(BridgeRegistrar& registrar)
{
	registrar.registerDestructor([](lua_State* L, void* userdata) {
		auto dumpInfo = (DumpInfo*)userdata;
		dumpInfo->~DumpInfo();
	});

	registrar.registerFieldPushed("__index", -2);
}

export
{
	class DumpInfoBridge : public Bridge<DumpInfoBridge, DumpInfo, register_DumpInfo>
	{
	public:
		static constexpr const char* className = "DumpInfo";
		static inline const luaL_Reg library[] = {
			{"new", lua_DumpInfo},
			{"__tostring", dumpInfo_tostring},
			{"newRegistrar", dumpInfo_newRegistrar},
			{"export", dumpInfo_export},
			{nullptr, nullptr}
		};
	};

	DumpInfo& luaL_checkDumpInfo(lua_State* L, int idx) {
		return *DumpInfoBridge::checkInstance(L, idx);
	}
}

int lua_DumpInfo(lua_State* L) {
	DumpInfoBridge::push(L);
	return 1;
}

int dumpInfo_tostring(lua_State* L) {
	auto& self = luaL_checkDumpInfo(L, 1);
	lua_pushstring(L, DumpInfoBridge::className);
	return 1;
}

int dumpInfo_newRegistrar(lua_State* L) {
	auto& self = luaL_checkDumpInfo(L, 1);
	auto source = luaL_checkstring(L, 2);
	RegistrarBridge::push(L, self.newRegistrar(source));
	return 1;
}

int dumpInfo_export(lua_State* L)
{
	auto& self = luaL_checkDumpInfo(L, 1);
	self.exportToFile("dumpresult.txt");
	return 0;
}