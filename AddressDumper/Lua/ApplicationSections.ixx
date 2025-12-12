module;
#include <lualib.h>
export module Lua.ApplicationSections;

import <utility>;

import Address;
import Lua.Bridge;
import Lua.Registrar;
import Lua.LuaLibRef;

import Memory;
export import ApplicationSections;

int lua_ApplicationSections(lua_State* L);

int ApplicationSections_tostring(lua_State* L);
int ApplicationSections_initialize(lua_State* L);
int ApplicationSections_getLibs(lua_State* L);
int ApplicationSections_translatePointerNoThrow(lua_State* L);
int ApplicationSections_translatePointer(lua_State* L);

void register_ApplicationSections(BridgeRegistrar& registrar)
{
	registrar.registerDestructor([](lua_State* L, void* userdata) {
		auto applicationSections = (ApplicationSections*)userdata;
		applicationSections->~ApplicationSections();
	});

	registrar.registerFieldPushed("__index", -2);
}

export
{
	class ApplicationSectionsBridge : public Bridge<ApplicationSectionsBridge, ApplicationSections, register_ApplicationSections>
	{
	public:
		static constexpr const char* className = "ApplicationSections";
		static inline const luaL_Reg library[] = {
			{"new", lua_ApplicationSections},
			{"__tostring", ApplicationSections_tostring},
			{"initialize", ApplicationSections_initialize},
			{"getLibs", ApplicationSections_getLibs},
			{"translatePointerNoThrow", ApplicationSections_translatePointerNoThrow},
			{"translatePointer", ApplicationSections_translatePointer},
			{nullptr, nullptr}
		};
	};

	ApplicationSections& luaL_checkApplicationSections(lua_State* L, int idx) {
		return *ApplicationSectionsBridge::checkInstance(L, idx);
	}
}

int lua_ApplicationSections(lua_State* L) {
	std::wstring processName;
	ApplicationSectionsBridge::push(L, processName);
	return 1;
}

int ApplicationSections_tostring(lua_State* L) {
	auto& self = luaL_checkApplicationSections(L, 1);
	lua_pushstring(L, self.getProcessName().c_str());
	return 1;
}

int ApplicationSections_getLibs(lua_State* L) {
	auto& self = luaL_checkApplicationSections(L, 1);
	return 1;
}

int ApplicationSections_initialize(lua_State* L) {
	auto& self = luaL_checkApplicationSections(L, 1);
	self.initialize();
	return 0;
}

int ApplicationSections_translatePointerNoThrow(lua_State* L) {
	auto& self = luaL_checkApplicationSections(L, 1);
	auto& address = luaL_checkAddress(L, 2);
	AddressBridge::push(self.translateExternalPointerNoThrow(address));
	return 0;
}

int ApplicationSections_translatePointer(lua_State* L) {
	auto& self = luaL_checkApplicationSections(L, 1);
	auto& address = luaL_checkAddress(L, 2);
	AddressBridge::push(self.translateExternalPointer(address));
	return 0;
}