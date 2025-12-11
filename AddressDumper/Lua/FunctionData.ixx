module;
#include <lualib.h>
export module Lua.FunctionData;

import <utility>;

import Address;
import Lua.Bridge;
import Memory;

int functionData_tostring(lua_State* L);

void register_FunctionData(BridgeRegistrar& registrar)
{
	registrar.registerFieldPushed("__index", -2);
}

export
{
	class FunctionDataBridge : public Bridge<FunctionDataBridge, FunctionData, register_FunctionData>
	{
	public:
		static constexpr const char* className = "FunctionData";
		static inline const luaL_Reg library[] = {
			{"__tostring", functionData_tostring},
			{nullptr, nullptr}
		};
	};

	FunctionData& luaL_checkFunctionData(lua_State* L, int idx) {
		return *FunctionDataBridge::checkInstance(L, idx);
	}
}

int functionData_tostring(lua_State* L) {
	auto& self = luaL_checkFunctionData(L, 1);
	lua_pushfstring(L, "FunctionData{prologueOffset=%llx,prologueRuntimeAddress=%llx}",
		self.prologueOffset.get(),
		self.prologueRuntimeAddress.get()
	);
	return 1;
}