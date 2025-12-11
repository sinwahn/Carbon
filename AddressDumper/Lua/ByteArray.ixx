module;
#include <lualib.h>
export module Lua.ByteArray;

import <utility>;

import Address;
import Lua.Bridge;
import Memory;

int byteArray_tostring(lua_State* L);

void register_ByteArray(BridgeRegistrar& registrar)
{
	registrar.registerFieldPushed("__index", -2);
}

export
{
	class ByteArrayBridge : public Bridge<ByteArrayBridge, ByteArray, register_ByteArray>
	{
	public:
		static constexpr const char* className = "ByteArray";
		static inline const luaL_Reg library[] = {
			{"__tostring", byteArray_tostring},
			{nullptr, nullptr}
		};
	};

	ByteArray& luaL_checkByteArray(lua_State* L, int idx) {
		return *ByteArrayBridge::checkInstance(L, idx);
	}
}

int byteArray_tostring(lua_State* L) {
	auto& self = luaL_checkByteArray(L, 1);
	lua_pushfstring(L, "ByteArray{base=%llx,size=%llx}", (uintptr_t)self.array, self.size);
	return 1;
}