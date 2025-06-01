export module Luau.Riblix;
import SharedAddresses;

import <memory>;
import <string>;
import RiblixStructures;
import Luau;

export
{
	inline Context* getCurrentContext()
	{
		return riblixAddresses.getCurrentContext();
	}

	inline void InstanceBridge_pushshared(lua_State* L, msvc_shared_ptr<Instance>& instance)
	{
		riblixAddresses.InstanceBridge_pushshared(L, instance);
	}

	inline void InstanceBridge_pushshared(lua_State* L, msvc_shared_ptr<Instance>&& instance)
	{
		riblixAddresses.InstanceBridge_pushshared(L, instance);
	}

	inline bool isTypeofType(lua_State* L, int idx, const char* name)
	{
		auto typeName = luaL_typename(L, idx);
		return strcmp(typeName, name) == 0;
	}

	inline void expectTypeofType(lua_State* L, int idx, const char* name)
	{
		if (!isTypeofType(L, idx, name))
			luaL_typeerrorL(L, idx, name);
	}

	inline Instance* toInstance(lua_State* L, int idx)
	{
		auto instance = (msvc_shared_ptr<Instance>*)(lua_touserdata(L, idx));
		return instance->get();
	}

	inline Instance* checkInstance(lua_State* L, int idx)
	{
		expectTypeofType(L, idx, "Instance");
		return toInstance(L, idx);
	}

	inline void push_instanceBridgeMap(lua_State* L)
	{
		lua_pushlightuserdatatagged(L, riblixAddresses.InstanceBridge_pushshared);
		lua_rawget(L, LUA_REGISTRYINDEX);
	}

}