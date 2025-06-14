module LuaEnv;

import <filesystem>;

import Luau;
import CarbonLuaApiLibs.fslib;
import CarbonLuaApiLibs.tablelib;
import CarbonLuaApiLibs.dbglib;
import CarbonLuaApiLibs.baselib;
import CarbonLuaApiLibs.closurelib;
import CarbonLuaApiLibs.gclib;

import Luau.Riblix;
import Luau.Compile;
import RiblixStructures;
import Logger;
import SharedAddresses;

void moveLibItems(lua_State* L, const char* libName, Table* env, Table* destination)
{
	lua_pushrawtable(L, env); // env
	lua_getfield(L, -1, libName); // env, lib

	lua_pushnil(L); // env, lib, nil
	while (lua_next(L, -2)) // env, lib, k, v
	{
		lua_pushrawtable(L, destination); // env, lib, k, v, target
		lua_pushvalue(L, -3); // env, lib, k, v, target, k
		lua_pushvalue(L, -3); // env, lib, k, v, target, k, v
		lua_settable(L, -3); // env, lib, k, v, target
		lua_pop(L, 1); // env, lib, k, v
		lua_pop(L, 1); // env, lib, k
	}

	lua_pop(L, 2); // pop env & lib
}

void registerFunction(lua_State* L, Table* destination, lua_CFunction function, const char* name)
{
	lua_pushrawtable(L, destination);
	lua_pushcclosure(L, function, name);
	lua_setfield(L, -2, name);
	lua_pop(L, 1);
}

Table* getrenv(lua_State* L, bool asMainThread)
{
	if (asMainThread)
		return L->gt;

	if (!L->gt->metatable)
		logger.log("cannot get renv from thread (crashing now XDD)");

	lua_pushrawtable(L, L->gt->metatable);
	lua_pushstring(L, "__index");
	lua_rawget(L, -2);
	auto result = hvalue(luaA_toobject(L, -1));
	lua_pop(L, 1);
	return result;
}

void createRedirectionProxy(lua_State* L, Table* main, Table* to)
{
	lua_createtable(L);
	auto proxy = lua_totable(L, -1);

	lua_pushrawtable(L, to);
	lua_setfield(L, -2, "__index");

	lua_pushstring(L, "The metatable is locked");
	lua_setfield(L, -2, "__metatable");

	main->metatable = proxy;
	lua_pop(L, 1);
}

int envgetter(lua_State* L)
{
	lua_pushrawtable(L, hvalue(index2addr(L, lua_upvalueindex(1))));
	return 1;
}

void LuaApiRuntimeState::injectEnvironment(std::shared_ptr<GlobalStateInfo> info) const
{
	lua_State* L = info->mainThread;
	auto renv = getrenv(L, true);
	L = lua_newthread(L);
	info->ourMainThread = L;

	lua_pushlightuserdatatagged(L, L);
	lua_pushrawthread(L, L);
	lua_rawset(L, LUA_REGISTRYINDEX);

	{
		lua_createtable(L);
		auto genv = lua_totable(L, -1);

		lua_pushrawtable(L, genv);
		lua_pushcclosure(L, envgetter, "getgenv", 1);
		lua_setfield(L, -2, "getgenv");

		lua_pushrawtable(L, renv);
		lua_pushcclosure(L, envgetter, "getrenv", 1);
		lua_setfield(L, -2, "getrenv");

		lua_createtable(L);
		lua_setfield(L, -2, "_G");

		lua_createtable(L);
		lua_setfield(L, -2, "shared");

		luaL_register(L, baseLibrary);
		luaL_register(L, filesystemLibrary);
		luaL_register(L, tableLibrary);
		luaL_register(L, debug_library);
		luaL_register(L, closureLibrary);
		luaL_register(L, closureDebugLibrary);
		luaL_register(L, gcLibrary);

		// debug
		{
			lua_createtable(L);
			Table* debug = lua_totable(L, -1);
			lua_pushvalue(L, -1);
			lua_setfield(L, -3, "debug");

			luaL_register(L, closureDebugLibrary);

			moveLibItems(L, "debug", renv, debug);

			if (luaApiRuntimeState.getLuaSettings().allow_setproto)
			{
				registerFunction(L, genv, carbon_setproto, "setproto");
				registerFunction(L, debug, carbon_setproto, "setproto");
			}

			debug->readonly = true;
			lua_pop(L, 1);
		}

		createRedirectionProxy(L, genv, renv);
		lua_pop(L, 1);
		L->gt = genv;
	}

	info->environmentInjected = true;
};

void LuaApiRuntimeState::runScript(std::shared_ptr<GlobalStateInfo> info, const std::string& source) const
{
	if (!info->environmentInjected)
		injectEnvironment(info);

	auto L = lua_newthread(info->ourMainThread);

	lua_createtable(L);
	auto env = lua_totable(L, -1);
	auto genv = L->gt;
	lua_pop(L, 1);

	if (luaApiRuntimeState.apiSettings->set_max_initial_identity)
		L->userdata->identity = 7;

	if (luaApiRuntimeState.apiSettings->set_max_initial_capabilities)
		L->userdata->capabilities.set(Capabilities::All);

	createRedirectionProxy(L, env, genv);
	L->gt = env;

	if (compile(L, source.c_str(), "carbon"))
	{
		// stack: closure
		try
		{
			// stack is clean and call base is stack base so its safe to call directly
			luaApiAddresses.task_defer(L);
		}
		catch (const lua_exception& e)
		{
			logger.log(e.what());
			lua_getglobal(L, "warn");
			lua_pushstring(L, e.what());
			lua_pcall(L, 1, 0, 0);
		}
		catch (const std::exception& e)
		{
			logger.log(e.what());
			lua_getglobal(L, "warn");
			lua_pushstring(L, e.what());
			lua_pcall(L, 1, 0, 0);
		}
		catch (...)
		{
			logger.log("unhandled exception on runScript");
			lua_getglobal(L, "warn");
			lua_pushstring(L, "unhandled exception");
			lua_pcall(L, 1, 0, 0);
		}
	}
	else
	{
		// stack: error
		lua_getglobal(L, "warn");
		lua_insert(L, -2);
		lua_pcall(L, 1, 0, 0);
	}
}

void setProtoExtraSpace(Proto* proto, ProtoExtraSpace* data) {
	proto->userdata = data;
	for (int index = 0; index < proto->sizep; index++)
		setProtoExtraSpace(proto->p[index], data);
}

static ProtoExtraSpace maSpace = ([]() -> ProtoExtraSpace {
	ProtoExtraSpace result;
	result.capabilities.set(Capabilities::All);
	return result;
})();

bool LuaApiRuntimeState::compile(lua_State* L, const char* source, const char* chunkname) const
{
	auto bytecode = ::compile(std::string(source));

	bool didLoad = !riblixAddresses.luau_load(L, chunkname, bytecode.c_str(), bytecode.size(), 0);

	if (didLoad)
	{
		auto compiled = lua_toclosure(L, -1);
		setProtoExtraSpace(compiled->l.p, &maSpace);
	}

	return didLoad;
}