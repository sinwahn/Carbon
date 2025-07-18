export module CarbonLuaApiLibs.baselib;

import Luau;
import Luau.Riblix;
import RiblixStructures;
import LuaEnv;
import StringUtils;

int carbon_getreg(lua_State* L);
int carbon_getstateenv(lua_State* L);

int carbon_identifyexecutor(lua_State* L);

int carbon_getnamecallmethod(lua_State* L);
int carbon_setnamecallmethod(lua_State* L);

int carbon_setidentity(lua_State* L);
int carbon_getidentity(lua_State* L);

int carbon_setcapability(lua_State* L);
int carbon_hascapability(lua_State* L);

int carbon_checkcaller(lua_State* L);
int carbon_isourthread(lua_State* L);
int carbon_setourthread(lua_State* L);

int carbon_getcallingscript(lua_State* L);

int carbon_getinstances(lua_State* L);
int carbon_getnilinstances(lua_State* L);

int carbon_cacheinvalidate(lua_State* L);
int carbon_cachereplace(lua_State* L);
int carbon_iscached(lua_State* L);
int carbon_cloneref(lua_State* L);

int carbon_loadstring(lua_State* L);

export const luaL_Reg baseLibrary[] = {
	{"getreg", carbon_getreg},
	{"getstateenv", carbon_getstateenv},

	{"identifyexecutor", carbon_identifyexecutor},

	{"getnamecallmethod", carbon_getnamecallmethod},
	{"setnamecallmethod", carbon_setnamecallmethod},

	{"setidentity", carbon_setidentity},
	{"getidentity", carbon_getidentity},

	{"setcapability", carbon_setcapability},
	{"hascapability", carbon_hascapability},

	{"checkcaller", carbon_checkcaller},
	{"isourthread", carbon_isourthread},
	{"setourthread", carbon_setourthread},

	{"getcallingscript", carbon_getcallingscript},

	{"getinstances", carbon_getinstances},
	{"getnilinstances", carbon_getnilinstances},

	{"cacheinvalidate", carbon_cacheinvalidate},
	{"cachereplace", carbon_cachereplace},
	{"iscached", carbon_iscached},
	{"cloneref", carbon_cloneref},

	{"loadstring", carbon_loadstring},

	{nullptr, nullptr},
};

int carbon_getreg(lua_State* L)
{
	lua_pushvalue(L, LUA_REGISTRYINDEX);
	return 1;
}


int carbon_identifyexecutor(lua_State* L)
{
	lua_pushstring(L, "coal");
	lua_pushstring(L, "mines");
	return 2;
}

int carbon_getnamecallmethod(lua_State* L)
{
	if (L->namecall)
		lua_pushrawstring(L, L->namecall);
	else
		lua_pushnil(L);
	return 1;
}

int carbon_setnamecallmethod(lua_State* L)
{
	luaL_checktype(L, 1, LUA_TSTRING);
	L->namecall = &index2addr(L, 1)->value.gc->ts;
	return 0;
}

int carbon_getstateenv(lua_State* L)
{
	luaL_checktype(L, 1, LUA_TTHREAD);
	auto state = thvalue(index2addr(L, 1));

	if (luaApiRuntimeState.getLuaSettings().getstateenv_returns_ref)
		lua_pushrawtable(L, state->gt);
	else
		lua_pushrawtable(L, luaH_clone(L, state->gt));

	return 1;
}

const char* getCapabilityName(Capabilities::CapabilityType capability_) {
	using enum Capabilities::CapabilityType;
	auto capability = (uint64_t)capability_;
	if (!capability) return "Restricted";
	if (capability & (uint64_t)Plugin) return "Plugin";
	if (capability & (uint64_t)LocalUser) return "LocalUser";
	if (capability & (uint64_t)WritePlayer) return "WritePlayer";
	if (capability & (uint64_t)RobloxScript) return "RobloxScript";
	if (capability & (uint64_t)RobloxEngine) return "RobloxEngine";
	if (capability & (uint64_t)NotAccessible) return "NotAccessible";
	if (capability & (uint64_t)RunClientScript) return "RunClientScript";
	if (capability & (uint64_t)RunServerScript) return "RunServerScript";
	if (capability & (uint64_t)AccessOutsideWrite) return "AccessOutsideWrite";
	if (capability & (uint64_t)Unassigned) return "Unassigned";
	if (capability & (uint64_t)AssetRequire) return "AssetRequire";
	if (capability & (uint64_t)LoadString) return "LoadString";
	if (capability & (uint64_t)ScriptGlobals) return "ScriptGlobals";
	if (capability & (uint64_t)CreateInstances) return "CreateInstances";
	if (capability & (uint64_t)Basic) return "Basic";
	if (capability & (uint64_t)Audio) return "Audio";
	if (capability & (uint64_t)DataStore) return "DataStore";
	if (capability & (uint64_t)Network) return "Network";
	if (capability & (uint64_t)Physics) return "Physics";
	if (capability & (uint64_t)UI) return "UI";
	if (capability & (uint64_t)CSG) return "CSG";
	if (capability & (uint64_t)Chat) return "Chat";
	if (capability & (uint64_t)Animation) return "Animation";
	if (capability & (uint64_t)Avatar) return "Avatar";
	if (capability & (uint64_t)Input) return "Input";
	if (capability & (uint64_t)Environment) return "Environment";
	if (capability & (uint64_t)RemoteEvent) return "RemoteEvent";
	if (capability & (uint64_t)LegacySound) return "LegacySound";
	if (capability & (uint64_t)Players) return "Players";
	if (capability & (uint64_t)CapabilityControl) return "CapabilityControl";
	if (capability & (uint64_t)InternalTest) return "InternalTest";
	if (capability & (uint64_t)PluginOrOpenCloud) return "PluginOrOpenCloud";
	if (capability & (uint64_t)Assistant) return "Assistant";
	return "Unknown";
}

Capabilities::CapabilityType nameToCapability(const char* name) {
	using enum Capabilities::CapabilityType;
	if (strcmp_caseInsensitive(name, "Restricted")) return Restricted;
	if (strcmp_caseInsensitive(name, "Plugin")) return Plugin;
	if (strcmp_caseInsensitive(name, "LocalUser")) return LocalUser;
	if (strcmp_caseInsensitive(name, "WritePlayer")) return WritePlayer;
	if (strcmp_caseInsensitive(name, "RobloxScript")) return RobloxScript;
	if (strcmp_caseInsensitive(name, "RobloxEngine")) return RobloxEngine;
	if (strcmp_caseInsensitive(name, "NotAccessible")) return NotAccessible;
	if (strcmp_caseInsensitive(name, "RunClientScript")) return RunClientScript;
	if (strcmp_caseInsensitive(name, "RunServerScript")) return RunServerScript;
	if (strcmp_caseInsensitive(name, "AccessOutsideWrite")) return AccessOutsideWrite;
	if (strcmp_caseInsensitive(name, "Unassigned")) return Unassigned;
	if (strcmp_caseInsensitive(name, "AssetRequire")) return AssetRequire;
	if (strcmp_caseInsensitive(name, "LoadString")) return LoadString;
	if (strcmp_caseInsensitive(name, "ScriptGlobals")) return ScriptGlobals;
	if (strcmp_caseInsensitive(name, "CreateInstances")) return CreateInstances;
	if (strcmp_caseInsensitive(name, "Basic")) return Basic;
	if (strcmp_caseInsensitive(name, "Audio")) return Audio;
	if (strcmp_caseInsensitive(name, "DataStore")) return DataStore;
	if (strcmp_caseInsensitive(name, "Network")) return Network;
	if (strcmp_caseInsensitive(name, "Physics")) return Physics;
	if (strcmp_caseInsensitive(name, "UI")) return UI;
	if (strcmp_caseInsensitive(name, "CSG")) return CSG;
	if (strcmp_caseInsensitive(name, "Chat")) return Chat;
	if (strcmp_caseInsensitive(name, "Animation")) return Animation;
	if (strcmp_caseInsensitive(name, "Avatar")) return Avatar;
	if (strcmp_caseInsensitive(name, "Input")) return Input;
	if (strcmp_caseInsensitive(name, "Environment")) return Environment;
	if (strcmp_caseInsensitive(name, "RemoteEvent")) return RemoteEvent;
	if (strcmp_caseInsensitive(name, "LegacySound")) return LegacySound;
	if (strcmp_caseInsensitive(name, "Players")) return Players;
	if (strcmp_caseInsensitive(name, "CapabilityControl")) return CapabilityControl;
	if (strcmp_caseInsensitive(name, "InternalTest")) return InternalTest;
	if (strcmp_caseInsensitive(name, "PluginOrOpenCloud")) return PluginOrOpenCloud;
	if (strcmp_caseInsensitive(name, "Assistant")) return Assistant;
	if (strcmp_caseInsensitive(name, "Unknown")) return Unknown;
	if (strcmp_caseInsensitive(name, "All")) return All;
	return Restricted;
}

int carbon_setcapability(lua_State* L)
{
	const char* name = luaL_checklstring(L, 1);
	bool doSet = luaL_optboolean(L, 2, true);
	if (doSet)
	{
		L->userdata->capabilities.set(nameToCapability(name));
		getCurrentContext()->capabilities.set(nameToCapability(name));
	}
	else
	{
		L->userdata->capabilities.clear(nameToCapability(name));
		getCurrentContext()->capabilities.clear(nameToCapability(name));
	}

	return 0;
}

int carbon_hascapability(lua_State* L)
{
	const char* name = luaL_checklstring(L, 1);
	lua_pushboolean(L, getCurrentContext()->capabilities.isSet(nameToCapability(name)));

	return 1;
}

// TODO: switch away from capabilities
int carbon_checkcaller(lua_State* L)
{
	lua_pushboolean(L, L->userdata->capabilities.isSet(Capabilities::OurThread));
	return 1;
}

// TODO: switch away from capabilities
int carbon_isourthread(lua_State* L)
{
	int argbase = 0;
	auto target = getthread(L, argbase);
	lua_pushboolean(L, target->userdata->capabilities.isSet(Capabilities::OurThread));
	return 1;
}

// TODO: switch away from capabilities
int carbon_setourthread(lua_State* L)
{
	int argbase = 0;
	auto target = getthread(L, argbase);

	bool isOur = luaL_checkboolean(L, argbase + 1);
	if (isOur)
		target->userdata->capabilities.set(Capabilities::OurThread);
	else
		target->userdata->capabilities.clear(Capabilities::OurThread);

	return 0;
}

int carbon_setidentity(lua_State* L)
{
	int argbase = 0;
	auto target = getthread(L, argbase);
	int identity = luaL_checkinteger(L, argbase + 1);
	target->userdata->identity = identity;
	if (target == L)
		getCurrentContext()->identity = identity;
	return 0;
}

int carbon_getidentity(lua_State* L)
{
	int argbase = 0;
	auto target = getthread(L, argbase);
	lua_pushinteger(L, target->userdata->identity);
	return 1;
}


int carbon_getcallingscript(lua_State* L)
{
	auto extraSpace = L->userdata;
	if (auto script = extraSpace->script)
		InstanceBridge_pushshared(L, script->getSelf().lock());
	else
		lua_pushnil(L);

	return 1;
}

int carbon_getinstances(lua_State* L)
{
	lua_createtable(L, 0, 0);
	push_instanceBridgeMap(L);

	int index = 0;
	lua_pushnil(L); // Stack: result, map, nil
	while (lua_next(L, -2)) // Stack: result, map, k, v
	{
		if (isTypeofType(L, -1, "Instance"))
		{
			lua_pushinteger(L, ++index); // Stack: result, map, k, v, index
			lua_pushvalue(L, -2); // Stack: result, map, k, v, index, v
			lua_rawset(L, -6); // Stack: result, map, k, v
		}
		lua_pop(L, 1); // Stack: result, map, k
	}
	lua_pushvalue(L, -2); // Stack: result, map, result
	return 1;
}

int carbon_getnilinstances(lua_State* L)
{
	lua_createtable(L, 0, 0);
	push_instanceBridgeMap(L);

	int index = 0;
	lua_pushnil(L); // Stack: result, map, nil
	while (lua_next(L, -2)) // Stack: result, map, k, v
	{
		if (isTypeofType(L, -1, "Instance"))
		{
			if (auto instance = toInstance(L, -1))
			{
				if (instance->getParent() == nullptr)
				{
					lua_pushinteger(L, ++index); // Stack: result, map, k, v, index
					lua_pushvalue(L, -2); // Stack: result, map, k, v, index, v
					lua_rawset(L, -6); // Stack: result, map, k, v
				}
			}
		}
		lua_pop(L, 1); // Stack: result, map, k
	}
	lua_pushvalue(L, -2); // Stack: result, map, result
	return 1;
}


int carbon_cacheinvalidate(lua_State* L)
{
	auto instance = checkInstance(L, 1);
	push_instanceBridgeMap(L);
	lua_pushlightuserdatatagged(L, instance);
	lua_pushnil(L);
	lua_rawset(L, -3);
	return 1;
}

int carbon_cachereplace(lua_State* L)
{
	auto instance = checkInstance(L, 1);
	checkInstance(L, 2);
	push_instanceBridgeMap(L);
	lua_pushlightuserdatatagged(L, instance);
	lua_pushvalue(L, 2);
	lua_rawset(L, -3);
	return 1;
}

int carbon_iscached(lua_State* L)
{
	auto instance = checkInstance(L, 1);
	push_instanceBridgeMap(L);
	lua_pushlightuserdatatagged(L, instance);
	lua_rawget(L, -2);
	lua_pushboolean(L, !lua_isnil(L, -1));
	return 1;
}

int carbon_cloneref(lua_State* L)
{
	auto instance = checkInstance(L, 1);
	lua_newuserdatatagged(L, sizeof(instance));
	lua_getmetatable(L, 1);
	lua_setmetatable(L, -2);
	return 1;
}

int carbon_loadstring(lua_State* L)
{
	size_t length = 0;
	const char* source = luaL_checklstring(L, 1, &length);
	const char* chunkname = luaL_optlstring(L, 2, "COAL");

	if (luaApiRuntimeState.compile(L, source, chunkname))
		return 1;

	lua_pushnil(L);
	lua_insert(L, -2);
	return 2;
}