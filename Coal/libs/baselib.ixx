module;
#include "../../Common/Utils.h"
export module libs.baselib;

import Luau;
import Luau.Riblix;
import RiblixStructures;
import LuaEnv;

int coal_getreg(lua_State* L);
int coal_getgenv(lua_State* L);
int coal_getrenv(lua_State* L);
int coal_getstateenv(lua_State* L);

int coal_identifyexecutor(lua_State* L);

int coal_getnamecallmethod(lua_State* L);
int coal_setnamecallmethod(lua_State* L);

int coal_setidentity(lua_State* L);
int coal_getidentity(lua_State* L);

int coal_setcapability(lua_State* L);
int coal_hascapability(lua_State* L);

int coal_checkcaller(lua_State* L);
int coal_isourthread(lua_State* L);
int coal_setourthread(lua_State* L);

int coal_getcallingscript(lua_State* L);

int coal_getinstances(lua_State* L);
int coal_getnilinstances(lua_State* L);

int coal_cacheinvalidate(lua_State* L);
int coal_cachereplace(lua_State* L);
int coal_iscached(lua_State* L);
int coal_cloneref(lua_State* L);

export const luaL_Reg baseLibrary[] = {
	{"getreg", coal_getreg},
	{"getgenv", coal_getgenv},
	{"getrenv", coal_getrenv},
	{"getstateenv", coal_getstateenv},

	{"identifyexecutor", coal_identifyexecutor},

	{"getnamecallmethod", coal_getnamecallmethod},
	{"setnamecallmethod", coal_setnamecallmethod},

	{"setidentity", coal_setidentity},
	{"getidentity", coal_getidentity},

	{"setcapability", coal_setcapability},
	{"hascapability", coal_hascapability},

	{"checkcaller", coal_checkcaller},
	{"isourthread", coal_isourthread},
	{"setourthread", coal_setourthread},

	{"getcallingscript", coal_getcallingscript},

	{"getinstances", coal_getinstances},
	{"getnilinstances", coal_getnilinstances},

	{"cacheinvalidate", coal_cacheinvalidate},
	{"cachereplace", coal_cachereplace},
	{"iscached", coal_iscached},
	{"cloneref", coal_cloneref},

	{nullptr, nullptr},
};


int coal_getreg(lua_State* L)
{
	lua_pushvalue(L, LUA_REGISTRYINDEX);
	return 1;
}

int coal_getgenv(lua_State* L)
{
	lua_pushrawtable(L, luaApiRuntimeState.mainEnv);
	return 1;
}

int coal_getrenv(lua_State* L)
{
	lua_pushrawtable(L, luaApiRuntimeState.mainEnv->metatable);
	lua_pushstring(L, "__index");
	lua_rawget(L, -2);
	return 1;
}

int coal_identifyexecutor(lua_State* L)
{
	lua_pushstring(L, "coal");
	lua_pushstring(L, "mines");
	return 2;
}

int coal_getnamecallmethod(lua_State* L)
{
	if (L->namecall)
		lua_pushrawstring(L, L->namecall);
	else
		lua_pushnil(L);
	return 1;
}

int coal_setnamecallmethod(lua_State* L)
{
	luaL_checktype(L, 1, LUA_TSTRING);
	L->namecall = &index2addr(L, 1)->value.gc->ts;
	return 0;
}

int coal_getstateenv(lua_State* L)
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

<<<<<<< HEAD:Coal/libs/baselib.ixx
Capabilities::CapabilityType nameToCapability(const char* name)
{
	if (strcmp_caseInsensitive(name, "All"))
	{
		return (Capabilities::CapabilityType)(
			Capabilities::Plugin
			| Capabilities::LocalUser
			| Capabilities::WritePlayer
			| Capabilities::RobloxScript
			| Capabilities::RobloxEngine
			| Capabilities::NotAccessible
			| Capabilities::RunClientScript
			| Capabilities::RunServerScript
			| Capabilities::AccessOutsideWrite
			| Capabilities::SpecialCapability
			| Capabilities::AssetRequire
			| Capabilities::LoadString
			| Capabilities::ScriptGlobals
			| Capabilities::CreateInstances
			| Capabilities::Basic
			| Capabilities::Audio
			| Capabilities::DataStore
			| Capabilities::Network
			| Capabilities::Physics
			);
	}

	if (strcmp_caseInsensitive(name, "Restricted")) return Capabilities::Restricted;
	if (strcmp_caseInsensitive(name, "Plugin")) return Capabilities::Plugin;
	if (strcmp_caseInsensitive(name, "LocalUser")) return Capabilities::LocalUser;
	if (strcmp_caseInsensitive(name, "WritePlayer")) return Capabilities::WritePlayer;
	if (strcmp_caseInsensitive(name, "RobloxScript")) return Capabilities::RobloxScript;
	if (strcmp_caseInsensitive(name, "RobloxEngine")) return Capabilities::RobloxEngine;
	if (strcmp_caseInsensitive(name, "NotAccessible")) return Capabilities::NotAccessible;
	if (strcmp_caseInsensitive(name, "RunClientScript")) return Capabilities::RunClientScript;
	if (strcmp_caseInsensitive(name, "RunServerScript")) return Capabilities::RunServerScript;
	if (strcmp_caseInsensitive(name, "AccessOutsideWrite")) return Capabilities::AccessOutsideWrite;
	if (strcmp_caseInsensitive(name, "SpecialCapability")) return Capabilities::SpecialCapability;
	if (strcmp_caseInsensitive(name, "AssetRequire")) return Capabilities::AssetRequire;
	if (strcmp_caseInsensitive(name, "LoadString")) return Capabilities::LoadString;
	if (strcmp_caseInsensitive(name, "ScriptGlobals")) return Capabilities::ScriptGlobals;
	if (strcmp_caseInsensitive(name, "CreateInstances")) return Capabilities::CreateInstances;
	if (strcmp_caseInsensitive(name, "Basic")) return Capabilities::Basic;
	if (strcmp_caseInsensitive(name, "Audio")) return Capabilities::Audio;
	if (strcmp_caseInsensitive(name, "DataStore")) return Capabilities::DataStore;
	if (strcmp_caseInsensitive(name, "Network")) return Capabilities::Network;
	if (strcmp_caseInsensitive(name, "Physics")) return Capabilities::Physics;

	return Capabilities::Restricted;
=======
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
>>>>>>> f0ff9a0 (- Automatic structure offset analyzer):Carbon/libs/baselib.ixx
}

int coal_setcapability(lua_State* L)
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

int coal_hascapability(lua_State* L)
{
	const char* name = luaL_checklstring(L, 1);
	lua_pushboolean(L, getCurrentContext()->capabilities.isSet(nameToCapability(name)));

	return 1;
}

int coal_checkcaller(lua_State* L)
{
	lua_pushboolean(L, L->userdata->capabilities.isSet(Capabilities::OurThread));
	return 1;
}

int coal_isourthread(lua_State* L)
{
	int argbase = 0;
	auto target = getthread(L, argbase);

	const char* name = luaL_checklstring(L, argbase + 1);
	lua_pushboolean(L, target->userdata->capabilities.isSet(Capabilities::OurThread));

	return 1;
}

int coal_setourthread(lua_State* L)
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

int coal_setidentity(lua_State* L)
{
	int argbase = 0;
	auto target = getthread(L, argbase);
	int identity = luaL_checkinteger(L, argbase + 1);
	target->userdata->identity = identity;
	if (target == L)
		getCurrentContext()->identity = identity;
	return 0;
}

int coal_getidentity(lua_State* L)
{
	int argbase = 0;
	auto target = getthread(L, argbase);
	lua_pushinteger(L, target->userdata->identity);
	return 1;
}


int coal_getcallingscript(lua_State* L)
{
	auto extraSpace = L->userdata;
	if (auto script = extraSpace->script)
<<<<<<< HEAD:Coal/libs/baselib.ixx
		InstanceBridge_pushshared(L, script->shared.lock());
=======
		InstanceBridge_pushshared(L, script->getSelf().lock());
>>>>>>> f0ff9a0 (- Automatic structure offset analyzer):Carbon/libs/baselib.ixx
	else
		lua_pushnil(L);

	return 1;
}

int coal_getinstances(lua_State* L)
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

int coal_getnilinstances(lua_State* L)
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


int coal_cacheinvalidate(lua_State* L)
{
	auto instance = checkInstance(L, 1);
	push_instanceBridgeMap(L);
	lua_pushlightuserdatatagged(L, instance);
	lua_pushnil(L);
	lua_rawset(L, -3);
	return 1;
}

int coal_cachereplace(lua_State* L)
{
	auto instance = checkInstance(L, 1);
	checkInstance(L, 2);
	push_instanceBridgeMap(L);
	lua_pushlightuserdatatagged(L, instance);
	lua_pushvalue(L, 2);
	lua_rawset(L, -3);
	return 1;
}

int coal_iscached(lua_State* L)
{
	auto instance = checkInstance(L, 1);
	push_instanceBridgeMap(L);
	lua_pushlightuserdatatagged(L, instance);
	lua_rawget(L, -2);
	lua_pushboolean(L, !lua_isnil(L, -1));
	return 1;
}

int coal_cloneref(lua_State* L)
{
	auto instance = checkInstance(L, 1);
	lua_newuserdatatagged(L, sizeof(instance));
	lua_getmetatable(L, 1);
	lua_setmetatable(L, -2);
	return 1;
}