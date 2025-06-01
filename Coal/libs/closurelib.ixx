export module libs.closurelib;

import <map>;
import Luau;
import FunctionMarker;
import LuaEnv;
import HookHandler;

export CallInfo* luaD_growCI_hook(lua_State* L);

int coal_iscclosure(lua_State* L);
int coal_islclosure(lua_State* L);
int coal_newcclosure(lua_State* L);
int coal_clonefunction(lua_State* L);

int coal_hookfunction(lua_State* L);
int coal_hookmetamethod(lua_State* L);
int coal_isfunctionhooked(lua_State* L);
int coal_restorefunction(lua_State* L);

int coal_setourclosure(lua_State* L);
int coal_isourclosure(lua_State* L);

int coal_setsafeenv(lua_State* L);

int coal_getstack(lua_State* L);
int coal_setstack(lua_State* L);

int coal_getmaxstacksize(lua_State* L);
int coal_getstacksize(lua_State* L);

int coal_getupvalues(lua_State* L);
int coal_getupvalue(lua_State* L);
int coal_setupvalue(lua_State* L);

int coal_getconstants(lua_State* L);
int coal_getconstant(lua_State* L);
int coal_setconstant(lua_State* L);

int coal_getprotoinfo(lua_State* L);
int coal_getprotos(lua_State* L);
int coal_getproto(lua_State* L);
export int coal_setproto(lua_State* L);
int coal_getinfo(lua_State* L);

export const luaL_Reg closureDebugLibrary[] = {
	{"getstack", coal_getstack},
	{"setstack", coal_setstack},

	{"getmaxstacksize", coal_getmaxstacksize},
	{"getstacksize", coal_getstacksize},

	{"getupvalue", coal_getupvalue},
	{"setupvalue", coal_setupvalue},
	{"getupvalues", coal_getupvalues},

	{"getconstants", coal_getconstants},
	{"getconstant", coal_getconstant},
	{"setconstant", coal_setconstant},

	{"getprotos", coal_getprotos},
	{"getproto", coal_getproto},

	{"getinfo", coal_getinfo},
	{"getprotoinfo", coal_getprotoinfo},

	{nullptr, nullptr},
};

export const luaL_Reg closureLibrary[] = {
	{"setsafeenv", coal_setsafeenv},

	{"iscclosure", coal_iscclosure},
	{"islclosure", coal_islclosure},
	{"setourclosure", coal_setourclosure},
	{"isourclosure", coal_isourclosure},

	{"newcclosure", coal_newcclosure},
	{"clonefunction", coal_clonefunction},

	{"hookfunction", coal_hookfunction},
	{"hookmetamethod", coal_hookmetamethod},
	{"isfunctionhooked", coal_isfunctionhooked},
	{"restorefunction", coal_restorefunction},

	{nullptr, nullptr},
};


int coal_iscclosure(lua_State* L)
{
	lua_pushboolean(L, luaL_checkfunction(L, 1)->isC);
	return 1;
}

int coal_islclosure(lua_State* L)
{
	lua_pushboolean(L, !luaL_checkfunction(L, 1)->isC);
	return 1;
}

inline void expectLuaFunction(lua_State* L, int idx)
{
	if (iscfunction(luaL_checkfunction(L, idx)))
		luaL_argerrorL(L, 1, "Lua function expected");
}

inline void expectCFunction(lua_State* L, int idx)
{
	if (isluafunction(luaL_checkfunction(L, idx)))
		luaL_argerrorL(L, 1, "C function expected");
}

inline void expectLuaFunction(lua_State* L, Closure& closure)
{
	if (closure.isC)
		luaL_argerrorL(L, 1, "Lua function expected");
}

int forwardCallFunction(lua_State* L, Closure* what)
{
	int passedArgsSize = lua_gettop(L);
	lua_pushclosure(L, what);

	for (int i = 1; i <= passedArgsSize; i++)
		lua_pushvalue(L, i);

	lua_call(L, passedArgsSize, LUA_MULTRET);

	int valuesReturned = lua_gettop(L) - passedArgsSize;
	return valuesReturned;
}

static thread_local bool isInHiddenCall = false;

CallInfo* luaD_growCI_hook(lua_State* L)
{
	if (!isInHiddenCall)
	{
		auto original = hookHandler.getHook(HookId::growCI).getOriginal();
		return reinterpret_cast<decltype(luaApiAddresses.luaD_growCI)>(original)(L);
	}
	else
	{
		const int hardlimit = LUAI_MAXCALLS + (LUAI_MAXCALLS >> 3);
		const int hooklimit = LUAI_MAXCALLS + (LUAI_MAXCALLS >> 4);

		if (L->size_ci >= hardlimit)
			luaD_throw(L, LUA_ERRERR); // error while handling stack error

		int request;
		if (L->size_ci >= LUAI_MAXCALLS)
			request = hooklimit;
		else
		{
			if (L->size_ci * 2 < LUAI_MAXCALLS)
				request = L->size_ci * 2;
			else
				request = LUAI_MAXCALLS;
		}

		luaApiAddresses.luaD_reallocCI(L, request);

		if (L->size_ci > hooklimit)
		{
			lua_pushstring(L, "stack overflow");
			luaD_throw(L, LUA_ERRRUN);
		}

		return ++L->ci;
	}
}

int forwardCallFunction_hidden(lua_State* L, Closure* what)
{
	int passedArgsSize = lua_gettop(L);
	lua_pushclosure(L, what);

	for (int i = 1; i <= passedArgsSize; i++)
		lua_pushvalue(L, i);

	isInHiddenCall = true;
	L->nCcalls--; // "hide" handler

	try
	{
		lua_call(L, passedArgsSize, LUA_MULTRET);
		L->nCcalls++;
		isInHiddenCall = false;
	}
	catch (...)
	{
		L->nCcalls++;
		isInHiddenCall = false;
		throw;
	}

	int valuesReturned = lua_gettop(L) - passedArgsSize;
	return valuesReturned;
}

int usercclosureHandler(lua_State* L)
{
	auto userClosure = clvalue(index2addr(L, lua_upvalueindex(1)));
	return forwardCallFunction(L, userClosure);
}

int coal_newcclosure(lua_State* L)
{
	expectLuaFunction(L, 1);
	auto name = luaL_optlstring(L, 2, nullptr);
	lua_pushvalue(L, 1);
	lua_pushcclosure(L, usercclosureHandler, name, 1);
	return 1;
}

Closure* copyLuaClosure(lua_State* L, Closure* original)
{
	Closure* copy = luaF_newLclosure(L, original->nupvalues, original->env, original->l.p);

	copy->nupvalues = original->nupvalues;
	copy->stacksize = original->stacksize;
	copy->preload = original->preload;
	copy->gclist = original->gclist;

	return copy;
}

void pushLuaClosureCopy(lua_State* L, Closure* target)
{
	Closure* copy = copyLuaClosure(L, target);
	lua_pushclosure(L, copy);
}

class LuaApiHookHandler
{
public:

	struct HookInfo
	{
		bool originalIsC;

		union
		{
			struct
			{
				lua_CFunction originalCFunction;
				Closure* hook;
			} c;

			struct
			{
				Proto* originalProtoCopy;
				Closure* originalClosureCopy;
			} l;
		};

		void changeCHook(lua_State* L, Closure* newHook)
		{
			if (!originalIsC)
				return;

			lua_pushlightuserdatatagged(L, c.hook);
			lua_pushnil(L);
			lua_rawset(L, LUA_REGISTRYINDEX);

			lua_pushlightuserdatatagged(L, newHook);
			lua_pushclosure(L, newHook);
			lua_rawset(L, LUA_REGISTRYINDEX);

			c.hook = newHook;
		}

		static HookInfo fromC(lua_State* L, Closure* target, Closure* hook)
		{
			HookInfo result;
			result.originalIsC = true;
			result.c.originalCFunction = target->c.f;

			result.c.hook = hook;

			// keep hook from gcing
			lua_pushlightuserdatatagged(L, hook);
			lua_pushclosure(L, hook);
			lua_rawset(L, LUA_REGISTRYINDEX);

			return result;
		}

		static HookInfo fromLua(lua_State* L, Closure* target, Closure* hook)
		{
			HookInfo result;
			result.originalIsC = true;

			// saving proto too as closure might get hooked once more
			result.l.originalProtoCopy = target->l.p;

			auto closureCopy = copyLuaClosure(L, target);

			// keep hook from gcing
			lua_pushlightuserdatatagged(L, hook);
			lua_pushclosure(L, hook);
			lua_rawset(L, LUA_REGISTRYINDEX);

			lua_pushlightuserdatatagged(L, closureCopy);
			lua_pushclosure(L, closureCopy);
			lua_rawset(L, LUA_REGISTRYINDEX);
			result.l.originalClosureCopy = std::move(closureCopy);

			return result;
		}
	};

	using map_t = std::map<Closure*, HookInfo>;
	map_t originalToUserHookMap;

	bool isHooked(Closure* function) const
	{
		return originalToUserHookMap.count(function);
	}

	Closure* getHook(lua_State* L, Closure* function) const
	{
		return getIteratorSafe(L, function)->second.c.hook;
	}

	void restoreOriginal(lua_State* L, Closure* function)
	{
		auto infoIter = getIteratorSafe(L, function);
		auto& hookInfo = infoIter->second;
		if (hookInfo.originalIsC)
		{
			function->c.f = hookInfo.c.originalCFunction;

			lua_pushlightuserdatatagged(L, hookInfo.c.hook);
			lua_pushnil(L);
			lua_rawset(L, LUA_REGISTRYINDEX);
		}
		else
		{
			auto originalCopy = hookInfo.l.originalClosureCopy;
			for (int i = 0; i < originalCopy->nupvalues; i++)
				setobj(&function->l.uprefs[i], &originalCopy->l.uprefs[i]);

			function->nupvalues = originalCopy->nupvalues;
			function->stacksize = originalCopy->stacksize;
			function->preload = originalCopy->preload;
			function->gclist = originalCopy->gclist;

			function->l.p = hookInfo.l.originalProtoCopy;

			lua_pushlightuserdatatagged(L, hookInfo.l.originalClosureCopy);
			lua_pushnil(L);
			lua_rawset(L, LUA_REGISTRYINDEX);
		}

		originalToUserHookMap.erase(infoIter);
	}

	void registerLuaHook(lua_State* L, Closure* original, Closure* hook)
	{
		auto iter = originalToUserHookMap.find(original);
		if (iter == originalToUserHookMap.end())
			originalToUserHookMap.emplace(original, HookInfo::fromLua(L, original, hook));
	}

	void registerCHook(lua_State* L, Closure* original, Closure* hook)
	{
		auto iter = originalToUserHookMap.find(original);
		if (iter == originalToUserHookMap.end())
		{
			originalToUserHookMap.emplace(original, HookInfo::fromC(L, original, hook));
		}
		else
			iter->second.changeCHook(L, hook);
	}

private:

	map_t::const_iterator getIteratorSafe(lua_State* L, Closure* function) const
	{
		auto iter = originalToUserHookMap.find(function);
		if (iter == originalToUserHookMap.end())
			luaL_errorL(L, "function was not hooked");
		return iter;
	}
};

static LuaApiHookHandler luaApiHookHandler;


void checkUpvalueCountForHook(lua_State* L, Closure* target, Closure* hook)
{
	if (hook->nupvalues > target->nupvalues)
		luaL_errorL(L, "hook function has too many upvalues");
}

void pushCClosureCopy(lua_State* L, Closure* target)
{
	for (int i = 0; i < target->nupvalues; i++)
		luaA_pushobject(L, &target->c.upvals[i]);

	lua_pushcclosure(L, target->c.f, target->c.debugname, target->nupvalues);
	clvalue(luaA_toobject(L, -1))->env = target->env;
}

int hookCallHandler(lua_State* L)
{
	auto currentClosure = clvalue(L->ci->func);
	auto hook = luaApiHookHandler.getHook(L, currentClosure);
	return forwardCallFunction(L, hook);
}

int hookHandler_hidden(lua_State* L)
{
	auto currentClosure = clvalue(L->ci->func);
	auto hook = luaApiHookHandler.getHook(L, currentClosure);
	return forwardCallFunction_hidden(L, hook);
}

Proto* createHookProto(lua_State* L, Closure* target, Closure* hook)
{
	auto newProto = luaF_newproto(L);
	auto targetProto = target->l.p;
	auto hookProto = hook->l.p;

	newProto->nups = hookProto->nups;
	newProto->nups = hookProto->nups;
	newProto->numparams = hookProto->numparams;
	newProto->is_vararg = hookProto->is_vararg;
	newProto->maxstacksize = hookProto->maxstacksize;
	newProto->flags = hookProto->flags;

	newProto->k = hookProto->k;
	newProto->code = hookProto->code;
	newProto->p = hookProto->p;
	newProto->codeentry = hookProto->codeentry;

	newProto->execdata = hookProto->execdata;
	newProto->exectarget = hookProto->exectarget;

	newProto->lineinfo = hookProto->lineinfo;
	newProto->abslineinfo = hookProto->abslineinfo;
	newProto->locvars = hookProto->locvars;
	newProto->upvalues = hookProto->upvalues;
	newProto->source = targetProto->source;

	newProto->debugname = targetProto->debugname;
	newProto->debuginsn = targetProto->debuginsn;

	newProto->typeinfo = targetProto->typeinfo;

	newProto->userdata = hookProto->userdata;
	newProto->gclist = hookProto->gclist;

	newProto->sizecode = hookProto->sizecode;
	newProto->sizep = hookProto->sizep;
	newProto->sizelocvars = hookProto->sizelocvars;
	newProto->sizeupvalues = hookProto->sizeupvalues;
	newProto->sizek = hookProto->sizek;
	newProto->sizelineinfo = hookProto->sizelineinfo;
	newProto->linegaplog2 = hookProto->linegaplog2;
	newProto->linedefined = targetProto->linedefined;
	newProto->bytecodeid = hookProto->bytecodeid;
	newProto->sizetypeinfo = hookProto->sizetypeinfo;

	return newProto;
}

// TODO: whole lua hooking method is pretty unstable
void replaceLuaClosure(lua_State* L, Closure* target, Closure* hook)
{
	luaApiHookHandler.registerLuaHook(L, target, hook);

	for (int i = 0; i < hook->nupvalues; i++)
		setobj(&target->l.uprefs[i], &hook->l.uprefs[i]);

	target->nupvalues = hook->nupvalues;
	target->stacksize = hook->stacksize;
	target->preload = hook->preload;
	target->gclist = hook->gclist;

	target->l.p = createHookProto(L, target, hook);
}

void replaceCClosure(lua_State* L, Closure* target, Closure* hook, bool hideStack)
{
	luaApiHookHandler.registerCHook(L, target, hook);
	target->c.f = hideStack ? hookHandler_hidden : hookCallHandler;
}

int coal_hookfunction(lua_State* L)
{
	luaL_checkfunction(L, 1);
	luaL_checkfunction(L, 2);

	if (lua_iscfunction(L, 1))
	{
		auto target = clvalue(luaA_toobject(L, 1));
		auto hook = clvalue(luaA_toobject(L, 2));

		pushCClosureCopy(L, target);
		replaceCClosure(L, target, hook, true);
	}
	else
	{
		expectLuaFunction(L, 2);
		auto target = clvalue(luaA_toobject(L, 1));
		auto hook = clvalue(luaA_toobject(L, 2));

		checkUpvalueCountForHook(L, target, hook);

		pushLuaClosureCopy(L, target);
		replaceLuaClosure(L, target, hook);
	}

	return 1;
}

// args:
// 1 - object
// 2 - metamethodName
// 3 - lua closure as hook
int coal_hookmetamethod(lua_State* L)
{
	TValue* object = index2addr(L, 1);
	Table* metatable = nullptr;

	switch (ttype(object))
	{
	case LUA_TTABLE:
		metatable = hvalue(object)->metatable;
		break;
	case LUA_TUSERDATA:
		metatable = uvalue(object)->metatable;
		break;
	default:
		luaL_typeerrorL(L, 1, "table or userdata");
	}

	if (!metatable)
		luaL_argerrorL(L, 1, "object does not have metatable");

	luaL_checklstring(L, 2);
	
	auto metamethodName = tsvalue(index2addr(L, 2));
	lua_pushrawtable(L, metatable);
	lua_pushvalue(L, 2);
	lua_rawget(L, -2);

	auto metamethod = luaA_toobject(L, -1);

	if (metamethod == luaO_nilobject())
		luaL_errorL(L, "object does not have metamethod with name '%s'", metamethodName->data);

	if (!ttisfunction(metamethod))
		luaL_errorL(L, "metamethod type is '%s', 'function' expected", lua_typename(L, metamethod->tt));

	Closure* hook = nullptr;
	Closure* target = clvalue(metamethod);

	expectLuaFunction(L, 3);
	if (iscfunction(metamethod))
	{
		hook = clvalue(luaA_toobject(L, 3));

		pushCClosureCopy(L, target);
		replaceCClosure(L, target, hook, true);
	}
	else
	{
		hook = clvalue(luaA_toobject(L, 3));
		checkUpvalueCountForHook(L, target, hook);

		pushLuaClosureCopy(L, target);
		replaceLuaClosure(L, target, hook);
	}

	return 1;
}

int coal_isfunctionhooked(lua_State* L)
{
	luaL_checktype(L, 1, LUA_TFUNCTION);
	auto function = clvalue(luaA_toobject(L, 1));
	lua_pushboolean(L, luaApiHookHandler.isHooked(function));
	return 1;
}

int coal_restorefunction(lua_State* L)
{
	luaL_checktype(L, 1, LUA_TFUNCTION);
	auto function = clvalue(luaA_toobject(L, 1));
	luaApiHookHandler.restoreOriginal(L, function);
	return 0;
}

int coal_clonefunction(lua_State* L)
{
	luaL_checktype(L, 1, LUA_TFUNCTION);
	auto function = clvalue(luaA_toobject(L, 1));

	if (function->isC)
		pushCClosureCopy(L, function);
	else
		pushLuaClosureCopy(L, function);

	return 1;
}

int coal_isourclosure(lua_State* L)
{
	luaL_checktype(L, 1, LUA_TFUNCTION);
	auto func = clvalue(luaA_toobject(L, 1));
	lua_pushboolean(L, functionMarker->isOurClosure(func));
	return 1;
}

int coal_setourclosure(lua_State* L)
{
	expectLuaFunction(L, 1);
	auto func = clvalue(luaA_toobject(L, 1));
	functionMarker->setOurProto(func->l.p);
	return 0;
}

int coal_setsafeenv(lua_State* L)
{
	TValue* object = index2addr(L, 1);
	Table* env = nullptr;

	switch (ttype(object))
	{
	case LUA_TTABLE:
		env = hvalue(object);
		break;
	case LUA_TFUNCTION:
		env = clvalue(object)->env;
		if (!env)
			env = L->gt;
		break;
	case LUA_TTHREAD:
		env = thvalue(object)->gt;
		break;
	case LUA_TBOOLEAN:
		// one arg mode
		L->gt->safeenv = luaL_checkboolean(L, 1);
		return 0;
	default:
		luaL_typeerrorL(L, 1, "table | function | thread | bool");
	}
	
	env->safeenv = luaL_checkboolean(L, 2);
	return 0;
}


int coal_getstack(lua_State* L)
{
	int level = luaL_checkinteger(L, 1);
	
	auto callInfo = getcallinfo(L, level);
	if (!callInfo)
		luaL_argerrorL(L, 1, "level out of range");

	if (clvalue(callInfo->func)->isC)
		luaL_errorL(L, "stack points to a C closure, Lua function expected");

	if (lua_isnumber(L, 2))
	{
		int index = lua_tointegerx(L, 2);
		if (index < 1)
			luaL_errorL(L, "stack index starts at 1");

		if (callInfo->top - callInfo->base < index)
			luaL_errorL(L, "stack index out of range");

		luaA_pushobject(L, callInfo->base + index - 1);
	}
	else
	{
		lua_createtable(L, 0, 0);

		int index = 1;
		for (StkId v = callInfo->base; v < callInfo->top; v++)
		{
			lua_pushinteger(L, index++);
			luaA_pushobject(L, v);
			lua_settable(L, -3);
		}
	}

	return 1;
}

int coal_setstack(lua_State* L)
{
	int level = luaL_checkinteger(L, 1);
	int index = luaL_checkinteger(L, 2);

	auto callInfo = getcallinfo(L, level);
	if (!callInfo)
		luaL_argerrorL(L, 1, "level out of range");

	if (clvalue(callInfo->func)->isC)
		luaL_errorL(L, "stack points to a C closure, Lua function expected");

	if (index < 1)
		luaL_errorL(L, "stack index starts at 1");

	if (callInfo->top - callInfo->base < index)
		luaL_errorL(L, "stack index out of range");

	TValue* target = callInfo->base + index - 1;
	TValue* changeTo = index2addr(L, 3);

	if (luaApiRuntimeState.getLuaSettings().setstack_block_different_type)
	{
		if (ttype(target) != ttype(changeTo))
			luaL_errorL(L, "cannot change value to a different type");
	}
	
	setobj(target, changeTo);

	return 0;
}

int coal_getmaxstacksize(lua_State* L)
{
	lua_pushinteger(L, L->stacksize);
	lua_pushinteger(L, L->size_ci);
	return 2;
}

int coal_getstacksize(lua_State* L)
{
	lua_pushinteger(L, (int)(L->top - L->stack));
	lua_pushinteger(L, (int)(L->end_ci - L->base_ci));
	return 2;
}

int coal_setupvalue(lua_State* L)
{
	Closure* func = getclosure(L, 1, true);
	if (luaApiRuntimeState.getLuaSettings().setupvalue_block_cclosure)
		expectLuaFunction(L, *func);

	int index = luaL_checkinteger(L, 2);
	luaL_checktype(L, 2, LUA_TNUMBER);
	luaL_checkany(L, 3);

	if (index < 1)
		luaL_errorL(L, "upvalue index starts at 1");

	if (index > func->nupvalues)
		luaL_errorL(L, "upvalue index is out of range");

	auto changeTo = index2addr(L, 3);

	TValue* value = getupvalue(func, index - 1);
	setobj(value, changeTo);

	return 0;
}

int coal_getupvalues(lua_State* L)
{
	Closure* func = getclosure(L, 1, true);

	if (func->isC && luaApiRuntimeState.getLuaSettings().getupvalue_block_cclosure)
	{
		lua_pushnil(L);
		return 1;
	}

	auto sizeups = func->nupvalues;
	lua_createtable(L, sizeups, 0);

	for (int index = 0; index < sizeups; index++)
	{
		lua_pushinteger(L, index + 1);

		TValue* value = getupvalue(func, index);

		luaA_pushobject(L, value);
		lua_settable(L, -3);
	}

	return 1;
}

int coal_getupvalue(lua_State* L)
{
	Closure* func = getclosure(L, 1, true);
	int index = luaL_checkinteger(L, 2);

	if (luaApiRuntimeState.getLuaSettings().getupvalue_block_cclosure && func->isC)
		lua_pushnil(L);
	else
	{
		if (index < 1)
			luaL_errorL(L, "upvalue index starts at 1");
		if (index - 1 >= func->nupvalues)
			luaL_errorL(L, "upvalue index is out of range");
		
		TValue* value = getupvalue(func, index - 1);

		luaA_pushobject(L, value);
	}

	return 1;
}

void cloneConstant(lua_State* L, TValue* constants, int index)
{
	switch (constants[index].tt)
	{
	case LUA_TNIL:
		lua_pushnil(L);
		break;
	case LUA_TBOOLEAN:
		lua_pushboolean(L, constants[index].value.b);
		break;
	case LUA_TNUMBER:
		lua_pushnumber(L, constants[index].value.n);
		break;
	case LUA_TSTRING:
	{
		auto& string = constants[index].value.gc->ts;
		lua_pushlstring(L, string.data, string.len);
		break;
	}
	case LUA_TVECTOR:
	{
		lua_pushvector(L,
			constants[index].value.v[0],
			constants[index].value.v[1],
			constants[index].value.v[2]
		);
		break;
	}
	case LUA_TFUNCTION:
	{
		if (luaApiRuntimeState.getLuaSettings().getconstant_block_functions)
		{
			lua_pushlightuserdatatagged(L, nullptr);
			break;
		}

		[[fallthrough]];
	}
	case LUA_TTABLE:
	case LUA_TUSERDATA:
		luaA_pushobject(L, &constants[index]);
		break;
	default:
		lua_pushnil(L);
		break;
	}
}

int coal_getconstants(lua_State* L)
{
	Closure* func = getclosure(L, 1, true);
	expectLuaFunction(L, *func);

	auto sizek = func->l.p->sizek;
	lua_createtable(L, sizek, 0);

	for (int index = 0; index < sizek; index++)
	{
		lua_pushinteger(L, index + 1);
		cloneConstant(L, func->l.p->k, index);
		lua_settable(L, -3);
	}

	return 1;
}

int coal_getconstant(lua_State* L)
{
	Closure* func = getclosure(L, 1, true);
	expectLuaFunction(L, *func);

	auto index = luaL_checkinteger(L, 2);

	if (index < 1)
		luaL_errorL(L, "constant index starts at 1");
	if (index >= func->l.p->sizek)
		luaL_errorL(L, "constant index is out of range");

	cloneConstant(L, func->l.p->k, index - 1);
	return 1;
}

int coal_setconstant(lua_State* L)
{
	Closure* func = getclosure(L, 1, true);
	expectLuaFunction(L, *func);

	auto index = luaL_checkinteger(L, 2);

	if (index < 1)
		luaL_errorL(L, "constant index starts at 1");
	if (index >= func->l.p->sizek)
		luaL_errorL(L, "constant index is out of range");

	auto target = &func->l.p->k[index - 1];
	auto changeTo = index2addr(L, 3);

	setobj(target, changeTo);

	return 0;
}

int coal_getprotos(lua_State* L)
{
	Closure* func = getclosure(L, 1, true);
	expectLuaFunction(L, *func);

	auto sizep = func->l.p->sizep;
	lua_createtable(L, sizep, 0);

	for (int index = 0; index < sizep; index++)
	{
		// lua index style
		lua_pushinteger(L, index + 1);

		Closure* cl = luaF_newLclosure(L, 0, func->env, *(func->l.p->p) + index);
		lua_pushclosure(L, cl);

		lua_settable(L, -3);
	}

	return 1;
}

int coal_getproto(lua_State* L)
{
	Closure* func = getclosure(L, 1, true);
	expectLuaFunction(L, *func);

	// lua index style
	auto index = luaL_checkinteger(L, 2);

	if (index < 1)
		luaL_errorL(L, "proto index starts at 1");
	if (index >= func->l.p->sizep)
		luaL_errorL(L, "proto index is out of range");

	Closure* cl = luaF_newLclosure(L, 0, func->env, *(func->l.p->p) + index - 1);
	lua_pushclosure(L, cl);

	return 1;
}

// TODO: ignores possible upvalue disbalance
int coal_setproto(lua_State* L)
{
	Closure* func = getclosure(L, 1, true);
	expectLuaFunction(L, *func);

	// lua index style
	auto index = luaL_checkinteger(L, 2);

	if (index < 1)
		luaL_errorL(L, "proto index starts at 1");
	if (index >= func->l.p->sizep)
		luaL_errorL(L, "proto index is out of range");

	expectLuaFunction(L, 3);
	auto hook = clvalue(luaA_toobject(L, 1));

	func->l.p->p[index - 1] = hook->l.p;
	return 0;
}

int coal_getprotoinfo(lua_State* L)
{
	Closure* func = getclosure(L, 1, true);
	expectLuaFunction(L, *func);
	int results = 0;

	Proto* proto = func->l.p;

	const char* options = luaL_checklstring(L, 2);
	for (const char* it = options; *it; it++)
	{
		switch (*it)
		{
		case 'p':
			lua_pushinteger(L, proto->sizep);
			results++;
			break;
		case 'u':
			lua_pushinteger(L, proto->nups);
			results++;
			break;
		case 'k':
			lua_pushinteger(L, proto->sizek);
			results++;
			break;
		case 'b':
			lua_pushinteger(L, proto->bytecodeid);
			results++;
			break;
		case 's':
			lua_pushinteger(L, proto->maxstacksize);
			results++;
			break;
		default:
			luaL_argerrorL(L, 2, "invalid option");
		}
	}

	return results;
}

int coal_getinfo(lua_State* L)
{
	lua_Debug ar;
	int argsBase;
	lua_State* L1 = getthread(L, argsBase);

	CallInfo* call = nullptr;
	Closure* func = nullptr;

	func = lua_toclosure(L1, argsBase + 1);
	if (!func)
	{
		call = getcallinfo(L1, argsBase + 1, true);
		func = clvalue(call->func);
	}

	const char* options = luaL_optlstring(L, argsBase + 2, "flSu");

	lua_createtable(L, 0, 4);

	if (strchr(options, 'S'))
	{
		if (func->isC)
		{
			ar.source = "=[C]";
			ar.what = "C";
			ar.linedefined = -1;
			ar.short_src = "[C]";
		}
		else
		{
			TString* source = func->l.p->source;
			ar.source = getstr(source);
			ar.what = "Lua";
			ar.linedefined = func->l.p->linedefined;
			ar.short_src = luaO_chunkid(ar.ssbuf, sizeof(ar.ssbuf), getstr(source), source->len);
		}

		lua_pushstring(L, ar.source);
		lua_setfield(L, -2, "source");

		lua_pushstring(L, ar.short_src);
		lua_setfield(L, -2, "short_src");

		lua_pushinteger(L, ar.linedefined);
		lua_setfield(L, -2, "linedefined");

		lua_pushstring(L, ar.what);
		lua_setfield(L, -2, "what");
	}

	if (strchr(options, 'l'))
	{
		int currentline = getcurrentline(func, call);
		lua_pushinteger(L, currentline);
		lua_setfield(L, -2, "currentline");
	}

	if (strchr(options, 'u'))
	{
		lua_pushinteger(L, func->nupvalues);
		lua_setfield(L, -2, "nups");
	}

	if (strchr(options, 'f'))
	{
		lua_pushclosure(L, func);
		lua_setfield(L, -2, "func");
	}

	return 1;
}