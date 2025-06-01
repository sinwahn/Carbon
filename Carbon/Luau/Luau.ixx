export module Luau;

import SharedAddresses;
export import LuauTypes;

import <cstdint>;
import <string>;
import <iostream>;
import <stdarg.h>;

export
{
	TValue* luaO_nilobject() {
		return luaApiAddresses.luaO_nilobject;
	}

	int lua_getinfo(lua_State* L, int level, const char* what, lua_Debug* ar) {
		return luaApiAddresses.lua_getinfo(L, level, what, ar);
	}

	[[noreturn]] void luaL_typeerrorL(lua_State* L, int narg, const char* tname) {
		luaApiAddresses.luaL_typeerrorL(L, narg, tname);
	}

	const char* luaL_typename(lua_State* L, int idx) {
		return luaApiAddresses.luaL_typename(L, idx);
	}

	void lua_pushlstring(lua_State* L, const char* s, size_t len) {
		luaApiAddresses.lua_pushlstring(L, s, len);
	}

	void lua_pushvalue(lua_State* L, int idx) {
		luaApiAddresses.lua_pushvalue(L, idx);
	}

	const char* lua_tolstring(lua_State* L, int idx, size_t* len) {
		return luaApiAddresses.lua_tolstring(L, idx, len);
	}

	void lua_settable(lua_State* L, int idx) {
		luaApiAddresses.lua_settable(L, idx);
	}

	int lua_getfield(lua_State* L, int idx, const char* k) {
		return luaApiAddresses.lua_getfield(L, idx, k);
	}

	void lua_setfield(lua_State* L, int idx, const char* k) {
		luaApiAddresses.lua_setfield(L, idx, k);
	}

	void lua_createtable(lua_State* L, int narr = 0, int nrec = 0) {
		luaApiAddresses.lua_createtable(L, narr, nrec);
	}

	Table* luaH_clone(lua_State* L, Table* tt) {
		return luaApiAddresses.luaH_clone(L, tt);
	}

	int lua_next(lua_State* L, int idx) {
		return luaApiAddresses.lua_next(L, idx);
	}

	int lua_rawget(lua_State* L, int idx) {
		return luaApiAddresses.lua_rawget(L, idx);
	}

	void lua_rawset(lua_State* L, int idx) {
		luaApiAddresses.lua_rawset(L, idx);
	}

	int lua_setmetatable(lua_State* L, int objindex) {
		return luaApiAddresses.lua_setmetatable(L, objindex);
	}

	int lua_getmetatable(lua_State* L, int objindex) {
		return luaApiAddresses.lua_getmetatable(L, objindex);
	}

	void lua_pushcclosurek(lua_State* L, lua_CFunction fn, const char* debugname, int nup, lua_Continuation cont) {
		luaApiAddresses.lua_pushcclosurek(L, fn, debugname, nup, cont);
	}

	Closure* luaF_newLclosure(lua_State* L, int nelems, Table* e, Proto* p) {
		return luaApiAddresses.luaF_newLclosure(L, nelems, e, p);
	}

	void luaD_call(lua_State* L, StkId func, int nresults) {
		luaApiAddresses.luaD_call(L, func, nresults);
	}

	Proto* luaF_newproto(lua_State* L) {
		return luaApiAddresses.luaF_newproto(L);
	}

	void* lua_newuserdatatagged(lua_State* L, size_t sz, int tag = 0) {
		return luaApiAddresses.lua_newuserdatatagged(L, sz, tag);
	}

	const TValue* luaH_get(Table* t, const TValue* key) {
		return luaApiAddresses.luaH_get(t, key);
	}

	lua_State* lua_newthread(lua_State* L) {
		return luaApiAddresses.lua_newthread(L);
	}

	int lua_type(lua_State* L, int idx);

	template <typename T>
	concept GCObjectOrTValue = std::same_as<T, GCObject> || std::same_as<T, TValue>;

	template <GCObjectOrTValue T> lua_Type ttype(const T* o) { return (lua_Type)o->tt; }

	template <GCObjectOrTValue T> bool ttisnil(const T* o) { return ttype(o) == LUA_TNIL; }
	template <GCObjectOrTValue T> bool ttisnumber(const T* o) { return ttype(o) == LUA_TNUMBER; }
	template <GCObjectOrTValue T> bool ttisstring(const T* o) { return ttype(o) == LUA_TSTRING; }
	template <GCObjectOrTValue T> bool ttistable(const T* o) { return ttype(o) == LUA_TTABLE; }
	template <GCObjectOrTValue T> bool ttisfunction(const T* o) { return ttype(o) == LUA_TFUNCTION; }
	template <GCObjectOrTValue T> bool ttisboolean(const T* o) { return ttype(o) == LUA_TBOOLEAN; }
	template <GCObjectOrTValue T> bool ttisuserdata(const T* o) { return ttype(o) == LUA_TUSERDATA; }
	template <GCObjectOrTValue T> bool ttisthread(const T* o) { return ttype(o) == LUA_TTHREAD; }
	template <GCObjectOrTValue T> bool ttisbuffer(const T* o) { return ttype(o) == LUA_TBUFFER; }
	template <GCObjectOrTValue T> bool ttislightuserdata(const T* o) { return ttype(o) == LUA_TLIGHTUSERDATA; }
	template <GCObjectOrTValue T> bool ttisvector(const T* o) { return ttype(o) == LUA_TVECTOR; }
	template <GCObjectOrTValue T> bool ttisupval(const T* o) { return ttype(o) == LUA_TUPVAL; }

	template <GCObjectOrTValue T> GCObject* gcvalue(const T* o) { return o->value.gc; }
	template <GCObjectOrTValue T> void* pvalue(const T* o) { return o->value.p; }
	template <GCObjectOrTValue T> lua_Number nvalue(const T* o) { return o->value.n; }
	template <GCObjectOrTValue T> float* vvalue(const T* o) { return const_cast<float*>(o->value.v); }
	template <GCObjectOrTValue T> TString* tsvalue(const T* o) { return &(o->value.gc->ts); }
	template <GCObjectOrTValue T> Udata* uvalue(const T* o) { return &(o->value.gc->u); }
	template <GCObjectOrTValue T> Closure* clvalue(const T* o) { return &(o->value.gc->cl); }
	template <GCObjectOrTValue T> Table* hvalue(const T* o) { return &(o->value.gc->h); }
	template <GCObjectOrTValue T> int bvalue(const T* o) { return o->value.b; }
	template <GCObjectOrTValue T> lua_State* thvalue(const T* o) { return &(o->value.gc->th); }
	template <GCObjectOrTValue T> Buffer* bufvalue(const T* o) { return &(o->value.gc->buf); }
	template <GCObjectOrTValue T> UpVal* upvalue(const T* o) { return &(o->value.gc->uv); }

	const char* getstr(const TString* s) { return s->data; }
	const char* svalue(const TValue* o) { return getstr(tsvalue(o)); }


	bool lua_isfunction(lua_State* L, int n) { return lua_type(L, (n)) == LUA_TFUNCTION; }
	bool lua_istable(lua_State* L, int n) { return lua_type(L, (n)) == LUA_TTABLE; }
	bool lua_islightuserdata(lua_State* L, int n) { return lua_type(L, (n)) == LUA_TLIGHTUSERDATA; }
	bool lua_isnil(lua_State* L, int n) { return lua_type(L, (n)) == LUA_TNIL; }
	bool lua_isboolean(lua_State* L, int n) { return lua_type(L, (n)) == LUA_TBOOLEAN; }
	bool lua_isvector(lua_State* L, int n) { return lua_type(L, (n)) == LUA_TVECTOR; }
	bool lua_isthread(lua_State* L, int n) { return lua_type(L, (n)) == LUA_TTHREAD; }
	bool lua_isbuffer(lua_State* L, int n) { return lua_type(L, (n)) == LUA_TBUFFER; }
	bool lua_isnone(lua_State* L, int n) { return lua_type(L, (n)) == LUA_TNONE; }
	bool lua_isnoneornil(lua_State* L, int n) { return lua_type(L, (n)) <= LUA_TNIL; }

	bool iscfunction(const TValue* o) { return ttype(o) == LUA_TFUNCTION && clvalue(o)->isC; }
	bool isluafunction(const TValue* o) { return ttype(o) == LUA_TFUNCTION && !clvalue(o)->isC; }

	bool iscfunction(const Closure* o) { return o->isC; }
	bool isluafunction(const Closure* o) { return !o->isC; }

	Closure* curr_func(lua_State* L) { return clvalue(L->ci->func); }

	void luaL_errorL(lua_State* L, const char* fmt, ...);

	TValue* getupvalue(Closure* function, int index)
	{
		if (function->isC)
		{
			return &function->c.upvals[index];
		}
		else
		{
			TValue* up = &function->l.uprefs[index];
			return ttisupval(up) ? upvalue(up)->v : up;
		}
	}

	int lua_upvalueindex(int i)
	{
		return LUA_GLOBALSINDEX - i;
	}

	bool luai_veceq(const float* a, const float* b)
	{
	#if LUA_VECTOR_SIZE == 4
		return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
	#else
		return a[0] == b[0] && a[1] == b[1] && a[2] == b[2];
	#endif
	}

	const char* currfuncname(lua_State* L)
	{
		Closure* cl = L->ci > L->base_ci ? curr_func(L) : nullptr;
		const char* debugname = cl && cl->isC ? cl->c.debugname + 0 : nullptr;

		if (debugname && strcmp(debugname, "__namecall") == 0)
			return L->namecall ? getstr(L->namecall) : nullptr;
		else
			return debugname;
	}

	[[noreturn]] void luaL_argerrorL(lua_State* L, int narg, const char* extramsg)
	{
		const char* fname = currfuncname(L);

		if (fname)
			luaL_errorL(L, "invalid argument #%d to '%s' (%s)", narg, fname, extramsg);
		else
			luaL_errorL(L, "invalid argument #%d (%s)", narg, extramsg);
	}


	Table* getcurrenv(lua_State* L)
	{
		if (L->ci == L->base_ci) // no enclosing function?
			return L->gt;        // use global table as environment
		else
			return curr_func(L)->env;
	}

	void sethvalue(TValue* obj, Table* x);

	TValue* pseudo2addr(lua_State* L, int idx)
	{
		switch (idx)
		{ // pseudo-indices
		case LUA_REGISTRYINDEX:
			return &L->global->registry;
		case LUA_ENVIRONINDEX:
		{
			sethvalue(&L->global->pseudotemp, getcurrenv(L));
			return &L->global->pseudotemp;
		}
		case LUA_GLOBALSINDEX:
		{
			sethvalue(&L->global->pseudotemp, L->gt);
			return &L->global->pseudotemp;
		}
		default:
		{
			Closure* func = curr_func(L);
			idx = LUA_GLOBALSINDEX - idx;
			return (idx <= func->nupvalues) ? &func->c.upvals[idx - 1] : (TValue*)&luaO_nilobject;
		}
		}
	}

	TValue* index2addr(lua_State* L, int idx)
	{
		if (idx > 0)
		{
			TValue* o = L->base + (idx - 1);
			if (o >= L->top)
				return luaO_nilobject();
			else
				return o;
		}
		else if (idx > LUA_REGISTRYINDEX)
		{
			return L->top + idx;
		}
		else
		{
			return pseudo2addr(L, idx);
		}
	}

	const char* const luaT_typenames[] = {
		// ORDER TYPE
		"nil",
		"boolean",

		"userdata",
		"number",
		"vector",

		"string",

		"table",
		"function",
		"userdata",
		"thread",
		"buffer",
	};

	const char* lua_typename(lua_State* L, int t)
	{
		return (t == LUA_TNONE) ? "no value" : luaT_typenames[t];
	}

	void tag_error(lua_State* L, int narg, int tag)
	{
		luaL_typeerrorL(L, narg, lua_typename(L, tag));
	}

	int lua_type(lua_State* L, int idx)
	{
		StkId o = index2addr(L, idx);
		return (o == luaO_nilobject()) ? LUA_TNONE : ttype(o);
	}

	void luaL_checktype(lua_State* L, int narg, lua_Type t)
	{
		if (lua_type(L, narg) != t)
			tag_error(L, narg, t);
	}

	void luaL_checkany(lua_State* L, int narg)
	{
		if (lua_type(L, narg) == LUA_TNONE)
			luaL_errorL(L, "missing argument #%d", narg);
	}

	void lua_setglobal(lua_State* L, const char* name)
	{
		lua_setfield(L, LUA_GLOBALSINDEX, name);
	}

	void lua_getglobal(lua_State* L, const char* name)
	{
		lua_getfield(L, LUA_GLOBALSINDEX, name);
	}

	#define cast_byte(i) (uint8_t(i))
	#define cast_num(i) (double(i))
	#define cast_int(i) (int(i))

	void setnilvalue(TValue* obj)
	{
		obj->tt = LUA_TNIL;
	}

	void setbvalue(TValue* obj, bool x)
	{
		obj->value.b = x;
		obj->tt = LUA_TBOOLEAN;
	}

	void setpvalue(TValue* obj, void* x, int tag)
	{
		obj->value.p = x;
		obj->extra[0] = tag;
		obj->tt = LUA_TLIGHTUSERDATA;
	}

	void setnvalue(TValue* obj, double x)
	{
		obj->value.n = x;
		obj->tt = LUA_TNUMBER;
	}

	void setsvalue(TValue* obj, TString* x)
	{
		obj->value.gc = (GCObject*)x;
		obj->tt = LUA_TSTRING;
	}

	void setuvalue(TValue* obj, UpVal* x)
	{
		obj->value.gc = (GCObject*)x;
		obj->tt = LUA_TUSERDATA;
	}

	void setvvalue(TValue* obj, float x, float y, float z)
	{
		float* vec = obj->value.v;
		vec[0] = (x);
		vec[1] = (y);
		vec[2] = (z);
		obj->tt = LUA_TVECTOR;
	}

	void sethvalue(TValue* obj, Table* x)
	{
		obj->value.gc = (GCObject*)x;
		obj->tt = LUA_TTABLE;
	}

	void setclvalue(TValue* obj, Closure* x)
	{
		obj->value.gc = (GCObject*)x;
		obj->tt = LUA_TFUNCTION;
	}

	void setuvalue(TValue* obj, Udata* x)
	{
		obj->value.gc = (GCObject*)x;
		obj->tt = LUA_TUSERDATA;
	}

	void setthvalue(TValue* obj, lua_State* x)
	{
		obj->value.gc = (GCObject*)x;
		obj->tt = LUA_TTHREAD;
	}

	void setbufvalue(TValue* obj, Buffer* x)
	{
		obj->value.gc = (GCObject*)x;
		obj->tt = LUA_TBUFFER;
	}

	void setobj(TValue* obj1, const TValue* obj2)
	{
		*obj1 = *obj2;
	}

	void setobjfull(TValue* obj1, const TValue* obj2)
	{
		*obj1 = *obj2;
		obj1->tt = obj2->tt;
	}

	void lua_insert(lua_State* L, int idx)
	{
		StkId p = index2addr(L, idx);
		for (StkId q = L->top; q > p; q--)
			setobj(q, q - 1);
		setobj(p, L->top);
	}

	void lua_settop(lua_State* L, int idx)
	{
		if (idx >= 0)
		{
			while (L->top < L->base + idx)
				setnilvalue(L->top++);
			L->top = L->base + idx;
		}
		else
		{
			L->top += idx + 1; // `subtract' index (index is negative)
		}
	}

	void lua_pop(lua_State* L, int n)
	{
		lua_settop(L, -(n)-1);
	}

	void incr_top(lua_State* L)
	{
		L->top++;
	}

	int luaO_str2d(const char* s, double* result)
	{
		char* endptr;
		*result = strtod(s, &endptr);
		if (endptr == s)
			return 0;                         // conversion failed
		if (*endptr == 'x' || *endptr == 'X') // maybe an hexadecimal constant?
			*result = cast_num(strtoul(s, &endptr, 16));
		if (*endptr == '\0')
			return 1; // most common case
		while (isspace(unsigned char(*endptr)))
			endptr++;
		if (*endptr != '\0')
			return 0; // invalid trailing characters?
		return 1;
	}

	const TValue* luaV_tonumber(const TValue* obj, TValue* n)
	{
		double num;
		if (ttisnumber(obj))
			return obj;
		if (ttisstring(obj) && luaO_str2d(svalue(obj), &num))
		{
			setnvalue(n, num);
			return n;
		}
		else
			return nullptr;
	}

	#define tonumber(o, n) (ttype(o) == LUA_TNUMBER || (((o) = luaV_tonumber(o, n)) != NULL))

	double lua_tonumberx(lua_State* L, int idx, bool* isnum = nullptr)
	{
		TValue n;
		const TValue* o = index2addr(L, idx);
		if (tonumber(o, &n))
		{
			if (isnum)
				*isnum = 1;
			return nvalue(o);
		}
		else
		{
			if (isnum)
				*isnum = 0;
			return 0;
		}
	}

	int lua_tointegerx(lua_State* L, int idx, bool* isnum = nullptr)
	{
		TValue n;
		const TValue* o = index2addr(L, idx);
		if (tonumber(o, &n))
		{
			int res;
			double num = nvalue(o);
			res = (int)num;
			if (isnum)
				*isnum = 1;
			return res;
		}
		else
		{
			if (isnum)
				*isnum = 0;
			return 0;
		}
	}

	unsigned lua_tounsignedx(lua_State* L, int idx, bool* isnum = nullptr)
	{
		TValue n;
		const TValue* o = index2addr(L, idx);
		if (tonumber(o, &n))
		{
			unsigned res;
			double num = nvalue(o);
			res = (unsigned)(long long)(num);
			if (isnum)
				*isnum = 1;
			return res;
		}
		else
		{
			if (isnum)
				*isnum = 0;
			return 0;
		}
	}

	const TValue* luaA_toobject(lua_State* L, int idx)
	{
		StkId p = index2addr(L, idx);
		return (p == luaO_nilobject()) ? nullptr : p;
	}

	void* lua_touserdata(lua_State* L, int idx)
	{
		StkId o = index2addr(L, idx);
		if (ttisuserdata(o))
			return uvalue(o)->data;
		else if (ttislightuserdata(o))
			return pvalue(o);
		else
			return nullptr;
	}

	lua_State* lua_tothread(lua_State* L, int idx)
	{
		StkId o = index2addr(L, idx);
		return (!ttisthread(o)) ? nullptr : thvalue(o);
	}

	Table* lua_totable(lua_State* L, int idx)
	{
		StkId o = index2addr(L, idx);
		return (!ttistable(o)) ? nullptr : hvalue(o);
	}

	Closure* lua_toclosure(lua_State* L, int idx)
	{
		StkId o = index2addr(L, idx);
		return (!ttisfunction(o)) ? nullptr : clvalue(o);
	}

	TString* lua_torawstring(lua_State* L, int idx)
	{
		StkId o = index2addr(L, idx);
		return (!ttisstring(o)) ? nullptr : tsvalue(o);
	}

	bool lua_toboolean(lua_State* L, int idx)
	{
		const TValue* o = index2addr(L, idx);
		return !(ttisnil(o) || (ttisboolean(o) && o->value.b == 0));
	}

	void luaA_pushobject(lua_State* L, const TValue* o)
	{
		setobj(L->top, o);
		incr_top(L);
	}
	void lua_pushnil(lua_State* L)
	{
		setnilvalue(L->top);
		incr_top(L);
	}

	void lua_pushboolean(lua_State* L, int b)
	{
		setbvalue(L->top, (b != 0)); // ensure that true is 1
		incr_top(L);
	}

	void lua_pushlightuserdatatagged(lua_State* L, void* p, int tag = 0)
	{
		setpvalue(L->top, p, tag);
		incr_top(L);
	}

	void lua_pushnumber(lua_State* L, double n)
	{
		setnvalue(L->top, n);
		incr_top(L);
	}

	void lua_pushinteger(lua_State* L, int n)
	{
		setnvalue(L->top, cast_num(n));
		incr_top(L);
	}

	void lua_pushunsigned(lua_State* L, unsigned u)
	{
		setnvalue(L->top, cast_num(u));
		incr_top(L);
	}

	void lua_pushvector(lua_State* L, float x, float y, float z)
	{
		setvvalue(L->top, x, y, z);
		incr_top(L);
	}

	void lua_pushstring(lua_State* L, const char* s)
	{
		if (s == nullptr)
			lua_pushnil(L);
		else
			lua_pushlstring(L, s, strlen(s));
	}

	void lua_pushrawstring(lua_State* L, TString* value)
	{
		setsvalue(L->top, value);
		incr_top(L);
	}

	void lua_pushrawtable(lua_State* L, Table* value)
	{
		sethvalue(L->top, value);
		incr_top(L);
	}

	void lua_pushclosure(lua_State* L, Closure* cl)
	{
		setclvalue(L->top, cl);
		incr_top(L);
	}

	void lua_pushrawuserdata(lua_State* L, Udata* u)
	{
		setuvalue(L->top, u);
		incr_top(L);
	}

	void lua_pushrawthread(lua_State* L, lua_State* thread)
	{
		setthvalue(L->top, thread);
		incr_top(L);
	}

	void lua_pushrawbuffer(lua_State* L, Buffer* buffer)
	{
		setbufvalue(L->top, buffer);
		incr_top(L);
	}

	void lua_pushrawgcobject(lua_State* L, GCObject* x)
	{
		L->top->value.gc = (GCObject*)x;
		L->top->tt = x->gch.tt;
		incr_top(L);
	}

	Closure* luaL_checkfunction(lua_State* L, int narg)
	{
		Closure* func = lua_toclosure(L, narg);
		if (!func)
			tag_error(L, narg, LUA_TFUNCTION);
		return func;
	}

	Table* luaL_checktable(lua_State* L, int narg)
	{
		Table* table = lua_totable(L, narg);
		if (!table)
			tag_error(L, narg, LUA_TTABLE);
		return table;
	}

	int luaL_checkinteger(lua_State* L, int narg)
	{
		bool isnum;
		int d = lua_tointegerx(L, narg, &isnum);
		if (!isnum)
			tag_error(L, narg, LUA_TNUMBER);
		return d;
	}

	bool luaL_checkboolean(lua_State* L, int narg) {
		// This checks specifically for boolean values, ignoring
		// all other truthy/falsy values. If the desired result
		// is true if value is present then lua_toboolean should
		// directly be used instead.
		if (!lua_isboolean(L, narg))
			tag_error(L, narg, LUA_TBOOLEAN);
		return lua_toboolean(L, narg);
	}

	bool luaL_optboolean(lua_State* L, int narg, bool def)
	{
		if (lua_isnoneornil(L, narg))
			return def;
		return luaL_checkboolean(L, narg);
	}

	const char* luaL_checklstring(lua_State* L, int narg, size_t* len = nullptr)
	{
		const char* s = lua_tolstring(L, narg, len);
		if (!s)
			tag_error(L, narg, LUA_TSTRING);
		return s;
	}

	const char* luaL_optlstring(lua_State* L, int narg, const char* def, size_t* len = nullptr)
	{
		if (lua_isnoneornil(L, narg))
		{
			if (len)
				*len = (def ? strlen(def) : 0);
			return def;
		}
		else
			return luaL_checklstring(L, narg, len);
	}

	int luaL_optinteger(lua_State* L, int narg, int def)
	{
		if (lua_isnoneornil(L, narg))
			return def;

		return luaL_checkinteger(L, narg);
	}

	bool lua_iscfunction(lua_State* L, int idx)
	{
		StkId o = index2addr(L, idx);
		return ttype(o) == LUA_TFUNCTION && clvalue(o)->isC;
	}

	bool lua_isluafunction(lua_State* L, int idx)
	{
		StkId o = index2addr(L, idx);
		return ttype(o) == LUA_TFUNCTION && !clvalue(o)->isC;
	}

	bool lua_isnumber(lua_State* L, int idx)
	{
		TValue n;
		const TValue* o = index2addr(L, idx);
		return tonumber(o, &n);
	}

	bool lua_isstring(lua_State* L, int idx)
	{
		int t = lua_type(L, idx);
		return t == LUA_TSTRING || t == LUA_TNUMBER;
	}

	void lua_pushcclosure(lua_State* L, lua_CFunction fn, const char* debugname = nullptr, int nup = 0)
	{
		lua_pushcclosurek(L, fn, debugname, nup, nullptr);
	}

	int lua_gettop(lua_State* L)
	{
		return cast_int(L->top - L->base);
	}

	void adjustresults(lua_State* L, int nres)
	{
		if (nres == LUA_MULTRET && L->top >= L->ci->top)
			L->ci->top = L->top;
	}

	void lua_call(lua_State* L, int nargs, int nresults)
	{
		StkId func;
		func = L->top - (nargs + 1);
		luaD_call(L, func, nresults);
		adjustresults(L, nresults);
	}


	/*
	** Execute a protected call.
	*/
	#define savestack(L, p) ((char*)(p) - (char*)L->stack)
	struct CallS
	{ // data to `f_call'
		StkId func;
		int nresults;
	};

	void f_call(lua_State* L, void* ud)
	{
		auto c = (CallS*)ud;
		luaD_call(L, c->func, c->nresults);
	}

	int lua_pcall(lua_State* L, int nargs, int nresults, int errfunc)
	{
		ptrdiff_t func = 0;
		if (errfunc != 0)
		{
			StkId o = index2addr(L, errfunc);
			func = savestack(L, o);
		}
		struct CallS c;
		c.func = L->top - (nargs + 1); // function to be called
		c.nresults = nresults;

		int status = luaApiAddresses.luaD_pcall(L, f_call, &c, savestack(L, c.func), func);

		adjustresults(L, nresults);
		return status;
	}

	CallInfo* getcallinfo(lua_State* L, int level)
	{
		if (unsigned(level) < unsigned(L->ci - L->base_ci))
			return L->ci - level;

		return nullptr;
	}


	CallInfo* getcallinfo(lua_State* L, int idx, bool opt)
	{
		int level = opt ? luaL_optinteger(L, idx, 1) : luaL_checkinteger(L, idx);
		if (level < 0)
			luaL_argerrorL(L, idx, "level must be non-negative");

		return getcallinfo(L, level);
	}

	Closure* getclosure(lua_State* L, int idx, bool opt)
	{
		StkId o = index2addr(L, idx);
		if (ttype(o) == LUA_TFUNCTION)
			return clvalue(o);

		if (auto callInfo = getcallinfo(L, idx, opt))
			return clvalue(callInfo->func);
	
		luaL_argerrorL(L, idx, "invalid level");
	}

	lua_State* getthread(lua_State* L, int& argsBase)
	{
		if (lua_isthread(L, 1))
		{
			argsBase = 1;
			return lua_tothread(L, 1);
		}
		else
		{
			argsBase = 0;
			return L;
		}
	}

	// thread status; 0 is OK
	enum lua_Status
	{
		LUA_OK = 0,
		LUA_YIELD,
		LUA_ERRRUN,
		LUA_ERRSYNTAX, // legacy error code, preserved for compatibility
		LUA_ERRMEM,
		LUA_ERRERR,
		LUA_BREAK, // yielded for a debug breakpoint
	};

	class lua_exception : public std::exception
	{
	public:
		lua_exception(lua_State* L, int status)
			: L(L)
			, status(status)
		{
		}

		const char* what() const throw() override
		{
			// LUA_ERRRUN passes error object on the stack
			if (status == LUA_ERRRUN)
				if (const char* str = lua_tolstring(L, -1, nullptr))
					return str;

			switch (status)
			{
			case LUA_ERRRUN:
				return "lua_exception: runtime error";
			case LUA_ERRSYNTAX:
				return "lua_exception: syntax error";
			case LUA_ERRMEM:
				return "lua_exception: " "not enough memory";
			case LUA_ERRERR:
				return "lua_exception: " "error in error handling";
			default:
				return "lua_exception: unexpected exception status";
			}
		}

		int getStatus() const
		{
			return status;
		}

		const lua_State* getThread() const
		{
			return L;
		}

	private:
		lua_State* L;
		int status;
	};

	[[noreturn]] void luaD_throw(lua_State* L, int errcode)
	{
		throw lua_exception(L, errcode);
	}

	#pragma warning( push )
	#pragma warning( disable : 4996) // This function or variable may be unsafe...
	const char* luaO_chunkid(char* buf, size_t buflen, const char* source, size_t srclen)
	{
		if (*source == '=')
		{
			if (srclen <= buflen)
				return source + 1;
			// truncate the part after =
			memcpy(buf, source + 1, buflen - 1);
			buf[buflen - 1] = '\0';
		}
		else if (*source == '@')
		{
			if (srclen <= buflen)
				return source + 1;
			// truncate the part after @
			memcpy(buf, "...", 3);
			memcpy(buf + 3, source + srclen - (buflen - 4), buflen - 4);
			buf[buflen - 1] = '\0';
		}
		else
		{                                         // buf = [string "string"]
			size_t len = strcspn(source, "\n\r"); // stop at first newline
			buflen -= sizeof("[string \"...\"]");
			if (len > buflen)
				len = buflen;
			strcpy(buf, "[string \"");
			if (source[len] != '\0')
			{ // must truncate?
				strncat(buf, source, len);
				strcat(buf, "...");
			}
			else
				strcat(buf, source);
			strcat(buf, "\"]");
		}
		return buf;
	}
	#pragma warning( pop ) 

	int getcurrentline(const Closure* func, const CallInfo* call)
	{
		if (func->isC)
			return -1;

		if (call)
		{
			auto p = clvalue(call->func)->l.p;
			if (!p->lineinfo)
			{
				return 0;
			}
			else
			{
				int pc = call->savedpc ? int(call->savedpc - p->code) - 1 : 0;
				return p->abslineinfo[pc >> p->linegaplog2] + p->lineinfo[pc];
			}
		}
		else
		{
			return func->l.p->linedefined;
		}
	}

	void luaL_where(lua_State* L, int level)
	{
		auto ci = getcallinfo(L, level);
		auto func = clvalue(ci->func);

		if (func->isC)
		{
			lua_pushstring(L, "");
			return;
		}

		char ssbuf[LUA_IDSIZE];
		TString* source = func->l.p->source;
		auto short_src = luaO_chunkid(ssbuf, sizeof(ssbuf), getstr(source), source->len);
		char result[LUA_BUFFERSIZE];
		snprintf(result, LUA_BUFFERSIZE, "%s:%d: ", short_src, getcurrentline(func, ci));
		lua_pushstring(L, result);
	}

	void luaL_errorL(lua_State* L, const char* fmt, ...)
	{
		luaL_where(L, 1);

		va_list args;
		va_start(args, fmt);
		char result[LUA_BUFFERSIZE];
		vsnprintf(result, sizeof(result), fmt, args);
		va_end(args);
		lua_pushstring(L, result);

		luaApiAddresses.lua_concat(L, 2);
		luaD_throw(L, LUA_ERRRUN);
	}

	using GCObjectVisitor = bool (*)(void* context, lua_Page* page, GCObject* gco);

	// returns true on jumpout
	template <bool singleItemSearch>
	inline bool luaM_visitpage(lua_Page* page, void* context, GCObjectVisitor visitor)
	{
		int blockCount = (page->pageSize - offsetof(lua_Page, data)) / page->blockSize;

		char* start = page->data + page->freeNext + page->blockSize;;
		char* end = page->data + blockCount * page->blockSize;
		int busyBlocks = page->busyBlocks;
		int blockSize = page->blockSize;

		for (char* pos = start; pos != end; pos += blockSize)
		{
			GCObject* gco = (GCObject*)pos;

			// skip memory blocks that are already freed
			if (gco->gch.tt == LUA_TNIL)
				continue;

			if (visitor(context, page, gco))
			{
				if (singleItemSearch)
					return true;
			}
		}

		return false;
	}

	template <bool singleItemSearch>
	inline void luaM_visitgco(lua_State* L, void* context, GCObjectVisitor visitor)
	{
		global_State* g = L->global;

		for (lua_Page* curr = g->allgcopages; curr;)
		{
			lua_Page* next = curr->listnext; // block visit might destroy the page
			if (luaM_visitpage<singleItemSearch>(curr, context, visitor))
				break;
			curr = next;
		}
	}

} // export