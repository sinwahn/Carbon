export module CarbonLuaApiLibs.gclib;

import <vector>;
import <optional>;
import <map>;

import Luau;
import FunctionMarker;
import Console;
import StringUtils;
import RiblixStructures;

int carbon_getgc(lua_State* L);
int carbon_filtergc(lua_State* L);

export const luaL_Reg gcLibrary[] = {
	{"getgc", carbon_getgc},
	{"filtergc", carbon_filtergc},
	{nullptr, nullptr},
};




int carbon_getgc(lua_State* L)
{
	bool includeTables = luaL_optboolean(L, 1, false);
	
	struct gcvisit
	{
		lua_State* L = nullptr;
		bool includeTables = false;
		uint32_t counter = 0;
	};
	
	gcvisit context { L, includeTables };

	lua_createtable(L, 2000, 0);

	lua_createtable(L, 0, 1);
	lua_pushstring(L, "__mode");
	lua_pushstring(L, "v");
	lua_rawset(L, -3);

	lua_setmetatable(L, -2);

	luaM_visitgco<false>(L, &context, [](void* context_, lua_Page* page, GCObject* gco) -> bool {
		gcvisit* context = (gcvisit*)context_;

		auto L = context->L;

		if (L->global->isdead(gco) || (!context->includeTables && gco->gch.tt == LUA_TTABLE))
			return false;
		
		switch (gco->gch.tt)
		{
		case LUA_TSTRING:
		case LUA_TTABLE:
		case LUA_TFUNCTION:
		case LUA_TUSERDATA:
		case LUA_TTHREAD:
		case LUA_TBUFFER:
			lua_pushnumber(L, ++context->counter);
			lua_pushrawgcobject(L, gco);
			lua_rawset(L, -3);
			break;
		}

		return false;
	});

	return 1;
}

struct TableFilter
{
	std::vector<TValue> keys;
	std::vector<TValue> values;
	std::vector<std::pair<TValue, TValue>> keyValuePairs;
	Table* metatable = nullptr;
};

struct FunctionFilter
{
	TString* name = nullptr;
	std::vector<TValue> constants;
	std::vector<TValue> upvalues;
	Proto* proto = nullptr;
	Table* environment = nullptr;
	TString* hash = nullptr;
	std::optional<bool> ignoreOur;
};

struct UserdataFilter
{
	Table* metatable = nullptr;
};

#define lightuserdatatag(o) (o)->extra[0]
bool rawequalbitOjb(const TValue* t1, const TValue* t2)
{
	if (ttype(t1) != ttype(t2))
		return false;
	
	switch (ttype(t1))
	{
	case LUA_TNIL:
		return true;
	case LUA_TNUMBER:
	{
		// to allow NaN and -0 comparison
		lua_Number n1 = nvalue(t1);
		lua_Number n2 = nvalue(t2);
		return memcmp(&n1, &n2, sizeof(lua_Number)) == 0;
	}
	case LUA_TVECTOR:
		return luai_veceq(vvalue(t1), vvalue(t2));
	case LUA_TBOOLEAN:
		return bvalue(t1) == bvalue(t2);
	case LUA_TLIGHTUSERDATA:
		return pvalue(t1) == pvalue(t2) && lightuserdatatag(t1) == lightuserdatatag(t2);
	default:
		return gcvalue(t1) == gcvalue(t2);
	}
}

#define twoto(x) ((int)(1 << (x)))
#define sizenode(t) (twoto((t)->lsizenode))

bool filterTable(Table* table, const TableFilter& filter)
{
	if (filter.metatable && table->metatable != filter.metatable)
		return false;

	for (const auto& key : filter.keys)
		if (ttisnil(luaH_get(table, &key)))
			return false;

	for (const auto& value : filter.values)
	{
		bool found = false;

		for (int i = 0; i < table->sizearray; ++i)
		{
			if (rawequalbitOjb(&table->array[i], &value))
			{
				found = true;
				break;
			}
		}

		if (!found)
		{
			for (int i = 0; i < sizenode(table); ++i)
			{
				LuaNode* n = &table->node[i];
				if (!ttisnil(&n->val) && rawequalbitOjb(&n->val, &value))
				{
					found = true;
					break;
				}
			}
		}

		if (!found)
			return false;
	}

	for (auto& [key, value] : filter.keyValuePairs)
		if (!rawequalbitOjb(luaH_get(table, &key), &value))
			return false;

	return true;
}

bool filterFunction(Closure* function, const FunctionFilter& filter)
{
	if (filter.name && filter.name == function->l.p->debugname)
		return false;

	if (filter.proto && function->l.p != filter.proto)
		return false;

	if (filter.environment && function->env != filter.environment)
		return false;

	if (filter.ignoreOur.has_value())
		if (functionMarker->isOurClosure(function) == filter.ignoreOur.value())
			return false;

	for (const auto& constant : filter.constants)
	{
		bool found = false;
		for (int i = 0; i < function->l.p->sizek; i++)
		{
			if (rawequalbitOjb(&function->l.p->k[i], &constant))
			{
				found = true;
				break;
			}
		}
		if (!found)
			return false;
	}

	for (const auto& upvalue : filter.upvalues)
	{
		bool found = false;
		for (int i = 0; i < function->nupvalues; i++) {
			if (rawequalbitOjb(getupvalue(function, i), &upvalue))
			{
				found = true;
				break;
			}
		}
		if (!found)
			return false;
	}

	return true;
}


bool filterUserdata(Udata* useradata, const UserdataFilter& filter)
{
	if (filter.metatable && useradata->metatable != filter.metatable)
		return false;

	return true;
}

// TODO: implement function hashing as a filter
int carbon_filtergc(lua_State* L)
{
	lua_Type searchType;

	auto typeName = std::string_view(luaL_checklstring(L, 1));
	auto options = lua_totable(L, 2);
	auto returnOne = luaL_optboolean(L, 3, false);

	if (typeName == "string")
		searchType = LUA_TSTRING;
	else if (typeName == "table")
		searchType = LUA_TTABLE;
	else if (typeName == "function")
		searchType = LUA_TFUNCTION;
	else if (typeName == "userdata")
		searchType = LUA_TUSERDATA;
	else if (typeName == "thread")
		searchType = LUA_TTHREAD;
	else if (typeName == "buffer")
		searchType = LUA_TBUFFER;

	struct SearchContext
	{
		lua_State* L = nullptr;
		lua_Type searchType = LUA_TNIL;
		uint32_t counter = 0;
		TableFilter tableFilter;
		FunctionFilter functionFilter;
		UserdataFilter userdataFilter;
	};

	SearchContext context{ L, searchType };

	if (options)
	{
		if (context.searchType == LUA_TTABLE)
		{
			lua_pushnil(L);
			while (lua_next(L, 2))
			{
				const char* key = lua_tolstring(L, -2, nullptr);

				if (strcmp_caseInsensitive(key, "Keys") == 0)
				{
					lua_pushnil(L);
					while (lua_next(L, -2))
					{
						TValue keyVal;
						setobj(&keyVal, L->top - 1);
						context.tableFilter.keys.push_back(keyVal);
						lua_pop(L, 1);
					}
				}
				else if (strcmp_caseInsensitive(key, "Values") == 0)
				{
					lua_pushnil(L);
					while (lua_next(L, -2))
					{
						TValue valueVal;
						setobj(&valueVal, L->top - 1);
						context.tableFilter.values.push_back(valueVal);
						lua_pop(L, 1);
					}
				}
				else if (strcmp_caseInsensitive(key, "KeyValuePairs") == 0)
				{
					lua_pushnil(L);
					while (lua_next(L, -2)) {
						std::pair<TValue, TValue> kvp;
						setobj(&kvp.first, L->top - 2);
						setobj(&kvp.second, L->top - 1);
						context.tableFilter.keyValuePairs.push_back(kvp);
						lua_pop(L, 1);
					}
				}
				else if (strcmp_caseInsensitive(key, "Metatable") == 0)
				{
					context.tableFilter.metatable = lua_totable(L, -1);
				}

				lua_pop(L, 1);
			}
		}
		else if (context.searchType == LUA_TFUNCTION)
		{
			lua_pushnil(L);
			while (lua_next(L, 2))
			{
				const char* key = lua_tolstring(L, -2, nullptr);

				if (strcmp_caseInsensitive(key, "Name") == 0)
				{
					context.functionFilter.name = lua_torawstring(L, -1);
				}
				else if (strcmp_caseInsensitive(key, "Constants") == 0)
				{
					lua_pushnil(L);
					while (lua_next(L, -2))
					{
						TValue constantVal;
						setobj(&constantVal, L->top - 1);
						context.functionFilter.constants.push_back(constantVal);
						lua_pop(L, 1);
					}
				}
				else if (strcmp_caseInsensitive(key, "Upvalues") == 0)
				{
					lua_pushnil(L);
					while (lua_next(L, -2))
					{
						TValue upvalueVal;
						setobj(&upvalueVal, L->top - 1);
						context.functionFilter.upvalues.push_back(upvalueVal);
						lua_pop(L, 1);
					}
				}
				else if (strcmp_caseInsensitive(key, "Proto") == 0)
				{
					if (auto closure = lua_toclosure(L, -1))
						if (!closure->isC)
							context.functionFilter.proto = closure->l.p;
				}
				else if (strcmp_caseInsensitive(key, "Environment") == 0)
				{
					context.functionFilter.environment = lua_totable(L, -1);
				}
				else if (strcmp_caseInsensitive(key, "IgnoreOur") == 0)
				{
					context.functionFilter.ignoreOur = lua_toboolean(L, -1);
				}
				
				lua_pop(L, 1);
			}
		}
		else if (context.searchType == LUA_TUSERDATA)
		{
			lua_pushnil(L);
			while (lua_next(L, 2))
			{
				const char* key = lua_tolstring(L, -2, nullptr);

				if (strcmp_caseInsensitive(key, "Metatable") == 0)
				{
					context.userdataFilter.metatable = lua_totable(L, -1);
				}

				lua_pop(L, 1);
			}
		}
	}

	if (returnOne)
	{
		luaM_visitgco<true>(L, &context, [](void* context_, lua_Page* page, GCObject* gco) -> bool {
			auto context = (SearchContext*)context_;

			auto L = context->L;

			if (L->global->isdead(gco))
				return false;

			if (gco->gch.tt == context->searchType)
			{
				if (gco->gch.tt == LUA_TTABLE && !filterTable(&gco->h, context->tableFilter))
					return false;

				if (gco->gch.tt == LUA_TFUNCTION && !filterFunction(&gco->cl, context->functionFilter))
					return false;

				if (gco->gch.tt == LUA_TUSERDATA && !filterUserdata(&gco->u, context->userdataFilter))
					return false;

				lua_pushrawgcobject(L, gco);
				return true;
			}

			return false;
		});
	}
	else
	{
		lua_createtable(L);

		lua_createtable(L, 0, 1);
		lua_pushstring(L, "__mode");
		lua_pushstring(L, "v");
		lua_rawset(L, -3);

		lua_setmetatable(L, -2);

		luaM_visitgco<false>(L, &context, [](void* context_, lua_Page* page, GCObject* gco) -> bool {
			auto context = (SearchContext*)context_;

			auto L = context->L;

			if (L->global->isdead(gco))
				return false;

			if (gco->gch.tt == context->searchType)
			{
				if (gco->gch.tt == LUA_TTABLE && !filterTable(&gco->h, context->tableFilter))
					return false;

				if (gco->gch.tt == LUA_TFUNCTION && !filterFunction(&gco->cl, context->functionFilter))
					return false;

				if (gco->gch.tt == LUA_TUSERDATA && !filterUserdata(&gco->u, context->userdataFilter))
					return false;

				lua_pushnumber(L, ++context->counter);
				lua_pushrawgcobject(L, gco);
				lua_rawset(L, -3);

				return true;
			}

			return false;
		});
	}

	return 1;
}