module;
#include <lualib.h>
export module Lua.Bridge;

import <utility>;
import <string>;
import <array>;
import ExceptionBase;
import Utils.Common;

class UserdataTagBank
{
public:
	int getNextFreeTag() {
		if (unsigned(nextFreeTag) >= LUA_UTAG_LIMIT)
			raise("Userdata tag limit reached");
		return nextFreeTag++;
	};
private:
	// 0 is default
	int nextFreeTag = 1;
};

static UserdataTagBank userdataTagBank;

export void luaL_pushmap(lua_State* L, const auto& container, const auto& pred)
{
	lua_createtable(L, 0, (int)container.size());
	for (const auto& [key, value] : container)
	{
		pred(L, key, value);
		lua_settable(L, -3);
	}
}

export void luaL_pusharraylike(lua_State* L, const auto& container, const auto& pred)
{
	lua_createtable(L, (int)container.size(), 0);

	int index = 1; // lua array starts from 1
	for (const auto& value : container)
	{
		lua_pushinteger(L, index++);
		pred(L, value);
		lua_settable(L, -3);
	}
}

export std::string luaL_checkstdstring(lua_State* L, int index)
{
	size_t stringSize = 0;
	const char* data = luaL_checklstring(L, index, &stringSize);
	return std::string(data, stringSize);
}

export std::string_view luaL_checkstdstringview(lua_State* L, int index)
{
	size_t stringSize = 0;
	const char* data = luaL_checklstring(L, index, &stringSize);
	return std::string_view(data, stringSize);
}

export class BridgeRegistrar
{
public:
	BridgeRegistrar(lua_State* L)
		: L(L)
	{

	}

	void registerMethod(const char* name, lua_CFunction func) {
		lua_pushstring(L, name);
		lua_pushcfunction(L, func, name);
		lua_settable(L, -3);
	};

	void registerField(const char* name, auto&& value) {
		lua_pushstring(L, name);

		using T = std::decay_t<decltype(value)>;
		if constexpr (std::is_same_v<T, double>)
			lua_pushnumber(L, value);
		else if constexpr (std::is_same_v<T, int>)
			lua_pushinteger(L, value);
		else if constexpr (std::is_same_v<T, const char*>)
			lua_pushstring(L, value);
		else if constexpr (std::is_same_v<T, lua_CFunction>)
			lua_pushcfunction(L, value, name);

		lua_settable(L, -3);
	};

	void registerFieldPushed(const char* name, int index) {
		lua_pushstring(L, name);
		lua_pushvalue(L, -2);
		lua_settable(L, -3);
	};

	void registerDestructor(lua_Destructor d) {
		destructor = d;
	}

	lua_Destructor getDestructor() const { return destructor; }

	lua_State* const L = nullptr;
private:
	lua_Destructor destructor = nullptr;
};

export template <
	typename DerivedBridge,
	typename Object,
	void(*userRegistrar)(BridgeRegistrar&) = nullptr
>
class Bridge
{
public:

	template <typename ...Args>
	static Object& push(lua_State* L, Args&& ...args)
	{
		auto instance = (Object*)lua_newuserdatataggedwithmetatable(L, sizeof(Object), tag);
		constructAt<Object>(instance, std::forward<Args>(args)...);
		if (tag)
			lua_getuserdatametatable(L, tag);
		else
			luaL_getmetatable(L, DerivedBridge::className);
		lua_setmetatable(L, -2);
		return *instance;
	}

	static void registerLib(lua_State* L)
	{
		registerMetatable(L);
		lua_pushvalue(L, -1);
		lua_setglobal(L, DerivedBridge::className);

		BridgeRegistrar registrar(L);
		registrar.registerField("__type", DerivedBridge::className);

		if constexpr (userRegistrar)
			userRegistrar(registrar);

		registerDestructor(registrar.getDestructor());

		if (shouldMakeTagged())
		{
			tag = userdataTagBank.getNextFreeTag();

			lua_pushvalue(L, -1);
			lua_setuserdatametatable(L, tag);
			
			if (destructor)
				lua_setuserdatadtor(L, tag, destructor);
		}

		lua_setreadonly(L, -1, true);

		lua_pop(L, 1);
	}

	static void registerMetatable(lua_State* L)
	{
		luaL_newmetatable(L, DerivedBridge::className);
		luaL_register(L, nullptr, DerivedBridge::library);
	}

	static bool isInstance(lua_State* L, int ud, Object** result = nullptr)
	{
		void* p = lua_touserdata(L, ud);
		if (p != nullptr)
		{ // value is a userdata?
			if (lua_getmetatable(L, ud))
			{
				lua_getuserdatametatable(L, tag);
				if (lua_rawequal(L, -1, -2))
				{                  // does it have the correct mt?
					lua_pop(L, 2); // remove both metatables
					if (result)
						*result = (Object*)p;
					return true;
				}
			}
		}
		return false;
	}

	static Object* checkInstance(lua_State* L, int ud)
	{
		void* p = lua_touserdata(L, ud);
		if (p != nullptr)
		{ // value is a userdata?
			if (lua_getmetatable(L, ud))
			{
				lua_getuserdatametatable(L, tag);
				if (lua_rawequal(L, -1, -2))
				{                  // does it have the correct mt?
					lua_pop(L, 2); // remove both metatables
					return (Object*)p;
				}
			}
		}
		luaL_typeerrorL(L, ud, DerivedBridge::className); // else error
	}

private:

	static void registerDestructor(lua_Destructor d) {
		destructor = d;
	}

	static bool shouldMakeTagged() {
		return true || destructor;
	}

	static inline lua_Destructor destructor = nullptr;
	static inline int tag = 0;
};