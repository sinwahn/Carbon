export module SharedAddresses;

import <memory>;
import <string>;

import LuauTypes;
import RiblixStructures;
<<<<<<< HEAD
import RiblixStructureOffsets;
=======
>>>>>>> 12167be5f07cdcc1f00513a6a279704889470d1f
import Pipes;

export
{
	struct LuaApiAddresses
	{
		TValue* luaO_nilobject = nullptr;

		int (*lua_getinfo)(lua_State* L, int level, const char* what, lua_Debug* ar) = nullptr;

		void (*luaL_typeerrorL)(lua_State* L, int narg, const char* tname) = nullptr;
		void (*luaL_errorL)(lua_State* L, const char* fmt, ...) = nullptr;
		const char* (*luaL_typename)(lua_State* L, int idx) = nullptr;

		void (*lua_pushlstring)(lua_State*, const char* s, size_t len) = nullptr;
		void (*lua_pushvalue)(lua_State*, int idx) = nullptr;
		const char* (*lua_tolstring)(lua_State*, int, size_t*) = nullptr;

		void (*lua_settable)(lua_State*, int idx) = nullptr;
		int (*lua_getfield)(lua_State* L, int idx, const char* k) = nullptr;
		void (*lua_setfield)(lua_State* L, int idx, const char* k) = nullptr;

		void (*lua_createtable)(lua_State*, int narr, int nrec) = nullptr;
		Table* (*luaH_clone)(lua_State* L, Table* tt) = nullptr;
		int (*lua_next)(lua_State* L, int idx) = nullptr;
		int (*lua_rawget)(lua_State* L, int idx) = nullptr;
		void (*lua_rawset)(lua_State* L, int idx) = nullptr;
		int (*lua_setmetatable)(lua_State*, int objindex) = nullptr;
		int (*lua_getmetatable)(lua_State*, int objindex) = nullptr;

		void (*lua_pushcclosurek)(lua_State* L, lua_CFunction fn, const char* debugname, int nup, lua_Continuation cont) = nullptr;
		Closure* (*luaF_newLclosure)(lua_State* L, int nelems, Table* e, Proto* p) = nullptr;

		void (*luaD_call)(lua_State* L, StkId func, int nresults) = nullptr;
		int (*luaD_pcall)(lua_State* L, Pfunc func, void* u, ptrdiff_t old_top, ptrdiff_t ef) = nullptr;

		Proto* (*luaF_newproto)(lua_State* L) = nullptr;

		void (*luaD_reallocCI)(lua_State* L, int newsize) = nullptr;
		CallInfo* (*luaD_growCI)(lua_State* L) = nullptr;

		void (*lua_concat)(lua_State* L, int n) = nullptr;
		void* (*lua_newuserdatatagged)(lua_State* L, size_t sz, int tag) = nullptr;
		const TValue* (*luaH_get)(Table* t, const TValue* key) = nullptr;

		lua_State* (*lua_newthread)(lua_State* L) = nullptr;
		int (*task_defer)(lua_State* L) = nullptr;
		lua_State* (*lua_newstate)(void* allocator, void* userdata) = nullptr;
	};

	struct RiblixAddresses
	{
		void (*InstanceBridge_pushshared)(lua_State*, msvc_shared_ptr<Instance>) = nullptr;
		Context* (*getCurrentContext)() = nullptr;
		int (*luau_load)(lua_State* L, const char* chunkname, const char* data, size_t size, int env) = nullptr;

		void (*FLOG1)(void* junk, const char* formatString, void* object) = nullptr;
	};

	int sharedMemorySize = 3000;

	inline LuaApiAddresses luaApiAddresses;
	inline RiblixAddresses riblixAddresses;

	struct SharedMemoryOffsets
	{
		LuaApiAddresses luaApiAddresses;
		RiblixAddresses riblixAddresses;
<<<<<<< HEAD
		RiblixOffsets riblixOffsets;
=======
>>>>>>> 12167be5f07cdcc1f00513a6a279704889470d1f
	};

	struct SharedMemoryContentDeserialized;
	struct SharedMemoryContent
	{
		const char data[1];
		SharedMemoryContentDeserialized deserialize() const;
	};

	struct SharedMemoryContentDeserialized
	{
		SharedMemoryOffsets offsets;
		std::wstring settingsPath;
		std::wstring userDirectoryPath;
		std::wstring logPath;
		std::string serialize() const;
	};

	std::string SharedMemoryContentDeserialized::serialize() const
	{
		WriteBuffer buffer;
		buffer.writeArray(&offsets, 1);

		buffer.writeU64(settingsPath.size());
		buffer.writeArray(settingsPath.c_str(), settingsPath.size());

		buffer.writeU64(userDirectoryPath.size());
		buffer.writeArray(userDirectoryPath.c_str(), userDirectoryPath.size());

		buffer.writeU64(logPath.size());
		buffer.writeArray(logPath.c_str(), logPath.size());

		return buffer.getResult();
	}

	SharedMemoryContentDeserialized SharedMemoryContent::deserialize() const
	{
		SharedMemoryContentDeserialized result;

		RawReadBuffer reader(data);
			
		auto readwstring = [&](){
			auto size = reader.readU64();
			auto string = reader.readArray<wchar_t>(size);
			return std::wstring(string, size);
		};

		result.offsets = *reader.readArray<SharedMemoryOffsets>(1);

		result.settingsPath = readwstring();
		result.userDirectoryPath = readwstring();
		result.logPath = readwstring();

		return result;
	}

	inline const wchar_t* sharedMemoryName = L"Carbon_SharedMemory";
}