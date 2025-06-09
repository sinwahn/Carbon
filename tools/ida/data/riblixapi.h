

void InstanceBridge_pushshared(lua_State*, msvc_shared_ptr_Instance instance);
Context* getCurrentContext() = nullptr;
int luau_load(lua_State* L, const char* chunkname, const char* data, size_t size, int env);
void FLOG1(void* junk, const char* formatString, void* object);

int table_clear(lua_State* L);
int table_clone(lua_State* L);
int table_concat(lua_State* L);
int table_create(lua_State* L);
int table_find(lua_State* L);
int table_foreach(lua_State* L);
int table_foreachi(lua_State* L);
int table_freeze(lua_State* L);
int table_getn(lua_State* L);
int table_insert(lua_State* L);
int table_isfrozen(lua_State* L);
int table_maxn(lua_State* L);
int table_move(lua_State* L);
int table_pack(lua_State* L);
int table_remove(lua_State* L);
int table_sort(lua_State* L);
int table_unpack(lua_State* L);

int task_cancel(lua_State* L);
int task_defer(lua_State* L);
int task_delay(lua_State* L);
int task_desynchronize(lua_State* L);
int task_spawn(lua_State* L);
int task_synchronize(lua_State* L);
int task_wait(lua_State* L);

int coroutine_close(lua_State* L);
int coroutine_create(lua_State* L);
int coroutine_isyieldable(lua_State* L);
int coroutine_running(lua_State* L);
int coroutine_status(lua_State* L);
int coroutine_wrap(lua_State* L);
int coroutine_yield(lua_State* L);

int script_Delay(lua_State* L);
int script_ElapsedTime(lua_State* L);
int script_PluginManager(lua_State* L);
int script_Spawn(lua_State* L);
int script_Stats(lua_State* L);
int script_UserSettings(lua_State* L);
int script_Version(lua_State* L);
int script_Wait(lua_State* L);
int script_collectgarbage(lua_State* L);
int script_delay(lua_State* L);
int script_elapsedTime(lua_State* L);
int script_getfenv(lua_State* L);
int script_loadstring(lua_State* L);
int script_print(lua_State* L);
int script_printidentity(lua_State* L);
int script_require(lua_State* L);
int script_setfenv(lua_State* L);
int script_settings(lua_State* L);
int script_spawn(lua_State* L);
int script_stats(lua_State* L);
int script_tick(lua_State* L);
int script_time(lua_State* L);
int script_version(lua_State* L);
int script_wait(lua_State* L);
int script_warn(lua_State* L);
