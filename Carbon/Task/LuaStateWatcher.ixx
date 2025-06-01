export module LuaStateWatcher;

import <vector>;
import <map>;
import <mutex>;

import LuauTypes;
import RiblixStructures;
import TaskList;

export struct GlobalStateInfo
{
	enum class VmType : int
	{
		Unknown,
		Game = 2,
		Core = 3,
		Plugins = 5,
		BuiltinPlugins = 6,
	};

	GlobalStateInfo(lua_State* mainThread);

	DataModel* dataModel = nullptr;
	lua_State* const mainThread = nullptr;
	lua_State* ourMainThread = nullptr;
	bool environmentInjected = false;
	VmType vmType = VmType::Unknown;
};

export class FetchDataModelForStateTask : public Task
{
public:
	FetchDataModelForStateTask(std::weak_ptr<GlobalStateInfo> info);

	ExecutionResult execute() override;
	Type getType() const override { return Type::FetchDataModelInfo; }
	bool equals(const Task& other) const override;

private:
	std::weak_ptr<GlobalStateInfo> info;
};

export class FetchLuaVmInfoTask : public Task
{
public:
	FetchLuaVmInfoTask(std::weak_ptr<GlobalStateInfo> info);

	ExecutionResult execute() override;
	Type getType() const override { return Type::FetchLuaVmInfo; }
	bool equals(const Task& other) const override;

private:
	std::weak_ptr<GlobalStateInfo> info;
};

export class GlobalStateWatcher
{
public:
	using map_t = std::map<lua_State*, std::shared_ptr<GlobalStateInfo>>;

	GlobalStateWatcher();

	void onDataModelClosing(DataModel* dataModel);
	void onGlobalStateCreated(lua_State* L);
	void onGlobalStateRemoving(lua_State* L);
	std::vector<std::shared_ptr<GlobalStateInfo>> getAssociatedStates(const DataModel* with);
	std::shared_ptr<GlobalStateInfo> getStateByAddress(uintptr_t address);

private:
	void addState(lua_State* L);
	map_t::iterator removeState(map_t::iterator pos);
	map_t::iterator removeState(lua_State* L);
	void removeAssociatedStates(const DataModel* with);

	map_t states;
	std::recursive_mutex mutex;
};