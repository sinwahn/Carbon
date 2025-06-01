module LuaStateWatcher;

import LuauTypes;
import Luau;
import Console;
import RiblixStructures;
import Logger;
import TaskList;
import DataModelWatcher;
<<<<<<< HEAD
import CarbonLuaApiLibs.dbglib;
=======
>>>>>>> 12167be5f07cdcc1f00513a6a279704889470d1f

GlobalStateInfo::GlobalStateInfo(lua_State* mainThread)
	: mainThread(mainThread)
{

}

DataModel* getAssociatedDataModel(const lua_State* L)
{
	if (auto extraSpace = L->userdata)
		if (auto scriptContext = extraSpace->scriptContext)
<<<<<<< HEAD
			if (auto parent = scriptContext->getParent())
				if (parent->getClassName() == "DataModel")
					return parent;
=======
			if (auto parent = scriptContext->parent)
				if (parent->getClassName() == "DataModel")
					return DataModel::toDataModel(parent);
>>>>>>> 12167be5f07cdcc1f00513a6a279704889470d1f

	return nullptr;
}


FetchDataModelForStateTask::FetchDataModelForStateTask(std::weak_ptr<GlobalStateInfo> info)
	: Task()
	, info(info)
{
}

Task::ExecutionResult FetchDataModelForStateTask::execute()
{
<<<<<<< HEAD
	carbon_disablepointerencoding(info.lock()->mainThread);
=======
>>>>>>> 12167be5f07cdcc1f00513a6a279704889470d1f
	if (info.expired())
		return ExecutionResult::Fail;

	auto dataModel = getAssociatedDataModel(info.lock()->mainThread);
	if (!dataModel)
		return ExecutionResult::Retry;

	info.lock()->dataModel = dataModel;
	dataModelWatcher.onDataModelFetchedForState(dataModel);

	taskListProcessor.add(std::move(FetchLuaVmInfoTask(info)));

	return ExecutionResult::Success;
}

bool FetchDataModelForStateTask::equals(const Task& other) const
{
	if (!Task::equals(other))
		return false;

	return info.lock() == static_cast<const FetchDataModelForStateTask&>(other).info.lock();
}

FetchLuaVmInfoTask::FetchLuaVmInfoTask(std::weak_ptr<GlobalStateInfo> info)
	: Task(std::chrono::milliseconds(200), 40, true)
	, info(info)
{
}


struct vmStatesStats
{
	uint32_t statesCount = 0;
	std::map<int, uint32_t> identitiesCount;
};

vmStatesStats getVmStats(lua_State* L)
{
	struct gcvisit
	{
		lua_State* L = nullptr;
		vmStatesStats stats;
	};

	gcvisit context{ L };

	luaM_visitgco<false>(L, &context, [](void* context_, lua_Page* page, GCObject* gco) -> bool {
		gcvisit* context = (gcvisit*)context_;

		auto L = context->L;

		if (L->global->isdead(gco))
			return false;

		switch (gco->gch.tt)
		{
		case LUA_TTHREAD:
<<<<<<< HEAD
			if (gco->th.userdata)
			{
				context->stats.identitiesCount[gco->th.userdata->identity]++;
				context->stats.statesCount++;
			}
=======
			context->stats.identitiesCount[gco->th.userdata->identity]++;
			context->stats.statesCount++;
>>>>>>> 12167be5f07cdcc1f00513a6a279704889470d1f
			break;
		}

		return false;
	});

	return context.stats;
}

Task::ExecutionResult FetchLuaVmInfoTask::execute()
{
	if (info.expired())
		return ExecutionResult::Fail;

	auto stats = getVmStats(info.lock()->mainThread);

	if (stats.statesCount == 0)
		return ExecutionResult::Retry;

	uint32_t highestCount = 0;
	int mostlyIdentity = 0;

	for (auto [identity, count] : stats.identitiesCount)
	{
		if (count > highestCount) {
			highestCount = count;
			mostlyIdentity = identity;
		}
	}

	info.lock()->vmType = (GlobalStateInfo::VmType)mostlyIdentity;

	taskListProcessor.replace(AvailableLuaStateReportTask());

	return ExecutionResult::Success;
}

bool FetchLuaVmInfoTask::equals(const Task& other) const
{
	if (!Task::equals(other))
		return false;

	return info.lock() == static_cast<const FetchLuaVmInfoTask&>(other).info.lock();
}

GlobalStateWatcher::GlobalStateWatcher()
{

}

void GlobalStateWatcher::onDataModelClosing(DataModel* dataModel)
{
	removeAssociatedStates(dataModel);
}

void GlobalStateWatcher::onGlobalStateCreated(lua_State* L)
{
	logger.log("adding global state", L);
	addState(L);
}

void GlobalStateWatcher::onGlobalStateRemoving(lua_State* L)
{
	logger.log("removing global state", L);

	taskListProcessor.add(std::move(AvailableLuaStateReportTask()));
}

std::vector<std::shared_ptr<GlobalStateInfo>> GlobalStateWatcher::getAssociatedStates(const DataModel* with)
{
	std::scoped_lock lock(mutex);
	std::vector<std::shared_ptr<GlobalStateInfo>>result;

	for (const auto& [_, info] : states)
		if (info->dataModel == with)
			result.push_back(info);
	
	return result;
}

std::shared_ptr<GlobalStateInfo> GlobalStateWatcher::getStateByAddress(uintptr_t address)
{
	std::scoped_lock lock(mutex);
	auto pos = states.find((lua_State*)address);
	if (pos == states.end())
		return nullptr;
	return pos->second;
}

void GlobalStateWatcher::addState(lua_State* L)
{
	std::scoped_lock lock(mutex);
	auto pos = states.find(L);
	if (pos != states.end())
	{
		logger.log("attempt to add duplicate global state", L);
		return;
	}

	auto dataModel = getAssociatedDataModel(L);
	auto info = std::make_shared<GlobalStateInfo>(L);
	info->dataModel = dataModel;

	auto emplaced = states.emplace(L, info);

	if (!dataModel)
	{
		auto& info = emplaced.first->second;
		taskListProcessor.add(FetchDataModelForStateTask(info));
	}
}

GlobalStateWatcher::map_t::iterator GlobalStateWatcher::removeState(map_t::iterator pos)
{
	std::scoped_lock lock(mutex);
	return states.erase(pos);
}

GlobalStateWatcher::map_t::iterator GlobalStateWatcher::removeState(lua_State* L)
{
	std::scoped_lock lock(mutex);
	auto pos = states.find(L);
	if (pos == states.end())
	{
		logger.log("attempt to remove unknown global state", L);
		return pos;
	}
	return removeState(pos);
}

void GlobalStateWatcher::removeAssociatedStates(const DataModel* with)
{
	std::scoped_lock lock(mutex);

	auto iter = states.begin();
	while (iter != states.end())
	{
		if (iter->second->dataModel == with)
		{
			onGlobalStateRemoving(iter->first);
			iter = removeState(iter);
		}
		else
		{
			iter++;
		}
	}
}