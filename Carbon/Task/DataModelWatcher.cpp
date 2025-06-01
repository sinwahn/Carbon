module DataModelWatcher;

import RiblixStructures;
import TaskList;
import Logger;
import GlobalState;

DataModelInfo::DataModelInfo(DataModel* dataModel)
	: dataModel(dataModel)
{
}

void DataModelInfo::setDataModel(DataModelType _type)
{
	if (type != _type)
	{
		type = _type;
		watcher->onDataModelInfoSet(this);
	}
}

DataModelType getDataModelType(const DataModel* dataModel)
{
	if (dataModel->getChildren().get()->empty())
		return DataModelType::Invalid;

	std::string name;
	name.reserve(100);

	for (auto& child : *dataModel->getChildren().get())
	{
		name = child->getClassName();
		if (name == "NetworkServer")
			return DataModelType::Server;

		if (name == "NetworkClient")
			return DataModelType::Client;
	}

	return DataModelType::Unknown;
}

bool DataModelInfo::tryFetchInfo()
{
	auto fetchedType = getDataModelType(dataModel);
	if (fetchedType == DataModelType::Invalid)
		return false;

	setDataModel(fetchedType);

	taskListProcessor.add(AvailableLuaStateReportTask());

	return true;
}

FetchDataModelInfoTask::FetchDataModelInfoTask(std::weak_ptr<DataModelInfo> info)
	: Task()
	, info(info)
{

}

Task::ExecutionResult FetchDataModelInfoTask::execute()
{
	if (info.expired())
		return Task::ExecutionResult::Fail;
	return info.lock()->tryFetchInfo() ? Task::ExecutionResult::Success : Task::ExecutionResult::Retry;
}

bool FetchDataModelInfoTask::equals(const Task& other) const
{
	if (!Task::equals(other))
		return false;

	return info.lock() == static_cast<const FetchDataModelInfoTask&>(other).info.lock();
}

const char* toString(DataModelType type)
{
	switch (type)
	{
	case DataModelType::Server: return "server";
	case DataModelType::Client: return "client";
	case DataModelType::Unknown: return "unknown";
	}
	return "invalid";
}

Task::ExecutionResult AvailableLuaStateReportTask::execute()
{
	reportAvailableLuaStates();
	return Task::ExecutionResult::Success;
}

void AvailableLuaStateReportTask::reportAvailableLuaStates() const
{
	std::scoped_lock lock(dataModelWatcher.getMutex());
	// keep in sync with OnAvailableStatesReportReceived
	auto writer = globalState.createPrivateWriteBuffer(PipeOp::ReportAvailableEnvironments);

	writer.writeU32((uint32_t)dataModelWatcher.dataModels.size());

	for (const auto& [dataModel, info] : dataModelWatcher.dataModels)
	{
		writer.writeU64((uintptr_t)dataModel);
		writer.writeU8((uint8_t)info->type);

		auto states = dataModelWatcher.stateWatcher.getAssociatedStates(dataModel);
		writer.writeU32((uint32_t)states.size());

		for (const auto& info : states)
		{
			writer.writeU64((uintptr_t)info->mainThread);
			writer.writeI32((int)info->vmType);
		}

	}

	writer.send();
}

DataModelWatcher::DataModelWatcher()
{
}

void DataModelWatcher::onDataModelClosing(DataModel* dataModel)
{
	logger.log("closing DM", dataModel);
	stateWatcher.onDataModelClosing(dataModel);
	removeDataModel(dataModel);
}

void DataModelWatcher::onDataModelInfoSet(DataModelInfo* info)
{
	taskListProcessor.replace(AvailableLuaStateReportTask());
}

void DataModelWatcher::onDataModelFetchedForState(DataModel* dataModel)
{
	if (tryAddDataModel(dataModel))
		logger.log("added new DM from fetch", dataModel);
	else
		logger.log("failed to add new DM from fetch", dataModel);
}

std::shared_ptr<GlobalStateInfo> DataModelWatcher::getStateByAddress(uintptr_t address)
{
	return stateWatcher.getStateByAddress(address);
}

void DataModelWatcher::addDataModel(DataModel* dataModel)
{
	logger.log("added DM", dataModel);

	auto emplaced = dataModels.emplace(dataModel, std::make_shared<DataModelInfo>(dataModel));

	auto& info = emplaced.first->second;
	bool needsDelayedFetch = !info->tryFetchInfo();

	if (needsDelayedFetch)
		taskListProcessor.add(FetchDataModelInfoTask(info));
}

bool DataModelWatcher::tryAddDataModel(DataModel* dataModel)
{
	std::scoped_lock lock(mutex);
	if (dataModels.contains(dataModel))
		return false;

	addDataModel(dataModel);
	return true;
}

void DataModelWatcher::removeDataModel(DataModel* dataModel)
{
	std::scoped_lock lock(mutex);
	taskListProcessor.remove(FetchDataModelInfoTask(dataModels[dataModel]));
	dataModels.erase(dataModel);
}