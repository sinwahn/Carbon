export module DataModelWatcher;

import RiblixStructures;
import TaskList;
import LuaStateWatcher;

import <mutex>;
import <map>;

// keep in sync with InjectionApi.cs
enum class DataModelType
{
	Invalid, // when type cannot be determined yet
	Server,
	Client,
	Unknown,
};

export class DataModelInfo
{
public:
	DataModelInfo(DataModel* dataModel);

	void setDataModel(DataModelType type);
	bool tryFetchInfo();

	DataModelType type = DataModelType::Invalid;
	DataModel* dataModel = nullptr;
	class DataModelWatcher* watcher;

};

export class FetchDataModelInfoTask : public Task
{
public:
	FetchDataModelInfoTask(std::weak_ptr<DataModelInfo> info);

	ExecutionResult execute() override;
	virtual bool equals(const Task& other) const override;

	Type getType() const override { return Type::FetchDataModelForState; };
	const DataModelInfo* getInfo() const { return info.lock().get(); };

private:
	std::weak_ptr<DataModelInfo> info;
};

export class AvailableLuaStateReportTask : public Task
{
public:
	Type getType() const override { return Type::AvailableLuaStateReport; }
	ExecutionResult execute() override;
private:
	void reportAvailableLuaStates() const;
};

export class DataModelWatcher
{
public:
	friend class AvailableLuaStateReportTask;

	DataModelWatcher();

	void onDataModelClosing(DataModel* dataModel);
	void onDataModelInfoSet(DataModelInfo* info);
	void onDataModelFetchedForState(DataModel* dataModel);

	std::shared_ptr<GlobalStateInfo> getStateByAddress(uintptr_t address);
	GlobalStateWatcher stateWatcher;
	std::recursive_mutex& getMutex() { return mutex; };
private:
	void addDataModel(DataModel* dataModel);
	bool tryAddDataModel(DataModel* dataModel);
	void removeDataModel(DataModel* dataModel);

	std::map<DataModel*, std::shared_ptr<DataModelInfo>> dataModels;
	std::recursive_mutex mutex;
};

export inline DataModelWatcher dataModelWatcher;