export module TaskList;

import <list>;
import <functional>;
import <optional>;
import <mutex>;

import Logger;

export class Task
{
public:
	friend class TaskListProcessor;

	Task(std::chrono::milliseconds frequency = std::chrono::milliseconds(30),
		int maxRetries = 30, bool initiallyDelayed = false
	)
		: frequency(frequency)
		, maxRetries(maxRetries)
	{
		if (initiallyDelayed)
			delayLeft = frequency;
	}

	~Task() = default;

	enum class Type
	{
		FetchDataModelInfo,
		FetchLuaVmInfo,
		FetchDataModelForState,
		AvailableLuaStateReport,
	};

	enum class ExecutionResult
	{
		Retry,
		Fail,
		Success,
	};

	virtual ExecutionResult execute() = 0;
	virtual Type getType() const = 0;
	virtual bool equals(const Task& other) const { return getType() == other.getType(); }

	void update(std::chrono::milliseconds deltaTime) { delayLeft -= deltaTime; }
	bool canExecute() const { return delayLeft <= std::chrono::milliseconds(0); }

	void markRetry() { retries++; delayLeft = frequency; }
	bool canRetry() const { return retries < maxRetries; }

private:

	int maxRetries = 30;
	int retries = 0;
	std::chrono::milliseconds delayLeft = std::chrono::milliseconds(0);
	std::chrono::milliseconds frequency;
};


export const char* toString(Task::Type type)
{
	switch (type)
	{
	case Task::Type::FetchDataModelInfo: return "FetchDataModelInfo";
	case Task::Type::FetchLuaVmInfo: return "FetchLuaVmInfo";
	case Task::Type::FetchDataModelForState: return "FetchDataModelForState";
	case Task::Type::AvailableLuaStateReport: return "AvailableLuaStateReport";
	}
	return "unknown";
}

export class TaskList
{
public:

	TaskList() = default;
	~TaskList() = default;

	using taskList_t = std::list<std::unique_ptr<Task>>;

	template <typename TaskDerived>
	void add(TaskDerived&& _task)
		requires std::is_base_of_v<Task, TaskDerived>
	{
		std::scoped_lock lock(mutex);
		auto copy = new TaskDerived(_task);
		logger.log("adding", toString(_task.getType()));
		tasks.push_back(std::move(std::unique_ptr<Task>(copy)));
	}

	template <typename TaskDerived>
	std::optional<taskList_t::iterator> find(Task::Type type, std::function<bool(const TaskDerived*)> visitor)
		requires std::is_base_of_v<Task, TaskDerived>
	{
		std::scoped_lock lock(mutex);
		auto pos = std::find_if(
			tasks.begin(),
			tasks.end(),
			[&](const std::unique_ptr<Task>& task) {
				if (task->getType() != type)
					return false;

				return visitor(static_cast<const TaskDerived*>(task.get()));
			}
		);

		if (pos == tasks.end())
			return std::nullopt;

		return pos;
	}

	template <typename TaskDerived>
	std::optional<taskList_t::iterator> find(TaskDerived&& copy)
		requires std::is_base_of_v<Task, TaskDerived>
	{
		std::scoped_lock lock(mutex);
		auto pos = std::find_if(
			tasks.begin(),
			tasks.end(),
			[&](const std::unique_ptr<Task>& task) {
				return task->equals(copy);
			}
		);

		if (pos == tasks.end())
			return std::nullopt;

		return pos;
	}

	template <typename TaskDerived>
	void replace(TaskDerived&& _task)
		requires std::is_base_of_v<Task, TaskDerived>
	{
		std::scoped_lock lock(mutex);
		logger.log("replacing", toString(_task.getType()));

		remove(std::forward<TaskDerived&&>(_task));
		add(std::forward<TaskDerived&&>(_task));
	}

	template <typename TaskDerived>
	void remove(TaskDerived&& _task)
		requires std::is_base_of_v<Task, TaskDerived>
	{
		std::scoped_lock lock(mutex);
		auto result = find(std::forward<TaskDerived&&>(_task));
		if (result.has_value())
		{
			logger.log("removing", toString(_task.getType()));
			tasks.erase(result.value());
		}
	}

protected:

	taskList_t tasks;
	std::recursive_mutex mutex;
};

export class TaskListProcessor : public TaskList
{
public:
	
	TaskListProcessor() = default;
	~TaskListProcessor() = default;
	
	void createRunThread();

private:

	void processTasks(std::chrono::milliseconds deltaTime);
	std::chrono::milliseconds sleepTime = std::chrono::milliseconds(30);
	bool alive = true;
};

export inline TaskListProcessor taskListProcessor;