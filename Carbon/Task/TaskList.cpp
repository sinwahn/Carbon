module TaskList;

import Logger;

import <memory>;
import <functional>;
import <optional>;
import <mutex>;
import <thread>;

void TaskListProcessor::createRunThread()
{
	std::thread([&]() {
		try
		{
			logger.log("TaskListProcessor::createRunThread");
			while (alive)
			{
				std::this_thread::sleep_for(sleepTime);
				processTasks(sleepTime);
			}
		}
		catch (std::exception& e)
		{
			logger.log(e.what());
		}
		catch (...)
		{
			logger.log("TaskListProcessor: caught something bad");
		}
	}).detach();
}

void TaskListProcessor::processTasks(std::chrono::milliseconds deltaTime)
{
	auto iter = tasks.begin();
	while (iter != tasks.end())
	{
		auto& task = *iter;

		task->update(deltaTime);

		if (task->canExecute())
		{
			switch (task->execute())
			{
			case Task::ExecutionResult::Retry:

				if (!task->canRetry())
				{
					logger.log("dropping task", toString(task->getType()));
					iter = tasks.erase(iter);
					continue;
				}

				task->markRetry();

				break;
			case Task::ExecutionResult::Fail:
			case Task::ExecutionResult::Success:
				iter = tasks.erase(iter);
				continue;
			}
		}

		iter++;
	}
}