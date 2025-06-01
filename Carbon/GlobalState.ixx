module;
#include "../Common/CarbonWindows.h"
export module GlobalState;

import Pipes;
import LuaEnv;
import Logger;
import GlobalSettings;
import TaskList;
import FunctionMarker;
import Formatter;
import DataModelWatcher;
import Exception;

class NamedPipeClientBase : public NamedPipeClient
{
public:
	NamedPipeClientBase(const std::string& name)
		: NamedPipeClient(name)
	{

	}

	void readPipeData()
	{
		logger.log("reading pipe", name);
		auto reader = makeReadBuffer();
		logger.log("handling op", (uint8_t)reader.getOp());
		if (!handlePacket(reader.getOp(), reader))
			logger.log("dropping pipe data, op:", (uint8_t)reader.getOp());
	}

	virtual bool handlePacket(PipeOp, PipeReadBuffer&)
	{
		return false;
	}
};

class CommonPipe : public NamedPipeClientBase
{
public:
	CommonPipe(const std::string& name)
		: NamedPipeClientBase(name)
	{

	}

};

class PrivatePipe : public NamedPipeClientBase
{
public:
	enum Direction
	{
		ToClient,
		ToServer,
	};

	PrivatePipe(const std::string& name, Direction direction)
		: NamedPipeClientBase(name + (direction == Direction::ToServer ? "ToServer" : "ToClient"))
	{

	}

	bool handlePacket(PipeOp op, PipeReadBuffer& reader) override
	{
		switch (op)
		{
		case PipeOp::RunScript:
		{
			uintptr_t stateAddress = reader.readU64();
			auto size = reader.readU64();
			auto string = reader.readArray<char>(size);
			auto code = std::string(string, size);

			auto info = dataModelWatcher.getStateByAddress(stateAddress);
			if (!info)
			{
				logger.log("invalid state passed on RunScript", (void*)stateAddress);
				return false;
			}

			luaApiRuntimeState.runScript(info, code);
			return true;
		}
		}

		return false;
	}
};

export class GlobalState
{
public:

	GlobalState();

	void init(HMODULE ghModule, const std::wstring& settingsPath, const std::wstring& userDirectory);
	void startPipesReading();
	PipeWriteBuffer createCommonWriteBuffer(PipeOp op);
	PipeWriteBuffer createPrivateWriteBuffer(PipeOp op);

private:

	HMODULE ghModule;
	TaskListProcessor taskListProcessor;
	CommonPipe commonPipe;
	PrivatePipe toServerPipe;
	PrivatePipe toClientPipe;
};

export inline GlobalState globalState;

GlobalState::GlobalState()
	: commonPipe(commonPipeName)
	, toServerPipe(privatePipeNamePrefix + std::to_string(GetCurrentProcessId()), PrivatePipe::Direction::ToServer)
	, toClientPipe(privatePipeNamePrefix + std::to_string(GetCurrentProcessId()), PrivatePipe::Direction::ToClient)
{

}

void GlobalState::init(HMODULE _ghModule, const std::wstring& settingsPath, const std::wstring& userDirectory)
{
	ghModule = _ghModule;

	if (!commonPipe.connect())
		logger.log("failed to connect to", commonPipe.getName(), formatLastError());

	globalSettings.init(settingsPath);

	luaApiRuntimeState.setLuaSettings(&globalSettings.luaApiSettings);
	luaApiRuntimeState.userContentApiRootDirectory = userDirectory;
	functionMarker = new FunctionMarker(ghModule);
}

void GlobalState::startPipesReading()
{
	std::thread([&]() {

		basicTryWrapper("GlobalState::startPipesReading/toClientPipe.readPipeData", [&]() {

			if (!toServerPipe.connect())
			{
				logger.log("failed to connect to", toServerPipe.getName(), formatLastError());
			}

			if (!toClientPipe.connect())
			{
				logger.log("failed to connect to", toClientPipe.getName(), formatLastError());
				return;
			}

			while (true)
				toClientPipe.readPipeData();
		});

	}).detach();

	auto writer = createCommonWriteBuffer(PipeOp::ProcessConnected);
	writer.writeU32(GetCurrentProcessId());
	writer.send();

	while (true)
		commonPipe.readPipeData();
}

PipeWriteBuffer GlobalState::createCommonWriteBuffer(PipeOp op)
{
	return commonPipe.makeWriteBuffer(op);
}

PipeWriteBuffer GlobalState::createPrivateWriteBuffer(PipeOp op)
{
	return toServerPipe.makeWriteBuffer(op);
}