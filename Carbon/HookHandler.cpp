module;
#include "MinHook/MinHook.h"
module HookHandler;

import <array>;
import <string>;

import Luau;
import CarbonLuaApiLibs.closurelib;
import Logger;
import Exception;

Hook::Hook(const std::string& name)
	: name(name)
	, target(target)
	, hook(hook)
{
}

bool Hook::setup()
{
	if (MH_OK != MH_CreateHook(target, hook, &original))
	{
		logger.log("failed to create", name, "hook");
		return false;
	}

	if (MH_OK != MH_EnableHook(target))
	{
		logger.log("failed to enable", name, "hook");
		return false;
	}

	return true;
}

bool Hook::remove()
{
	if (MH_OK != MH_RemoveHook(target))
	{
		logger.log("failed to remove", name, "hook");
		return false;
	}

	return true;
}

HookHandler::HookHandler()
	: hooks({
		{ "growCI" },
		{ "lua_getfield" },
		{ "FLOG1" },
		{ "lua_newstate" },
	})
{
	MH_Initialize();
}

HookHandler::~HookHandler()
{
	removeAll();
	MH_Uninitialize();
}

void HookHandler::removeAll()
{
	for (auto& hook : hooks)
		hook.remove();
}