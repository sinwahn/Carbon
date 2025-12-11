module;
#include <lualib.h>
export module Lua.BaseLib;

import Api;
import ExceptionBase;

import Lua.Address;
import Lua.FunctionData;
import Lua.Section;
import Lua.ByteArray;
import Memory;
import Lua.Bridge;

// user can pass either section + address or functionData directly
FunctionData checkFunctionData(lua_State* L, int& argIndex)
{
	FunctionData* existingData = nullptr;
	if (FunctionDataBridge::isInstance(L, ++argIndex), &existingData)
		return *existingData;

	auto& section = luaL_checkSection(L, ++argIndex);
	auto& functionAddress = luaL_checkAddress(L, ++argIndex);
	if (!functionAddress.isLocalValid())
		raise("Invalid function address", lua_tostring(L, argIndex - 1));
	return section->createFunctionData(functionAddress);
}

int dumper_getCallingFunctions(lua_State* L)
{
	int argIndex = 0;
	auto functionData = checkFunctionData(L, argIndex);
	auto calls = getCallingFunctions(functionData);

	luaL_pusharraylike(L, calls, [](auto L, const Address& offset) {
		AddressBridge::push(L, offset);
	});

	return 1;
}

int dumper_getCallingFunctionAt(lua_State* L)
{
	int argIndex = 0;
	auto functionData = checkFunctionData(L, argIndex);
	int index = luaL_checkinteger(L, ++argIndex);
	if (index < 1)
		luaL_errorL(L, "index is out of range");
	auto call = getCallingFunctionAt(functionData, index + 1);
	AddressBridge::push(L, call);
	return 1;
}

int dumper_getLeaTargets(lua_State* L)
{
	int argIndex = 0;
	auto functionData = checkFunctionData(L, argIndex);
	auto targets = getLeaTargets(functionData);

	luaL_pusharraylike(L, targets, [](auto L, const Address& offset) {
		AddressBridge::push(L, offset);
	});
	
	return 1;
}

int dumper_findSequences(lua_State* L)
{
	auto& section = luaL_checkSection(L, 1);
	auto data = luaL_checkstdstringview(L, 2);
	ByteArray toFind((BYTE*)data.data(), data.size());
	auto found = findSequences(section->newBuffer(), toFind);

	luaL_pusharraylike(L, found, [&](auto L, const Offset& offset) {
		AddressBridge::push(L, section->offsetToAddress(offset));
	});

	return 1;
}

int dumper_findSequence(lua_State* L)
{
	auto& section = luaL_checkSection(L, 1);
	auto data = luaL_checkstdstringview(L, 2);
	ByteArray toFind((BYTE*)data.data(), data.size());
	auto found = findSequence(section->newBuffer(), toFind);
	AddressBridge::push(L, found);
	return 1;
}

int getNextFunction(lua_State* L)
{
	auto& data = luaL_checkFunctionData(L, 1);
	FunctionDataBridge::push(L, getNextFunction(data));
	return 1;
}

int getCallInfo(lua_State* L)
{
	auto& data = luaL_checkFunctionData(L, 1);
	FunctionDataBridge::push(L, getNextFunction(data));
	return 1;
}

int tryDumpLuau(lua_State* L)
{
	L;
	tryDumpLuau_api();
	return 0;
}

export const luaL_Reg baseLibrary[] = {
	{"getCallingFunctions", dumper_getCallingFunctions},
	{"getCallingFunctionAt", dumper_getCallingFunctionAt},
	{"getLeaTargets", dumper_getLeaTargets},
	{"getNextFunction", getNextFunction},
	{"findSequence", dumper_findSequence},
	{"findSequences", dumper_findSequences},

	{nullptr, nullptr},
};