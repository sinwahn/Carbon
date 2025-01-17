module;
#include "../../Common/CarbonWindows.h"
export module CarbonLuaApiLibs.dbglib;

import <ranges>;
import Luau;
import Luau.Riblix;
import RiblixStructures;
import StringUtils;
import Formatter;

int carbon_disablepointerencoding(lua_State* L);
int carbon_getdescriptors(lua_State* L);
int carbon_getdescriptorinfo(lua_State* L);
int carbon_getscriptcontext(lua_State* L);
int carbon_getcfunction(lua_State* L);
int carbon_repush(lua_State* L);
int carbon_gettt(lua_State* L);
int carbon_getgcaddr(lua_State* L);
int carbon_torva(lua_State* L);
int carbon_getcontext(lua_State* L);

int carbon_getinstancebrigdemap(lua_State* L);

int carbon_dumpstacks(lua_State* L);
int carbon_debugbreak(lua_State* L);

int carbon_setscriptable(lua_State* L);

export const luaL_Reg debug_library[] = {
	{"disablepointerencoding", carbon_disablepointerencoding},
	{"getdescriptors", carbon_getdescriptors},
	{"getdescriptorinfo", carbon_getdescriptorinfo},
	{"dumpstacks", carbon_dumpstacks},
	{"torva", carbon_torva},
	{"getcontext", carbon_getcontext},

	{"getscriptcontext", carbon_getscriptcontext},
	{"getcfunction", carbon_getcfunction},
	{"getgcaddr", carbon_getgcaddr},
	{"repush", carbon_repush},
	{"gettt", carbon_gettt},

	{"getinstancebrigdemap", carbon_getinstancebrigdemap},

	{"setscriptable", carbon_setscriptable},
	{"debugbreak", carbon_debugbreak},

	{nullptr, nullptr},
};

int carbon_disablepointerencoding(lua_State* L)
{
	L->global->ptrenckey[0] = 1;
	L->global->ptrenckey[1] = 0;
	L->global->ptrenckey[2] = 0;
	L->global->ptrenckey[3] = 0;
	return 0;
}

int carbon_getinstancebrigdemap(lua_State* L)
{
	push_instanceBridgeMap(L);
	return 1;
}

// returns false if passed categoryName is invalid
bool pushDescriptorsTable(lua_State* L, const char* categoryName, Instance* instance)
{
	auto classDescriptor = instance->classDescriptor;

	auto pushCollection = [&](auto container) {

		auto collection = container.collection;
		lua_createtable(L, (int)collection.size(), 0);

		for (auto [index, descriptor] : std::ranges::views::enumerate(collection.createViewRange()))
		{
			lua_pushinteger(L, (int)index + 1); // lua array style
			lua_pushstring(L, descriptor->name->c_str());
			lua_settable(L, -3);
		}
	};

	std::span<MemberDescriptor*> collection;

	if (strcmp_caseInsensitive(categoryName, "Property"))
	{
		pushCollection(classDescriptor->properties);
	}
	else if (strcmp_caseInsensitive(categoryName, "Event"))
	{
		pushCollection(classDescriptor->events);
	}
	else if (strcmp_caseInsensitive(categoryName, "Function"))
	{
		pushCollection(classDescriptor->functions);
	}
	else if (strcmp_caseInsensitive(categoryName, "YieldFunction"))
	{
		pushCollection(classDescriptor->yieldFunctions);
	}
	else if (strcmp_caseInsensitive(categoryName, "Callback"))
	{
		pushCollection(classDescriptor->callbacks);
	}
	else
	{
		return false;
	}

	return true;

}

int carbon_getdescriptors(lua_State* L)
{
	auto instance = checkInstance(L, 1);

	if (lua_isnoneornil(L, 2))
	{
		lua_createtable(L, 0, 5);

		lua_pushstring(L, "Property");
		pushDescriptorsTable(L, "Property", instance);
		lua_settable(L, -3);

		lua_pushstring(L, "Event");
		pushDescriptorsTable(L, "Event", instance);
		lua_settable(L, -3);

		lua_pushstring(L, "Function");
		pushDescriptorsTable(L, "Function", instance);
		lua_settable(L, -3);

		lua_pushstring(L, "YieldFunction");
		pushDescriptorsTable(L, "YieldFunction", instance);
		lua_settable(L, -3);

		lua_pushstring(L, "Callback");
		pushDescriptorsTable(L, "Callback", instance);
		lua_settable(L, -3);
	}
	else
	{
		const char* name = luaL_checklstring(L, 2);
		if (!pushDescriptorsTable(L, name, instance))
			luaL_argerrorL(L, 2, "invalid descriptor collection name");
	}

	return 1;
}


void pushRva(lua_State* L, uintptr_t address)
{
	lua_pushstring(L, Formatter::pointerToString(address - (uintptr_t)GetModuleHandle(nullptr)).c_str());
}

void pushRva(lua_State* L, void* address)
{
	pushRva(L, (uintptr_t)address);
}

int carbon_getdescriptorinfo(lua_State* L)
{
	auto instance = checkInstance(L, 1);

	static const int commonPropertiesCount = 9;
	auto setCommonInfo = [&](MemberDescriptor* target) {
		lua_pushstring(L, "Address");
		lua_pushstring(L, Formatter::pointerToString(target).c_str());
		lua_settable(L, -3);

		lua_pushstring(L, "Name");
		lua_pushstring(L, target->name->c_str());
		lua_settable(L, -3);

		{
			lua_createtable(L, 0, 6);

			lua_pushstring(L, "Properties");
			lua_pushvalue(L, -2);
			lua_settable(L, -4);

			lua_pushstring(L, "IsPublic");
			lua_pushboolean(L, target->properties.isSet(DescriptorMemberProperties::IsPublic));
			lua_settable(L, -3);

			lua_pushstring(L, "IsEditable");
			lua_pushboolean(L, target->properties.isSet(DescriptorMemberProperties::IsEditable));
			lua_settable(L, -3);

			lua_pushstring(L, "CanReplicate");
			lua_pushboolean(L, target->properties.isSet(DescriptorMemberProperties::CanReplicate));
			lua_settable(L, -3);

			lua_pushstring(L, "CanXmlRead");
			lua_pushboolean(L, target->properties.isSet(DescriptorMemberProperties::CanXmlRead));
			lua_settable(L, -3);

			lua_pushstring(L, "CanXmlWrite");
			lua_pushboolean(L, target->properties.isSet(DescriptorMemberProperties::CanXmlWrite));
			lua_settable(L, -3);

			lua_pushstring(L, "IsScriptable");
			lua_pushboolean(L, target->properties.isSet(DescriptorMemberProperties::IsScriptable));
			lua_settable(L, -3);

			lua_pushstring(L, "AlwaysClone");
			lua_pushboolean(L, target->properties.isSet(DescriptorMemberProperties::AlwaysClone));
			lua_settable(L, -3);

			lua_pop(L, 1);
		}
	};

	auto createPropertyInfo = [](lua_State* L, void* _property)
	{
		auto property = (PropertyDescriptor*)_property;
		lua_createtable(L, 0, commonPropertiesCount + 4);

		lua_pushstring(L, "Get");
		lua_pushstring(L, Formatter::pointerToString(property->getset->get).c_str());
		lua_settable(L, -3);

		lua_pushstring(L, "Set");
		lua_pushstring(L, Formatter::pointerToString(property->getset->set).c_str());
		lua_settable(L, -3);

		lua_pushstring(L, "GetRva");
		pushRva(L, property->getset->get);
		lua_settable(L, -3);

		lua_pushstring(L, "SetRva");
		pushRva(L, property->getset->set);
		lua_settable(L, -3);
	};

	auto createEmptyInfo = [](lua_State* L, void* = nullptr) {
		lua_createtable(L, 0, commonPropertiesCount);
	};

	if (lua_isnoneornil(L, 2))
	{
		auto pushCollection = [&](auto container, void(*infoCreator)(lua_State*, void*)) {

			auto collection = container.collection;
			lua_createtable(L, (int)collection.size(), 0);

			for (auto [index, descriptor] : std::ranges::views::enumerate(collection.createViewRange()))
			{
				lua_pushstring(L, descriptor->name->c_str());
				infoCreator(L, descriptor);
				setCommonInfo(descriptor);
				lua_settable(L, -3);
			}
		};

		lua_createtable(L, 0, 5);

		lua_pushstring(L, "Property");
		pushCollection(instance->classDescriptor->properties, createPropertyInfo);
		lua_settable(L, -3);

		lua_pushstring(L, "Event");
		pushCollection(instance->classDescriptor->events, createEmptyInfo);
		lua_settable(L, -3);

		lua_pushstring(L, "Function");
		pushCollection(instance->classDescriptor->functions, createEmptyInfo);
		lua_settable(L, -3);

		lua_pushstring(L, "YieldFunction");
		pushCollection(instance->classDescriptor->yieldFunctions, createEmptyInfo);
		lua_settable(L, -3);

		lua_pushstring(L, "Callback");
		pushCollection(instance->classDescriptor->callbacks, createEmptyInfo);
		lua_settable(L, -3);
	}
	else
	{
		const char* descriptorName = luaL_checklstring(L, 2);

		if (auto property = instance->classDescriptor->properties.getDescriptor(descriptorName))
		{
			createPropertyInfo(L, property);
			setCommonInfo(property);
		}
		else if (auto event = instance->classDescriptor->events.getDescriptor(descriptorName))
		{
			createEmptyInfo(L);
			setCommonInfo(event);
		}
		else if (auto function = instance->classDescriptor->functions.getDescriptor(descriptorName))
		{
			createEmptyInfo(L);
			setCommonInfo(function);
		}
		else if (auto yieldFunction = instance->classDescriptor->yieldFunctions.getDescriptor(descriptorName))
		{
			createEmptyInfo(L);
			setCommonInfo(yieldFunction);
		}
		else if (auto callback = instance->classDescriptor->callbacks.getDescriptor(descriptorName))
		{
			createEmptyInfo(L);
			setCommonInfo(callback);
		}
		else
		{
			luaL_argerrorL(L, 2, "invalid descriptor name");
		}
	}

	return 1;
}

int carbon_getscriptcontext(lua_State* L)
{
	auto extraSpace = L->userdata;
	auto scriptContext = extraSpace->scriptContext;
	InstanceBridge_pushshared(L, scriptContext->self.lock());
	return 1;
}

int setDescriptorProperty(lua_State* L, DescriptorMemberProperties::PropertyType property)
{
	auto instance = checkInstance(L, 1);
	const char* descriptorName = luaL_checklstring(L, 2);
	bool newValue = luaL_checkboolean(L, 3);

	auto target = instance->classDescriptor->getMemberDescriptor(descriptorName);

	if (!target)
		luaL_argerrorL(L, 2, "invalid descriptor name");

	lua_pushboolean(L, target->properties.isSet(property));

	if (newValue)
		target->properties.set(property);
	else
		target->properties.clear(property);

	return 1;
}

int carbon_setscriptable(lua_State* L)
{
	return setDescriptorProperty(L, DescriptorMemberProperties::IsScriptable);
}

int carbon_debugbreak(lua_State* L)
{
	__debugbreak();
	return 0;
}

int carbon_getcfunction(lua_State* L)
{
	Closure* func = getclosure(L, 1, true);
	if (!func->isC)
		luaL_argerrorL(L, 1, "c closure expected");

	lua_pushstring(L, Formatter::pointerToString(func->c.f).c_str());
	return 1;
}

int carbon_gettt(lua_State* L)
{
	lua_pushinteger(L, luaA_toobject(L, 1)->tt);
	return 1;
}

int carbon_getgcaddr(lua_State* L)
{
	lua_pushstring(L, Formatter::pointerToString(luaA_toobject(L, -1)->value.gc).c_str());
	return 1;
}

int carbon_torva(lua_State* L)
{
	auto address = Formatter::stringToPointer(luaL_checklstring(L, 1));
	if (errno == ERANGE)
		luaL_argerrorL(L, 1, "invalid address");
	pushRva(L, address);
	return 1;
}

int carbon_getcontext(lua_State* L)
{
	lua_pushstring(L, Formatter::pointerToString(getCurrentContext()).c_str());
	return 1;
}

int carbon_repush(lua_State* L)
{
	auto instance = checkInstance(L, 1);
	InstanceBridge_pushshared(L, instance->self.lock());
	InstanceBridge_pushshared(L, instance->self.lock());
	return 2;
}

void safePush(lua_State* L, StkId v)
{
	__try
	{
		luaA_pushobject(L, v);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		lua_pushstring(L, "uninitialized");
	}
}

int carbon_dumpstacks(lua_State* L)
{
	// save previous slots because we override them in this function
	const int savedSlotsSize = 20;
	StkId savedSlots[savedSlotsSize] = { nullptr };

	int freeSlotsSize = int(L->stack_last + 1 - L->top);
	int usedSavedSlotsSize = freeSlotsSize < savedSlotsSize ? freeSlotsSize : savedSlotsSize;
	memcpy(&savedSlots, L->top, usedSavedSlotsSize * sizeof(StkId));

	lua_createtable(L, 0, 4);

	// top is not included in dump info in these lambdas
	auto pushCiStack = [&](CallInfo* base, CallInfo* top)
	{
		lua_createtable(L, int(top - base), 0);

		int index = 1;
		for (CallInfo* ci = base; ci < top; ci++)
		{
			lua_pushinteger(L, index++);

			// push call info
			{
				lua_createtable(L, 0, 3);

				lua_pushstring(L, "address");
				lua_pushstring(L, Formatter::pointerToString(ci).c_str());
				lua_settable(L, -3);

				lua_pushstring(L, "addresses");
				// push addresses
				{
					lua_createtable(L, 0, 3);

					lua_pushstring(L, "base");
					lua_pushstring(L, Formatter::pointerToString(ci->base).c_str());
					lua_settable(L, -3);

					lua_pushstring(L, "func");
					lua_pushstring(L, Formatter::pointerToString(ci->func).c_str());
					lua_settable(L, -3);

					lua_pushstring(L, "top");
					lua_pushstring(L, Formatter::pointerToString(ci->top).c_str());
					lua_settable(L, -3);
				}
				lua_settable(L, -3);

				lua_pushstring(L, "objects");
				// push objects
				{
					lua_createtable(L, 0, 3);

					if (ci->base)
					{
						lua_pushstring(L, "base");
						safePush(L, ci->base);
						lua_settable(L, -3);
					}

					if (ci->func)
					{
						lua_pushstring(L, "func");
						safePush(L, ci->func);
						lua_settable(L, -3);
					}

					if (ci->top)
					{
						lua_pushstring(L, "top");
						safePush(L, ci->top);
						lua_settable(L, -3);
					}
				}

				lua_settable(L, -3);
			}

			lua_settable(L, -3);
		}
	};

	auto pushAddress = [&](StkId v, int index)
	{
		lua_pushinteger(L, index);
		lua_pushstring(L, Formatter::pointerToString(v).c_str());
		lua_settable(L, -3);
	};

	auto pushObject = [&](StkId v, int index)
	{
		lua_pushinteger(L, index);
		safePush(L, v);
		lua_settable(L, -3);
	};
	
	auto pushStack = [&](StkId base, StkId top)
	{
		lua_createtable(L, 0, 2);

		lua_pushstring(L, "addresses");
		// push addresses
		{
			lua_createtable(L, int(top - base), 0);

			int index = 1;
			for (StkId v = base; v < top; v++)
				pushAddress(v, index++);
		}

		lua_settable(L, -3);

		lua_pushstring(L, "objects");
		// push objects
		{
			lua_createtable(L, int(top - base), 0);
			int index = 1;
			for (StkId v = base; v < top; v++)
				pushObject(v, index++);
		}

		lua_settable(L, -3);
	};

	auto pushFreeStack = [&](StkId base, StkId top)
	{
		lua_createtable(L, 0, 2);

		lua_pushstring(L, "addresses");
		// push addresses
		{
			lua_createtable(L, 0, freeSlotsSize);

			int index = 1;

			for (int i = 0; i < usedSavedSlotsSize; i++)
				pushAddress(savedSlots[i], index++);

			if (freeSlotsSize > savedSlotsSize)
			{
				for (StkId v = base + savedSlotsSize; v < top; v++)
					pushAddress(v, index++);
			}
		}

		lua_settable(L, -3);

		lua_pushstring(L, "objects");
		// push objects
		{
			lua_createtable(L, 0, freeSlotsSize);

			int index = 1;

			for (int i = 0; i < usedSavedSlotsSize; i++)
				pushObject(savedSlots[i], index++);

			if (freeSlotsSize > savedSlotsSize)
			{
				for (StkId v = base + savedSlotsSize; v < top; v++)
					pushObject(v, index++);
			}
		}

		lua_settable(L, -3);
	};

	{
		lua_pushstring(L, "ci");
		pushCiStack(L->base_ci, L->ci + 1);
		lua_settable(L, -3);
	}

	{
		lua_pushstring(L, "free_ci");
		pushCiStack(L->ci + 1, L->end_ci);
		lua_settable(L, -3);
	}

	{
		lua_pushstring(L, "stack");
		pushStack(L->stack, L->top);
		lua_settable(L, -3);
	}

	{
		lua_pushstring(L, "free_stack");
		pushFreeStack(L->top, L->stack_last + 1);
		lua_settable(L, -3);
	}

	return 1;
}