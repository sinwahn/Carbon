export module RiblixStructureOffsets;

import <stdint.h>;
import <functional>;

import RttiDescriptorContainer;
import LuauTypes;

int kInvalidOffset = -1;

RttiDescriptorContainer rttiDescriptorContainer;

using offsetPredicate = std::function<bool(uintptr_t address)>;

template<typename... Args>
int offsetFinder(uintptr_t object, int limit, int step, const offsetPredicate& predicate)
{
	for (uintptr_t currentAddress = object; currentAddress < object + limit; currentAddress += step)
	{
		if (predicate(currentAddress))
		{
			return int(currentAddress - object);
		}
	}

	return 0;
}

auto pointerToRttiNamedBySubstring = [](std::string_view pattern) -> offsetPredicate {
	return [pattern](uintptr_t address) -> bool {
		if (auto object = tryDereference(address))
			if (auto name = rttiDescriptorContainer.tryGetName(*object))
				return name->find(pattern) != std::string::npos;
		return false;
	};
};

export
{
	struct RiblixOffsets
	{
		bool initialized = false;

		void initialize(const lua_State* state)
		{
			auto extraSpace = state->userdata;

			RobloxExtraSpace.findScriptContext(extraSpace);
			auto scriptContext = tryDereference((uintptr_t)extraSpace, RobloxExtraSpace.scriptContext).value();
			
			Instance.findParent(scriptContext);
			auto dataModel = tryDereference(scriptContext, Instance.parent).value();

			Instance.findName(dataModel);
			Instance.findDescriptor(dataModel);
			Instance.findChildren(dataModel);

			initialized = true;
		}

		struct
		{
			// finds with msvc rtti
			void findDescriptor(uintptr_t someInstance)
			{
				descriptor = offsetFinder(someInstance, 0x150, 8,
					pointerToRttiNamedBySubstring("RBX::Reflection::ClassDescriptor"));
			}

			// dereference pointer on DataModel and check for "Game"
			void findName(uintptr_t dataModel)
			{
				name = offsetFinder(dataModel, 0x150, 8, [](uintptr_t address) -> bool {
					if (auto namePointer = tryDereference(address))
					{
						if (!isValidAddress(*namePointer))
							return false;

						auto name = (const char*)namePointer.value();
						return name[0] == 'G'
							&& name[1] == 'a'
							&& name[2] == 'm'
							&& name[3] == 'e';
					}
					return false;
				});
			}

			// finds with msvc rtti
			void findChildren(uintptr_t someInstance)
			{
				auto controlBlock = offsetFinder(someInstance, 0x150, 8,
					pointerToRttiNamedBySubstring("_Ref_count_obj_alloc3<std::vector<std::shared_ptr<RBX::Instance>,"));
				children = controlBlock - 8;
			}

			// finds with msvc rtti
			void findParent(uintptr_t ScriptContext)
			{
				parent = offsetFinder(ScriptContext, 0x150, 8,
					pointerToRttiNamedBySubstring("RBX::DataModel"));
			}

			int descriptor = kInvalidOffset;
			int name = kInvalidOffset;
			int children = kInvalidOffset;
			int parent = kInvalidOffset;

		} Instance;

		struct
		{
			int scriptContext = kInvalidOffset;

			// find with msvc rtti
			void findScriptContext(const struct RobloxExtraSpace* object)
			{
				scriptContext = offsetFinder((uintptr_t)object, 0x150, 8,
					pointerToRttiNamedBySubstring("RBX::ScriptContext"));
			}

		} RobloxExtraSpace;
	};

	inline RiblixOffsets riblixOffsets;
}