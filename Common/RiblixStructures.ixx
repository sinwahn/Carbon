export module RiblixStructures;

import <string>;
import <vector>;
import <memory>;
import <span>;
import RiblixStructureOffsets;

export
{
	struct msvc_string
	{
		bool isLarge() const { return myCapacity > smallStringCapacity; }
		const char* c_str() const { return isLarge() ? largeBuffer : buffer; }
		size_t size() const { return mySize; }
		size_t capacity() const { return myCapacity; }

		operator std::string() const
		{
			std::string result;
			result.resize(size());
			memcpy(result.data(), c_str(), mySize);
			return result;
		}

		bool operator ==(const char* other) const
		{
			return memcmp(c_str(), other, mySize);
		}

	private:

		static constexpr int bufferSize = 16;
		static constexpr int smallStringCapacity = bufferSize - 1;

		union {
			char* largeBuffer;
			char buffer[bufferSize];
		};

		size_t mySize;
		size_t myCapacity;
	};

	template<typename value_type>
	struct msvc_vector
	{
		value_type* first;
		value_type* last;
		value_type* limit;

		bool empty() const { return first == last; }
		size_t size() const { return last - first; }

		template<typename value_type>
		struct vector_iterator
		{
			using difference_type = ptrdiff_t;
			using pointer = value_type*;
			using reference = value_type&;

			vector_iterator(pointer ptr) : ptr(ptr) {}

			reference operator*() const { return *ptr; }
			pointer operator->() { return ptr; }

			vector_iterator& operator++()noexcept
			{
				++ptr;
				return *this;
			}

			vector_iterator operator++(int)noexcept
			{
				vector_iterator tmp = *this;
				++(*this);
				return tmp;
			}

			vector_iterator& operator--()noexcept
			{
				--ptr;
				return *this;
			}

			vector_iterator operator--(int)noexcept
			{
				vector_iterator tmp = *this;
				--(*this);
				return tmp;
			}

			bool operator==(const vector_iterator& other)noexcept { return ptr == other.ptr; }
			bool operator!=(const vector_iterator& other) noexcept { return ptr != other.ptr; }
			bool operator<(const vector_iterator& other) noexcept { return ptr < other.ptr; }
			bool operator<=(const vector_iterator& other)noexcept { return ptr <= other.ptr; }
			bool operator>(const vector_iterator& other) noexcept { return ptr > other.ptr; }
			bool operator>=(const vector_iterator& other) noexcept { return ptr >= other.ptr; }

			vector_iterator operator+(difference_type n) const noexcept { return vector_iterator(ptr + n); }
			vector_iterator& operator+=(difference_type n) {
				ptr += n;
				return *this;
			}

			vector_iterator operator-(difference_type n) const noexcept { return vector_iterator(ptr - n); }
			vector_iterator& operator-=(difference_type n) {
				ptr -= n;
				return *this;
			}

			difference_type operator-(const vector_iterator& other) const noexcept { return ptr - other.ptr; }

			reference operator[](difference_type n) const noexcept { return ptr[n]; }

			pointer ptr;
		};

		using iterator = vector_iterator<value_type>;
		using const_iterator = vector_iterator<const value_type>;

		iterator begin() noexcept { return iterator(first); }
		iterator end() noexcept { return iterator(last); }
		const_iterator begin() const noexcept { return const_iterator(first); }
		const_iterator end() const noexcept { return const_iterator(last); }
		const_iterator cbegin() const noexcept { return const_iterator(first); }
		const_iterator cend() const noexcept { return const_iterator(last); }

		std::span<value_type> createViewRange()
		{
			return std::span<value_type>(first, last);
		}

	};


	template<typename T>
	struct msvc_Ref_count_base;

	template<typename T>
	struct msvc_weak_ptr;

	template<typename T>
	struct msvc_shared_ptr
	{
		T* object;
		msvc_Ref_count_base<T>* controlBlock;

		T& operator*() const { return *object; }
		T* operator->() const { return object; }

		T* get() const { return object; }

		bool constructFromWeak(const msvc_weak_ptr<T>& other);
	};

	template<typename T>
	struct msvc_Ref_count_base
	{
		void* vftable;
		unsigned long uses;
		unsigned long weaks;

		bool incrementRefsNotZero()
		{
			if (uses > 0)
			{
				uses++;
				return true;
			}

			return false;
		}
	};

	template<typename T>
	struct msvc_weak_ptr
	{
		T* object; // nullptr if deleted
		msvc_Ref_count_base<T>* controlBlock;

		msvc_shared_ptr<T> lock()
		{
			msvc_shared_ptr<T> result;
			result.constructFromWeak(*this);
			return result;
		}

		bool expired() const { return controlBlock ? controlBlock->uses == 0 : true; }
	};

	template<typename T>
	bool msvc_shared_ptr<T>::constructFromWeak(const msvc_weak_ptr<T>& other)
	{
		if (other.controlBlock && other.controlBlock->incrementRefsNotZero())
		{
			object = other.object;
			controlBlock = other.controlBlock;
			return true;
		}

		return false;
	}

	struct __declspec(novtable) Descriptor
	{
		void* vftable;
		const msvc_string* name;
		void* _1;
		size_t _2;
		size_t _3;
	};

	class DescriptorMemberProperties
	{
	public:
		enum PropertyType : uint32_t {
			IsPublic = 1ULL << 0,
			IsEditable = 1ULL << 1,
			CanReplicate = 1ULL << 2,
			CanXmlRead = 1ULL << 3,
			CanXmlWrite = 1ULL << 4,
			IsScriptable = 1ULL << 5,
			AlwaysClone = 1ULL << 6,
		};

		void set(PropertyType property) { bitfield |= property; }
		void clear(PropertyType property) { bitfield &= ~property; }
		bool isSet(PropertyType property) const { return bitfield & property; }

		uint32_t bitfield;
	};

	struct __declspec(novtable) MemberDescriptor : public Descriptor
	{
		const msvc_string* category;
		struct ClassDescriptor* owner;
		void* _1;
		DescriptorMemberProperties properties;
		int _2;
		void* TType;
		void* _3;
		void* _4;
		void* _5;
		void* _6;
		void* _7;
		void* _8;
	};

	struct __declspec(novtable) PropertyDescriptor : public MemberDescriptor
	{
		struct GetSet {
			void* vftable;
			void* get;
			void* set;
		} *getset;
	};

	struct __declspec(novtable) EventDescriptor : public MemberDescriptor
	{

	};

	struct __declspec(novtable) FunctionDescriptor : public MemberDescriptor
	{
		void* _1;
		void* _2;
		void** _vftable; // ? array of functions
		void* function; //?
	};

	struct __declspec(novtable) YieldFunctionDescriptor : public MemberDescriptor
	{
		void* _1;
		void* _2;
		void** _3; //?
		void* function; //?
	};

	struct __declspec(novtable) CallbackDescriptor : public MemberDescriptor
	{

	};

	template <typename Member>
	struct __declspec(novtable) MemberDescriptorContainer
	{
		msvc_vector<Member*> collection;
		char __pad[168 - sizeof(collection)];

		Member* getDescriptor(const char* name) const
		{
			for (auto member : collection)
				if (*member->name == name)
					return member;
			return nullptr;
		}

		MemberDescriptorContainer<MemberDescriptor>& toBase()
		{
			using base = MemberDescriptorContainer<MemberDescriptor>;
			return *reinterpret_cast<base*>(this);
		}
	};

	struct __declspec(novtable) ClassDescriptor
		: public Descriptor
	{
		MemberDescriptorContainer<PropertyDescriptor> properties;
		MemberDescriptorContainer<EventDescriptor> events;
		MemberDescriptorContainer<FunctionDescriptor> functions;
		MemberDescriptorContainer<YieldFunctionDescriptor> yieldFunctions;
		MemberDescriptorContainer<CallbackDescriptor> callbacks;

		void* _1;
		void* _2;
		unsigned _3 : 4;
		unsigned isScriptable : 1;

		MemberDescriptor* getMemberDescriptor(const char* name) const
		{
			if (auto property = properties.getDescriptor(name))
				return property;
			else if (auto event = events.getDescriptor(name))
				return event;
			else if (auto function = functions.getDescriptor(name))
				return function;
			else if (auto yieldFunction = yieldFunctions.getDescriptor(name))
				return yieldFunction;
			else if (auto callback = callbacks.getDescriptor(name))
				return callback;

			return nullptr;
		}
	};

	class Capabilities
	{
	public:
		enum CapabilityType : uint64_t {
			Restricted = 0,
			Plugin = 1ULL << 0,
			LocalUser = 1ULL << 1,
			WritePlayer = 1ULL << 2,
			RobloxScript = 1ULL << 3,
			RobloxEngine = 1ULL << 4,
			NotAccessible = 1ULL << 5,

			RunClientScript = 1ULL << 8,
			RunServerScript = 1ULL << 9,
			AccessOutsideWrite = 1ULL << 11,

			Unassigned = 1ULL << 15,
			AssetRequire = 1ULL << 16,
			LoadString = 1ULL << 17,
			ScriptGlobals = 1ULL << 18,
			CreateInstances = 1ULL << 19,
			Basic = 1ULL << 20,
			Audio = 1ULL << 21,
			DataStore = 1ULL << 22,
			Network = 1ULL << 23,
			Physics = 1ULL << 24,
			UI = 1ULL << 25,
			CSG = 1ULL << 26,
			Chat = 1ULL << 27,
			Animation = 1ULL << 28,
			Avatar = 1ULL << 29,
			Input = 1ULL << 30,
			Environment = 1ULL << 31,
			RemoteEvent = 1ULL << 32,
			LegacySound = 1ULL << 33,
			Players = 1ULL << 34,
			CapabilityControl = 1ULL << 35,

			OurThread = 1ULL << 42,

			InternalTest = 1ULL << 60,
			PluginOrOpenCloud = 1ULL << 61,
			Assistant = 1ULL << 62,
			Unknown = 1ULL << 63,

			All = Plugin | LocalUser | WritePlayer | RobloxScript
				| RobloxEngine | NotAccessible | RunClientScript
				| RunServerScript | AccessOutsideWrite | Unassigned
				| AssetRequire | LoadString | ScriptGlobals | CreateInstances
				| Basic | Audio | DataStore | Network | Physics | UI
				| CSG | Chat | Animation | Avatar | Input | Environment
				| RemoteEvent | LegacySound | Players | CapabilityControl
				| InternalTest | PluginOrOpenCloud | Assistant
		};

		void set(CapabilityType capability) { bitfield |= (uint64_t)capability; }
		void clear(CapabilityType capability) { bitfield &= ~(uint64_t)capability; }
		bool isSet(CapabilityType capability) const { return bitfield & (uint64_t)capability; }

		uint64_t bitfield;
	};


	struct WeakObjectRef
	{
		void* vftable;
	};

	struct WeakThreadRef
	{
		void* vftable;
	};

	struct FunctionScriptSlot
	{
		void* vftable;
		msvc_weak_ptr<FunctionScriptSlot> self;
		void* _1;
		msvc_string* name;
		void* _3;
		void* _4;
		size_t _5;
		struct Instance* scriptContext;
		void* _6;
		void* _7;
		WeakThreadRef* thread;
		WeakObjectRef* object;
	};

	struct Connection
	{
		int _1;
		int _2;
		void* someFunc;
		Connection* next;
		int* someFlags;
		struct Signal* signal;
		void* someFunc2;
		msvc_shared_ptr<FunctionScriptSlot> scriptSlot;
		int _3;
		int _4;
		int _5;
		Capabilities _6; // not sure, EE 03 flashbacks
	};

	struct Signal
	{
		int _1;
		int size;
		Connection* head;
	};

	struct OnDemandInstance
	{
		void* _1;
		Signal* childAdded;
		Signal* childRemoved;
		char _2[280 - 8 * 3];
		Capabilities definesCapabilities;
		// 272 - SourceAssetId
		// 312 - ReplicatedGuiInsertionOrder
		// 208 - Tags*?
	};

	struct _OldInstance
	{
		/*  0*/ void* vftable;
		/*  8*/ msvc_weak_ptr<Instance> self;
		/* 24*/ ClassDescriptor* classDescriptor;
		/* 32*/ int _1[2];
		/* 40*/ bool isArchivable;
		/* 48*/ OnDemandInstance* _8;
		/* 56*/ int _2[4];
		/* 60*/ int debugId;
		/* 64*/ bool isParentLocked;
		/* 65*/ bool _3;
		/* 66*/ bool _4;
		/* 67*/ bool sandboxed;
		/* 72*/ const char* name;
		/* 80*/ msvc_shared_ptr<msvc_vector<msvc_shared_ptr<Instance>>> children;
		/* 96*/ Instance* parent;
		/* 104*/ struct {
			size_t uniqueId;
			size_t _1;
			size_t historyId;
		} *history;
		/* 112*/ int _6[2];
		/* 128*/ int numExpectedChildren;
		/* 132*/ int _7[3];
	};

	struct Address
	{
		uintptr_t getAddress() const { return (uintptr_t)this; }
		uintptr_t getAddress(int offset) const {
			return (uintptr_t)this + offset;
		}
	};

	struct Instance : Address
	{
		msvc_weak_ptr<Instance>& getSelf() {
			return *reinterpret_cast<msvc_weak_ptr<Instance>*>(uintptr_t(this) + 0x8);
		}

		std::string getClassName() const {
			return *getDescriptor()->name;
		}

		ClassDescriptor* getDescriptor() const {
			return *(ClassDescriptor**)(getAddress(riblixOffsets.Instance.descriptor));
		}

		const char* getName() const {
			return (const char*)(getAddress(riblixOffsets.Instance.name));
		}

		using children_t = msvc_shared_ptr<msvc_vector<msvc_shared_ptr<Instance>>>;
		children_t& getChildren() const {
			return *(children_t*)(getAddress(riblixOffsets.Instance.children));
		}

		Instance* getParent() const {
			return *(Instance**)(getAddress(riblixOffsets.Instance.parent));
		}
	};

	struct RobloxExtraSpace
	{
		// intrusive set stuff
		RobloxExtraSpace* _1;
		void* _2;
		RobloxExtraSpace* _3;
		void* _4;
		void* ref_count_shared;
		void* _5;
		int identity;
		int _6;
		void* _7;

		Instance* scriptContext;
		Capabilities capabilities;
		uint32_t _8;
		Instance* script;
		void* ref_count_script;

		Instance* getScriptContext() {
			return (Instance*)(getAddress(riblixOffsets.RobloxExtraSpace.scriptContext));
		}

		//Instance* getScript() {
		//	return (Instance*)(getAddress(riblixOffsets.RobloxExtraSpace.script));
		//}
	};

	struct Context
	{
		int identity;
		void* _1;
		void* _2;
		struct lua_State* _3;
		Capabilities capabilities;
		void* capabilitiesGetter;
	};

	struct ProtoExtraSpace
	{
		Capabilities capabilities;
		int _1;
		size_t _2;
	};

	using DataModel = Instance;

	// TODO: insanely unreliable
	struct DataModel_
	{
		Instance* toInstance()
		{
			auto address = (uintptr_t)this + 0x190;
			return (Instance*)address;
		}

		const Instance* toInstance() const
		{
			auto address = (uintptr_t)this + 0x190;
			return (Instance*)address;
		}

		static DataModel* toDataModel(Instance* self)
		{
			auto address = (uintptr_t)self - 0x190;
			return (DataModel*)address;
		}
	};
}