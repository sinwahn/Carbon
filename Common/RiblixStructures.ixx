export module RiblixStructures;

import <string>;
import <vector>;
import <memory>;

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
		size_t _1;
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
			void* _1;
			void* set;
			void* _2;
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
		std::vector<Member*> collection;
		char __pad[168 - sizeof(collection)];

		Member* getDescriptor(const char* name) const
		{
			for (auto member : collection)
				if (*member->name == name)
					return member;
			return nullptr;
		}
	};

	struct __declspec(novtable) ClassDescriptor
		: public Descriptor
		, public MemberDescriptorContainer<PropertyDescriptor>
		, public MemberDescriptorContainer<EventDescriptor>
		, public MemberDescriptorContainer<FunctionDescriptor>
		, public MemberDescriptorContainer<YieldFunctionDescriptor>
		, public MemberDescriptorContainer<CallbackDescriptor>
	{
		void* _1;
		void* _2;
		unsigned _3 : 4;
		unsigned isScriptable : 1;

		MemberDescriptor* getMemberDescriptor(const char* name) const
		{
			if (auto property = MemberDescriptorContainer<PropertyDescriptor>::getDescriptor(name))
				return property;
			else if (auto event = MemberDescriptorContainer<EventDescriptor>::getDescriptor(name))
				return event;
			else if (auto function = MemberDescriptorContainer<FunctionDescriptor>::getDescriptor(name))
				return function;
			else if (auto yieldFunction = MemberDescriptorContainer<YieldFunctionDescriptor>::getDescriptor(name))
				return yieldFunction;
			else if (auto callback = MemberDescriptorContainer<CallbackDescriptor>::getDescriptor(name))
				return callback;

			return nullptr;
		}
	};

	class Capabilities
	{
	public:
		enum CapabilityType : uint32_t {
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
			SpecialCapability = 1ULL << 15,
			AssetRequire = 1ULL << 16,
			LoadString = 1ULL << 17,
			ScriptGlobals = 1ULL << 18,
			CreateInstances = 1ULL << 19,
			Basic = 1ULL << 20,
			Audio = 1ULL << 21,
			DataStore = 1ULL << 22,
			Network = 1ULL << 23,
			Physics = 1ULL << 24,

			// TODO: capabilities are not inherited, find something better
			Dummy = 1ULL << 25, // use this one as our thread marking

			OurThread = Dummy,
			All = Plugin
			| LocalUser
			| WritePlayer
			| RobloxScript
			| RobloxEngine
			| NotAccessible
			| RunClientScript
			| RunServerScript
			| AccessOutsideWrite
			| SpecialCapability
			| AssetRequire
			| LoadString
			| ScriptGlobals
			| CreateInstances
			| Basic
			| Audio
			| DataStore
			| Network
			| Physics,
		};

		void set(CapabilityType capability) { bitfield |= capability; }
		void clear(CapabilityType capability) { bitfield &= ~capability; }
		bool isSet(CapabilityType capability) const { return bitfield & capability; }

		uint32_t bitfield;
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

	struct __declspec(novtable) OnDemandInstance
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

	struct __declspec(novtable) Instance
	{
		/*  0*/ void* vftable;
		/*  8*/ msvc_weak_ptr<Instance> self;
		/* 24*/ ClassDescriptor* classDescriptor;
		/* 32*/ int _1[2];
		/* 40*/ bool isArchivable;
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
		/* 144*/ OnDemandInstance* _8;

		std::string getClassName()
		{
			return *classDescriptor->name;
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

	struct DataModel
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