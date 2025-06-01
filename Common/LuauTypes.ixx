export module LuauTypes;

import <cstdint>;

export
{
	const int LUA_IDSIZE = 256; // LUA_IDSIZE gives the maximum size for the description of the source
	const int LUA_MINSTACK = 20; // LUA_MINSTACK is the guaranteed number of Lua stack slots available to a C function
	const int LUAI_MAXCSTACK = 8000; // LUAI_MAXCSTACK limits the number of Lua stack slots that a C function can use
	const int LUAI_MAXCALLS = 20000; // LUAI_MAXCALLS limits the number of nested calls
	const int LUAI_MAXCCALLS = 200; // LUAI_MAXCCALLS is the maximum depth for nested C calls; this limit depends on native stack size
	const int LUA_BUFFERSIZE = 512; // buffer size used for on-stack string operations; this limit depends on native stack size
	const int LUA_UTAG_LIMIT = 128; // number of valid Lua userdata tags
	const int LUA_LUTAG_LIMIT = 128; // number of valid Lua lightuserdata tags
	const int LUA_SIZECLASSES = 40; // upper bound for number of size classes used by page allocator
	const int LUA_MEMORY_CATEGORIES = 256; // available number of separate memory categories
	const int LUA_MINSTRTABSIZE = 32; // minimum size for the string table (must be power of 2)
	const int LUA_MAXCAPTURES = 32; // maximum number of captures supported by pattern matching
	const int LUA_VECTOR_SIZE = 3; // must be 3 or 4

	const int LUA_EXTRA_SIZE = (LUA_VECTOR_SIZE - 2);

	const int LUA_REGISTRYINDEX = (-LUAI_MAXCSTACK - 2000);
	const int LUA_ENVIRONINDEX = (-LUAI_MAXCSTACK - 2001);
	const int LUA_GLOBALSINDEX = (-LUAI_MAXCSTACK - 2002);

	const int LUA_MULTRET = -1;

	enum lua_Type
	{
		LUA_TNONE = -1,
		LUA_TNIL = 0,     // must be 0 due to lua_isnoneornil
		LUA_TBOOLEAN = 1, // must be 1 due to l_isfalse


		LUA_TLIGHTUSERDATA,
		LUA_TNUMBER,
		LUA_TVECTOR,

		LUA_TSTRING, // all types above this must be value types, all types below this must be GC types - see iscollectable


		LUA_TTABLE,
		LUA_TFUNCTION,
		LUA_TUSERDATA,
		LUA_TTHREAD,
		LUA_TBUFFER,

		// values below this line are used in GCObject tags but may never show up in TValue type tags
		LUA_TPROTO,
		LUA_TUPVAL,
		LUA_TDEADKEY,

		// the count of TValue type tags
		LUA_T_COUNT = LUA_TPROTO
	};

	enum TMS
	{
		TM_INDEX,
		TM_NEWINDEX,
		TM_MODE,
		TM_NAMECALL,
		TM_CALL,
		TM_ITER,
		TM_LEN,

		TM_EQ, // last tag method with `fast' access


		TM_ADD,
		TM_SUB,
		TM_MUL,
		TM_DIV,
		TM_IDIV,
		TM_MOD,
		TM_POW,
		TM_UNM,


		TM_LT,
		TM_LE,
		TM_CONCAT,
		TM_TYPE,
		TM_METATABLE,

		TM_N // number of elements in the enum
	};

	using lua_Number = double;
	using lua_Integer = int;
	using lua_Unsigned = unsigned;

	struct TString;
	struct stringtable
	{
		TString** hash;
		uint32_t nuse; // number of elements
		int size;
	};

	struct lua_State;
	typedef int (*lua_CFunction)(lua_State* L);
	typedef int (*lua_Continuation)(lua_State* L, int status);
	typedef void* (*lua_Alloc)(void* ud, void* ptr, size_t osize, size_t nsize);

	// type of protected functions, to be ran by `runprotected'
	typedef void (*Pfunc)(lua_State* L, void* ud);

	struct luaL_Reg
	{
		const char* name;
		lua_CFunction func;
	};

	union L_Umaxalign
	{
		double u;
		void* s;
		long l;
	};

	struct Proto;

	struct lua_ExecutionCallbacks
	{
		void* context;
		void (*close)(lua_State* L);                 // called when global VM state is closed
		void (*destroy)(lua_State* L, Proto* proto); // called when function is destroyed
		int (*enter)(lua_State* L, Proto* proto);    // called when function is about to start/resume (when execdata is present), return 0 to exit VM
		void (*disable)(lua_State* L, Proto* proto); // called when function has to be switched from native to bytecode in the debugger
		size_t(*getmemorysize)(lua_State* L, Proto* proto); // called to request the size of memory associated with native part of the Proto
	};

	struct lua_Debug
	{
		const char* name;      // (n)
		const char* what;      // (s) `Lua', `C', `main', `tail'
		const char* source;    // (s)
		const char* short_src; // (s)
		int linedefined;       // (s)
		int currentline;       // (l)
		unsigned char nupvals; // (u) number of upvalues
		unsigned char nparams; // (a) number of parameters
		char isvararg;         // (a)
		void* userdata;        // only valid in luau_callhook

		char ssbuf[LUA_IDSIZE];
	};

	struct lua_Callbacks
	{
		void* userdata; // arbitrary userdata pointer that is never overwritten by Luau

		void (*interrupt)(lua_State* L, int gc);  // gets called at safepoints (loop back edges, call/ret, gc) if set
		void (*panic)(lua_State* L, int errcode); // gets called when an unprotected error is raised (if longjmp is used)

		void (*userthread)(lua_State* LP, lua_State* L); // gets called when L is created (LP == parent) or destroyed (LP == NULL)
		int16_t(*useratom)(const char* s, size_t l);    // gets called when a string is created; returned atom can be retrieved via tostringatom

		void (*debugbreak)(lua_State* L, lua_Debug* ar);     // gets called when BREAK instruction is encountered
		void (*debugstep)(lua_State* L, lua_Debug* ar);      // gets called after each instruction in single step mode
		void (*debuginterrupt)(lua_State* L, lua_Debug* ar); // gets called when thread execution is interrupted by break in another thread
		void (*debugprotectederror)(lua_State* L);           // gets called when protected call results in an error
	};

	struct GCStats
	{
		// data for proportional-integral controller of heap trigger value
		int32_t triggerterms[32] = { 0 };
		uint32_t triggertermpos = 0;
		int32_t triggerintegral = 0;

		size_t atomicstarttotalsizebytes = 0;
		size_t endtotalsizebytes = 0;
		size_t heapgoalsizebytes = 0;

		double starttimestamp = 0;
		double atomicstarttimestamp = 0;
		double endtimestamp = 0;
	};

#define CommonHeader \
		uint8_t tt; uint8_t marked; uint8_t memcat

	struct GCheader
	{
		CommonHeader;
	};

	union GCObject;

	union Value
	{
		GCObject* gc;
		void* p;
		double n;
		int b;
		float v[2]; // v[0], v[1] live here; v[2] lives in TValue::extra
	};

	struct TValue
	{
		Value value;
		int extra[LUA_EXTRA_SIZE];
		int tt;
	};

	struct UpVal
	{
		CommonHeader;
		uint8_t markedopen; // set if reachable from an alive thread (only valid during atomic)

		// 4 byte padding (x64)

		TValue* v; // points to stack or to its own value
		union
		{
			TValue value; // the value (when closed)
			struct
			{
				// global double linked list (when open)
				struct UpVal* prev;
				struct UpVal* next;

				// thread linked list (when open)
				struct UpVal* threadnext;
			} open;
		} u;

		static bool isopen(UpVal* up)
		{
			return (up)->v != &(up)->u.value;
		}
	};

#define bitmask(b) (1 << (b))
#define bit2mask(b1, b2) (bitmask(b1) | bitmask(b2))

#define WHITE0BIT 0
#define WHITE1BIT 1
#define BLACKBIT 2
#define FIXEDBIT 3
#define WHITEBITS bit2mask(WHITE0BIT, WHITE1BIT)


	struct lua_Page
	{
		// list of pages with free blocks
		lua_Page* prev;
		lua_Page* next;

		// list of all pages
		lua_Page* listprev;
		lua_Page* listnext;

		int pageSize;  // page size in bytes, including page header
		int blockSize; // block size in bytes, including block header (for non-GCO)

		void* freeList; // next free block in this page; linked with metadata()/freegcolink()
		int freeNext;   // next free block offset in this page, in bytes; when negative, freeList is used instead
		int busyBlocks; // number of blocks allocated out of this page

		// provide additional padding based on current object size to provide 16 byte alignment of data
		// later static_assert checks that this requirement is held
		char padding[sizeof(void*) == 8 ? 8 : 12];

		char data[1];
	};

	struct global_State
	{
		stringtable strt; // hash table for strings

		lua_Alloc frealloc;   // function to reallocate memory
		void* ud;            // auxiliary data to `frealloc'

		uint8_t currentwhite;
		uint8_t gcstate; // state of garbage collector

		GCObject* gray;      // list of gray objects
		GCObject* grayagain; // list of objects to be traversed atomically
		GCObject* weak;     // list of weak tables (to be cleared)

		size_t GCthreshold;                       // when totalbytes > GCthreshold, run GC step
		size_t totalbytes;                        // number of bytes currently allocated
		int gcgoal;                               // see LUAI_GCGOAL
		int gcstepmul;                            // see LUAI_GCSTEPMUL
		int gcstepsize;                          // see LUAI_GCSTEPSIZE

		struct lua_Page* freepages[LUA_SIZECLASSES]; // free page linked list for each size class for non-collectable objects
		struct lua_Page* freegcopages[LUA_SIZECLASSES]; // free page linked list for each size class for collectable objects
		struct lua_Page* allpages; // page linked list with all pages for all non-collectable object classes (available with LUAU_ASSERTENABLED)
		struct lua_Page* allgcopages; // page linked list with all pages for all collectable object classes
		struct lua_Page* sweepgcopage; // position of the sweep in `allgcopages'

		size_t memcatbytes[LUA_MEMORY_CATEGORIES]; // total amount of memory used by each memory category


		struct lua_State* mainthread;
		UpVal uvhead;                                    // head of double-linked list of all open upvalues
		struct LuaTable* mt[LUA_T_COUNT];                   // metatables for basic types
		TString* ttname[LUA_T_COUNT];       // names for basic types
		TString* tmname[TM_N];             // array with tag-method names

		TValue pseudotemp; // storage for temporary values used in pseudo2addr

		TValue registry; // registry table, used by lua_ref and LUA_REGISTRYINDEX
		int registryfree; // next free slot in registry

		struct lua_jmpbuf* errorjmp; // jump buffer data for longjmp-style error handling

		uint64_t rngstate; // PCG random number generator state
		uint64_t ptrenckey[4]; // pointer encoding key for display

		lua_Callbacks cb;

		lua_ExecutionCallbacks ecb;

		void (*udatagc[LUA_UTAG_LIMIT])(lua_State*, void*); // for each userdata tag, a gc callback to be called immediately before freeing memory
		LuaTable* udatamt[LUA_UTAG_LIMIT]; // metatables for tagged userdata

		TString* lightuserdataname[LUA_LUTAG_LIMIT]; // names for tagged lightuserdata

		GCStats gcstats;

#ifdef LUAI_GCMETRICS
		GCMetrics gcmetrics;
#endif

		bool isdead(GCObject* o);
		uint8_t otherwhite() { return currentwhite ^ WHITEBITS; }
	};

	using StkId = TValue*; // index to stack elements
	using Instruction = uint32_t;

	struct CallInfo
	{
		StkId base;    // base for this function
		StkId func;    // function index in the stack
		StkId top;     // top for this function
		const Instruction* savedpc;

		int nresults;       // expected number of results from this function
		unsigned int flags; // call frame flags, see LUA_CALLINFO_*
	};

	/*
	** `per thread' state
	*/
	// clang-format off
	struct lua_State
	{
		CommonHeader;
		uint8_t status;

		uint8_t activememcat; // memory category that is used for new GC object allocations

		bool isactive;   // thread is currently executing, stack may be mutated without barriers
		bool singlestep; // call debugstep hook after each instruction

		StkId top;                                        // first free slot in the stack
		StkId base;                                       // base of current function
		global_State* global;
		CallInfo* ci;                                     // call info for current function
		StkId stack_last;                                 // last free slot in the stack
		StkId stack;                                     // stack base

		CallInfo* end_ci;                          // points after end of ci array
		CallInfo* base_ci;                        // array of CallInfo's

		int stacksize;
		int size_ci;                              // size of array `base_ci'

		unsigned short nCcalls;     // number of nested C calls
		unsigned short baseCcalls; // nested C calls when resuming coroutine

		int cachedslot;    // when table operations or INDEX/NEWINDEX is invoked from Luau, what is the expected slot for lookup?

		struct Table* gt;           // table of globals
		struct UpVal* openupval;    // list of open upvalues in this stack
		union GCObject* gclist;

		TString* namecall; // when invoked from Luau using NAMECALL, what method do we need to invoke?

		struct RobloxExtraSpace* userdata;
	};

	struct TString
	{
		CommonHeader;

		// 1 byte padding
		int16_t atom;

		// 2 byte padding
		TString* next; // next string in the hash table bucket

		unsigned int hash;
		unsigned int len;

		char data[1]; // string data is allocated right after the header
	};


	typedef struct Udata
	{
		CommonHeader;

		uint8_t tag;
		int len;
		struct Table* metatable;

		union
		{
			char data[1];      // userdata is allocated right after the header
			L_Umaxalign dummy; // ensures maximum alignment for data
		};
	} Udata;

	typedef struct Buffer
	{
		CommonHeader;

		unsigned int len;
		union
		{
			char data[1];      // buffer is allocated right after the header
			L_Umaxalign dummy; // ensures maximum alignment for data
		};
	} Buffer;

	struct Proto
	{
		CommonHeader;

		uint8_t nups; // number of upvalues
		uint8_t numparams;
		uint8_t is_vararg;
		uint8_t maxstacksize;
		uint8_t flags;


		TValue* k;              // constants used by the function
		Instruction* code;      // function bytecode
		struct Proto** p;       // functions defined inside the function
		const Instruction* codeentry;

		void* execdata;
		uintptr_t exectarget;


		uint8_t* lineinfo;      // for each instruction, line number as a delta from baseline
		int* abslineinfo;       // baseline line info, one entry for each 1<<linegaplog2 instructions; allocated after lineinfo
		struct LocVar* locvars; // information about local variables
		TString** upvalues;     // upvalue names
		TString* source;

		TString* debugname;
		uint8_t* debuginsn; // a copy of code[] array with just opcodes

		uint8_t* typeinfo;

		void* userdata;

		GCObject* gclist;


		int sizecode;
		int sizep;
		int sizelocvars;
		int sizeupvalues;
		int sizek;
		int sizelineinfo;
		int linegaplog2;
		int linedefined;
		int bytecodeid;
		int sizetypeinfo;
	};

	// clang-format on

	struct LocVar
	{
		TString* varname;
		int startpc; // first point where variable is active
		int endpc;   // first point where variable is dead
		uint8_t reg; // register slot, relative to base, where variable is stored
	};

	struct Closure
	{
		CommonHeader;

		uint8_t isC;
		uint8_t nupvalues;
		uint8_t stacksize;
		uint8_t preload;

		GCObject* gclist;
		struct Table* env;

		union
		{
			struct
			{
				lua_CFunction f;
				lua_Continuation cont;
				const char* debugname;
				TValue upvals[1];
			} c;

			struct
			{
				Proto* p;
				TValue uprefs[1];
			} l;
		};
	};

	struct TKey
	{
		::Value value;
		int extra[LUA_EXTRA_SIZE];
		unsigned tt : 4;
		int next : 28; // for chaining
	};

	struct LuaNode
	{
		TValue val;
		TKey key;
	};

	struct Table
	{
		CommonHeader;

		uint8_t tmcache;    // 1<<p means tagmethod(p) is not present
		uint8_t readonly;   // sandboxing feature to prohibit writes to table
		uint8_t safeenv;    // environment doesn't share globals with other scripts
		uint8_t lsizenode;  // log2 of size of `node' array
		uint8_t nodemask8; // (1<<lsizenode)-1, truncated to 8 bits

		int sizearray; // size of `array' array
		union
		{
			int lastfree;  // any free position is before this position
			int aboundary; // negated 'boundary' of `array' array; iff aboundary < 0
		};

		struct Table* metatable;
		TValue* array;  // array part
		LuaNode* node;
		GCObject* gclist;
	};

	union GCObject
	{
		GCheader gch;
		TString ts;
		Udata u;
		Closure cl;
		Table h;
		Proto p;
		UpVal uv;
		lua_State th; // thread
		Buffer buf;
	};

	bool global_State::isdead(GCObject* o)
	{
		return ((o->gch.marked & (WHITEBITS | bitmask(FIXEDBIT))) == (otherwhite() & WHITEBITS));
	}
}