typedef signed char        int8_t;
typedef short              int16_t;
typedef int                int32_t;
typedef long long          int64_t;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
typedef unsigned __int64  uintptr_t;

typedef double L_Umaxalign;
struct GCObject
{
    uint8_t tt; uint8_t marked; uint8_t memcat;
    char _[168];
};

struct TString
{
    uint8_t tt; uint8_t marked; uint8_t memcat;
    // 1 byte padding

    int16_t atom;

    // 2 byte padding

    TString* next; // next string in the hash table bucket

    unsigned int hash;
    unsigned int len;

    char data[1]; // string data is allocated right after the header
};


typedef uint32_t Instruction;

struct Udata
{
    uint8_t tt; uint8_t marked; uint8_t memcat;
    uint8_t tag;
    int len;
    struct Table* metatable;
    union
    {
        char data[1];      // userdata is allocated right after the header
        L_Umaxalign dummy; // ensures maximum alignment for data
    };
};

struct Buffer
{
    uint8_t tt; uint8_t marked; uint8_t memcat;

    unsigned int len;

    union
    {
        char data[1];      // buffer is allocated right after the header
        L_Umaxalign dummy; // ensures maximum alignment for data
    };
};

union Value
{
    void* gc;
    void* p;
    double n;
    int b;
    float v[2]; // v[0], v[1] live here; v[2] lives in TValue::extra
};

struct TValue
{
    Value value;
    int extra[1];
    int tt;
};

typedef TValue* StkId;

struct TKey
{
    Value value;
    int extra[1];
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
    uint8_t tt; uint8_t marked; uint8_t memcat;

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
    void* gclist;
};

struct UpVal
{
    uint8_t tt; uint8_t marked; uint8_t memcat;
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
};

struct Proto
{
    uint8_t tt; uint8_t marked; uint8_t memcat;


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
    void* locvars; // information about local variables
    TString** upvalues;     // upvalue names
    TString* source;

    TString* debugname;
    uint8_t* debuginsn; // a copy of code[] array with just opcodes

    uint8_t* typeinfo;

    void* userdata;

    void* gclist;


    int sizecode;
    int sizep;
    int sizelocvars;
    int sizeupvalues;
    int sizek;
    int sizelineinfo;
    int linegaplog2;
    int linedefined;
    int bytecodeid;
};

struct CallInfo
{

    StkId base;    // base for this function
    StkId func;    // function index in the stack
    StkId top;     // top for this function
    const Instruction* savedpc;

    int nresults;       // expected number of results from this function
    unsigned int flags; // call frame flags, see LUA_CALLINFO_*
};

struct lua_State
{
    uint8_t tt; uint8_t marked; uint8_t memcat;
    uint8_t status;

    uint8_t activememcat; // memory category that is used for new GC object allocations

    bool isactive;   // thread is currently executing, stack may be mutated without barriers
    bool singlestep; // call debugstep hook after each instruction


    StkId top;                                        // first free slot in the stack
    StkId base;                                       // base of current function
    struct global_State* global;
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


    Table* gt;           // table of globals
    UpVal* openupval;    // list of open upvalues in this stack
    GCObject* gclist;

    TString* namecall; // when invoked from Luau using NAMECALL, what method do we need to invoke?

    void* userdata;
};

typedef int (*lua_CFunction)(lua_State* L);
typedef int (*lua_Continuation)(lua_State* L, int status);

struct Closure
{
    uint8_t tt; uint8_t marked; uint8_t memcat;

    uint8_t isC;
    uint8_t nupvalues;
    uint8_t stacksize;
    uint8_t preload;

    void* gclist;
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
            struct Proto* p;
            TValue uprefs[1];
        } l;
    };
};

struct stringtable
{
    TString** hash;
    uint32_t nuse; // number of elements
    int size;
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

    char ssbuf[256];
};

typedef void (*lua_InterruptFn)(lua_State* L, int gc);
typedef void (*lua_PanicFn)(lua_State* L, int errcode);
typedef void (*lua_UserThreadFn)(lua_State* LP, lua_State* L);
typedef int16_t (*lua_UserAtomFn)(const char* s, size_t l);
typedef void (*lua_DebugFn)(lua_State* L, lua_Debug* ar);
typedef void (*lua_ProtectedErrorFn)(lua_State* L);
typedef void (*lua_OnAllocateFn)(lua_State* L, size_t osize, size_t nsize);

struct lua_Callbacks {
    void* userdata;
    lua_InterruptFn interrupt;
    lua_PanicFn panic;
    lua_UserThreadFn userthread;
    lua_UserAtomFn useratom;
    lua_DebugFn debugbreak;
    lua_DebugFn debugstep;
    lua_DebugFn debuginterrupt;
    lua_ProtectedErrorFn debugprotectederror;
    lua_OnAllocateFn onallocate;
};

typedef void* (*lua_Alloc)(void* ud, void* ptr, size_t osize, size_t nsize);

struct lua_ExecutionCallbacks
{
    void* context;
    void (*close)(lua_State* L);                 // called when global VM state is closed
    void (*destroy)(lua_State* L, Proto* proto); // called when function is destroyed
    int (*enter)(lua_State* L, Proto* proto);    // called when function is about to start/resume (when execdata is present), return 0 to exit VM
    void (*disable)(lua_State* L, Proto* proto); // called when function has to be switched from native to bytecode in the debugger
    size_t(*getmemorysize)(lua_State* L, Proto* proto); // called to request the size of memory associated with native part of the Proto
    uint8_t(*gettypemapping)(lua_State* L, const char* str, size_t len); // called to get the userdata type index
};

struct GCStats
{
    // data for proportional-integral controller of heap trigger value
    int32_t triggerterms[32];
    uint32_t triggertermpos;
    int32_t triggerintegral;

    size_t atomicstarttotalsizebytes;
    size_t endtotalsizebytes;
    size_t heapgoalsizebytes;

    double starttimestamp;
    double atomicstarttimestamp;
    double endtimestamp;
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

struct global_State
{
    stringtable strt; // hash table for strings

    lua_Alloc frealloc;   // function to reallocate memory
    void* ud;            // auxiliary data to `frealloc'

    uint8_t currentwhite;
    uint8_t gcstate; // state of garbage collector

    void* gray;      // list of gray objects
    void* grayagain; // list of objects to be traversed atomically
    void* weak;     // list of weak tables (to be cleared)

    size_t GCthreshold;                       // when totalbytes > GCthreshold, run GC step
    size_t totalbytes;                        // number of bytes currently allocated
    int gcgoal;                               // see LUAI_GCGOAL
    int gcstepmul;                            // see LUAI_GCSTEPMUL
    int gcstepsize;                          // see LUAI_GCSTEPSIZE

    struct lua_Page* freepages[40]; // free page linked list for each size class for non-collectable objects
    struct lua_Page* freegcopages[40]; // free page linked list for each size class for collectable objects
    struct lua_Page* allpages; // page linked list with all pages for all non-collectable object classes (available with LUAU_ASSERTENABLED)
    struct lua_Page* allgcopages; // page linked list with all pages for all classes
    struct lua_Page* sweepgcopage; // position of the sweep in `allgcopages'

    size_t memcatbytes[256]; // total amount of memory used by each memory category


    struct lua_State* mainthread;
    UpVal uvhead;                                    // head of double-linked list of all open upvalues
    struct Table* mt[11];                   // metatables for basic types
    TString* ttname[11];       // names for basic types
    TString* tmname[21];             // array with tag-method names

    TValue pseudotemp; // storage for temporary values used in pseudo2addr

    TValue registry; // registry table, used by lua_ref and LUA_REGISTRYINDEX
    int registryfree; // next free slot in registry

    struct lua_jmpbuf* errorjmp; // jump buffer data for longjmp-style error handling

    uint64_t rngstate; // PCG random number generator state
    uint64_t ptrenckey[4]; // pointer encoding key for display

    lua_Callbacks cb;

    lua_ExecutionCallbacks ecb;

    void (*udatagc[128])(lua_State*, void*); // for each userdata tag, a gc callback to be called immediately before freeing memory
    Table* udatamt[128]; // metatables for tagged userdata

    TString* lightuserdataname[128]; // names for tagged lightuserdata

    GCStats gcstats;
};