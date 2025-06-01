export module HookHandler;

import <array>;
import <string>;

export class Hook
{
public:

	Hook(const std::string& name);
	Hook& setTarget(void* _target) { target = _target; return *this; };
	Hook& setHook(void* _hook) { hook = _hook; return *this; };
	void* getOriginal() { return original; };
	bool setup();
	bool remove();
private:
	const std::string name;
	void* target = nullptr;
	void* hook = nullptr;
	void* original = nullptr;
};

export enum class HookId
{
	growCI,
	lua_getfield,
	FLOG1,
	lua_newstate,
	_Size,
};

export class HookHandler
{
public:
	HookHandler();
	~HookHandler();
	void removeAll();
	constexpr const Hook& getHook(HookId id) const { return hooks.at((int)id); }
	constexpr Hook& getHook(HookId id) { return hooks.at((int)id); }
private:
	std::array<Hook, (int)HookId::_Size> hooks;
};

export inline HookHandler hookHandler;