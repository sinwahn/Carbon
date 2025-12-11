export module LuaLib;

import <string>;
import Memory;

import Utils.UnorderedMap;
import ApplicationSections;

export class LuaLib
{
public:
	LuaLib(Address address)
		: address(address)
	{

	}

	static LuaLib newAsNamed(
		const std::string& libName,
		Address address,
		Address lastLoadedFromFunction
	)
	{
		LuaLib result(address);
		result.libName = libName;
		result.lastLoadedFromFunction = lastLoadedFromFunction;
		return result;
	}

	static LuaLib newAsUnnamed(
		Address address,
		Address lastLoadedFromFunction
	)
	{
		LuaLib result(address);
		result.lastLoadedFromFunction = lastLoadedFromFunction;
		return result;
	}

	bool operator==(const LuaLib& other) const {
		return address == other.address;
	}

	bool isNamed() const {
		return !libName.empty();
	}

	bool hasItem(const std::string& name) const {
		return items.contains(name);
	}

	Address getItem(const std::string& name) const {
		return items.get(name);
	}

	void setName(const std::string& name) {
		libName = name;
	}

	const std::string& getName() { return libName; }
	const auto& parseItems(const ApplicationSections& sections)
	{
		LocalAddress currentPtr = sections.translateExternalPointer(address);

		// luaL_Reg uses nullptrs as array terminating element
		while (currentPtr.deref())
		{
			std::string name = (const char*)sections.translateExternalPointer(currentPtr.getStoredPointer());
			currentPtr += 8;
			auto funcAddress = currentPtr.getStoredPointer();
			items.setOrCreate(name, funcAddress);
			currentPtr += 8;
		}

		return items;
	}

	const Address address;
	Address lastLoadedFromFunction;

	UnorderedMap<std::string, Address> items;
private:
	std::string libName;
};