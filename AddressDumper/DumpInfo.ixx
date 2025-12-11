export module DumpInfo;

import <iostream>;
import <vector>;

import ExceptionBase;
import Formatter;
import Memory;
import Utils.UnorderedMap;

import ApplicationSections;
import LuaLib;

export
{
	class DumpInfo;
	class Registrar
	{
	public:
		friend DumpInfo;
		
		~Registrar() = default;

		Registrar& add(const std::string& name, Address address);
		const std::string& getSource() const { return source; }

	private:

		Registrar(const std::string& name, DumpInfo& self)
			: source(name)
			, self(self)
		{

		}

		std::string source;
		DumpInfo& self;
	};

	class DumpInfo
	{
	public:
		friend Registrar;

		DumpInfo() = default;
		~DumpInfo() = default;

		void add(const std::string& source, const std::string& objectName, Address object)
		{
			if (auto existing = registered.find(objectName))
			{
				if (existing->address == object)
				{
					existing->sources.push_back(source);
				}
				else
				{
					raise(
						"registered function", objectName,
						"differs from new address"
						"\n\tlast source:", existing->sources.back(),
						"\n\tat", formatAddress(existing->address),
						"\n\tnew source:", source,
						"\n\tat", formatAddress(object)
					);
				}
			}
			else
			{
				std::cout << defaultFormatter.format("added", objectName, "from", source, "at", formatAddress(object)) << std::endl;
				ObjectInfo entry;
				entry.address = object;
				entry.sources.push_back(source);
				registered.create(objectName, std::move(entry));
			}
		}

		Address get(const std::string& name) const
		{
			if (auto existing = registered.find(name))
				return existing->address;
			raise("function", name, "was not registered");
		}

		const auto& getRegistered() const {
			return registered;
		}

		void setImageStart(Address imageStart_) {
			imageStart = imageStart_;
		}

		std::string formatAddress(Address what) const {
			return defaultFormatter.format((void*)what, (void*)(what - imageStart));
		}

		Registrar newRegistrar(const std::string& name) {
			return Registrar(name, *this);
		}

		void printRegistered(std::ostream& stream, const ApplicationSections& sections)
		{
			for (auto& [name, info] : registered)
			{
				// name=address|value
				stream << name <<
					"=" << (void*)(info.address - imageStart) <<
					"|" << *(void**)sections.translateExternalPointer(info.address) << std::endl;
			}
		}

		template <typename ...Args>
		LuaLib& addLib(Address at, Args&& ...args) {
			return libs.create(at, std::forward<Args>(args)...);
		}

		const auto& getLibs() const { return libs; }

	private:

		using ObjectName = std::string;

		struct ObjectInfo
		{
			std::vector<std::string> sources;
			Address address;
		};

		Address imageStart;
		UnorderedMap<ObjectName, ObjectInfo> registered;
		UnorderedMap<Address, LuaLib> libs;
	};

	Registrar& Registrar::add(const std::string& name, Address address)
	{
		self.add(source, name, address);
		return *this;
	}
}