export module GlobalSettings;

import <fstream>;
import <iostream>;
import <vector>;
import <string>;

import LuaEnv;

class GlobalSettings
{
public:
	GlobalSettings();

	LuaApiSettings luaApiSettings;

	void init(const std::wstring& settingsPath);

private:
	class Descriptor
	{
	public:
		Descriptor(const char* name, size_t offset);
		void deserialize(const GlobalSettings* self, const std::string& value) const;
		void serialize(const GlobalSettings* self, std::ofstream& stream) const;
		bool& getValue(const GlobalSettings* self) const;
		const std::string& getName() const { return name; }
	private:
		std::string name;
		size_t offset = 0; // from GlobalSettings
	};

	bool readFromFile(const std::wstring& settingsPath);
	void writeToFile(const std::wstring& settingsPath);

	void createDescriptors();

	template<typename... Args>
	void newDescriptor(Args&&... args)
	{
		descriptors.push_back(Descriptor(std::forward<Args>(args)...));
	}

	Descriptor* getDescriptor(const std::string& name);

	std::vector<Descriptor> descriptors;
};

export inline GlobalSettings globalSettings;

GlobalSettings::GlobalSettings()
{
	createDescriptors();
}

GlobalSettings::Descriptor::Descriptor(const char* name, size_t offset)
	: name(name)
	, offset(offset)
{

}

void GlobalSettings::Descriptor::deserialize(const GlobalSettings* self, const std::string& value) const
{
	getValue(self) = (value != "false" && value != "0");
}

void GlobalSettings::Descriptor::serialize(const GlobalSettings* self, std::ofstream& stream) const
{
	if (getValue(self))
		stream << "true";
	else
		stream << "false";
}

bool& GlobalSettings::Descriptor::getValue(const GlobalSettings* self) const
{
	return *reinterpret_cast<bool*>((uintptr_t)self + offset);
}

void GlobalSettings::init(const std::wstring& settingsPath)
{
	if (!readFromFile(settingsPath))
	{
		std::wcout << "creating default settings file" << std::endl;
		writeToFile(settingsPath);
	}
}

bool GlobalSettings::readFromFile(const std::wstring& settingsPath)
{
	std::ifstream settings(settingsPath);
	if (!settings)
	{
		std::wcout << "failed to read settings from file " << settingsPath << std::endl;
		return false;
	}

	std::string line;
	while (std::getline(settings, line)) {
		size_t pos = line.find('=');
		if (pos != std::string::npos) {
			std::string name = line.substr(0, pos);
			std::string value = line.substr(pos + 1);

			auto descriptor = getDescriptor(name);
			if (!descriptor)
				continue;

			descriptor->deserialize(this, value);
		}
	}

	return true;
}


void GlobalSettings::writeToFile(const std::wstring& settingsPath)
{
	std::ofstream settings(settingsPath);
	if (!settings)
	{
		std::wcout << "failed to write settings to file " << settingsPath << std::endl;
		return;
	}

	for (const auto& descriptor : descriptors)
	{
		settings << descriptor.getName() << "=";
		descriptor.serialize(this, settings);
		settings << "\n";
	}
}


void GlobalSettings::createDescriptors()
{
	auto offsetLuaApiSettings = offsetof(GlobalSettings, luaApiSettings);
	newDescriptor("getupvalue_block_cclosure", offsetLuaApiSettings + offsetof(LuaApiSettings, getupvalue_block_cclosure));
	newDescriptor("setupvalue_block_cclosure", offsetLuaApiSettings + offsetof(LuaApiSettings, setupvalue_block_cclosure));
	newDescriptor("setstack_block_different_type", offsetLuaApiSettings + offsetof(LuaApiSettings, setstack_block_different_type));
	newDescriptor("getconstant_block_functions", offsetLuaApiSettings + offsetof(LuaApiSettings, getconstant_block_functions));
	newDescriptor("allow_setproto", offsetLuaApiSettings + offsetof(LuaApiSettings, allow_setproto));
	newDescriptor("set_max_initial_identity", offsetLuaApiSettings + offsetof(LuaApiSettings, set_max_initial_identity));
	newDescriptor("set_max_initial_capabilities", offsetLuaApiSettings + offsetof(LuaApiSettings, set_max_initial_capabilities));
}

GlobalSettings::Descriptor* GlobalSettings::getDescriptor(const std::string& name)
{
	for (auto& descriptor : descriptors)
	{
		if (descriptor.getName() == name)
			return &descriptor;
	}

	return nullptr;
}