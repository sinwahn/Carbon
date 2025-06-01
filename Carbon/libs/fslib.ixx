export module CarbonLuaApiLibs.fslib;

import <filesystem>;
import <fstream>;
import <array>;
import Luau;
import LuaEnv;
import StringUtils;

int carbon_readfile(lua_State* L);
int carbon_loadfile(lua_State* L);
int carbon_writefile(lua_State* L);

int carbon_isfile(lua_State* L);
int carbon_isfolder(lua_State* L);
int carbon_listfiles(lua_State* L);
int carbon_makefolder(lua_State* L);

int carbon_delfolder(lua_State* L);
int carbon_delfile(lua_State* L);
int carbon_appendfile(lua_State* L);

export const luaL_Reg filesystemLibrary[] = {
	{"readfile", carbon_readfile},
	{"loadfile", carbon_loadfile},
	{"writefile", carbon_writefile},
	{"isfile", carbon_isfile},
	{"isfolder", carbon_isfolder},
	{"listfiles", carbon_listfiles},
	{"makefolder", carbon_makefolder},
	{"delfolder", carbon_delfolder},
	{"delfile", carbon_delfile},
	{"appendfile", carbon_appendfile},

	{nullptr, nullptr},
}; 

std::wstring getPath(lua_State* L)
{
	size_t size;
	auto cstring = luaL_checklstring(L, 1, &size);

	std::string path = std::string(cstring, size);
	std::replace(path.begin(), path.end(), '/', '\\');

	if (path.find("..") != std::string::npos)
		luaL_errorL(L, "attempt to escape directory");

	std::wstring wpath = std::wstring(path.begin(), path.end());
	auto result = luaApiRuntimeState.userContentApiRootDirectory / wpath;
	
	return result;
}


bool isExtensionAllowed(const std::filesystem::path& path)
{
	static const std::array<std::string, 13> disallowedExtensions{
		".exe", ".scr", ".bat", ".com", ".csh", ".msi", ".vb", ".vbs", ".vbe", ".ws", ".wsf", ".wsh", ".ps1"
	};

	for (auto& test : disallowedExtensions)
		if (strcmp_caseInsensitive(path.extension().string(), test))
			return false;

	return true;
}

int carbon_readfile(lua_State* L)
{
	auto path = getPath(L);

	if (!std::filesystem::exists(path))
		luaL_errorL(L, "file does not exist");

	std::ifstream stream(path, std::ios_base::binary);
	std::string result((std::istreambuf_iterator<char>(stream)),
		std::istreambuf_iterator<char>());

	lua_pushlstring(L, result.c_str(), result.size());

	return 1;
}

int carbon_loadfile(lua_State* L)
{
	auto path = getPath(L);

	if (!std::filesystem::exists(path))
		luaL_errorL(L, "file does not exist");

	std::ifstream stream(path, std::ios_base::binary);
	std::string result((std::istreambuf_iterator<char>(stream)),
		std::istreambuf_iterator<char>());

	if (luaApiRuntimeState.compile(L, result.c_str(), result.c_str()))
		return 1;

	lua_pushnil(L);
	lua_insert(L, -2);

	return 2;
}

int carbon_writefile(lua_State* L)
{
	auto path = getPath(L);

	size_t contentSize;
	auto contentCString = luaL_checklstring(L, 2, &contentSize);

	if (!isExtensionAllowed(path))
		luaL_errorL(L, "forbidden extension");

	std::ofstream out;
	out.open(path, std::ios::out | std::ios::binary);
	out.write(contentCString, contentSize);
	out.close();

	return 0;
}

int carbon_isfile(lua_State* L)
{
	auto path = getPath(L);
	lua_pushboolean(L, std::filesystem::is_regular_file(path));
	return 1;
}

int carbon_isfolder(lua_State* L)
{
	auto path = getPath(L);
	lua_pushboolean(L, (std::filesystem::is_directory(path)));
	return 1;
}

int carbon_listfiles(lua_State* L)
{
	auto path = getPath(L);
	lua_createtable(L, 0, 0);

	int index = 1;
	for (auto& p : std::filesystem::directory_iterator(path))
	{
		auto subpath = p.path().string().substr(luaApiRuntimeState.userContentApiRootDirectory.string().size() + 1);
		lua_pushinteger(L, index++);
		lua_pushstring(L, subpath.c_str());
		lua_settable(L, -3);
	}

	return 1;
}

int carbon_makefolder(lua_State* L)
{
	auto path = getPath(L);
	std::filesystem::create_directories(path);
	return 0;
}

int carbon_delfolder(lua_State* L)
{
	auto path = getPath(L);
	if (!std::filesystem::remove_all(path))
		luaL_errorL(L, "folder does not exist");

	return 0;
}

int carbon_delfile(lua_State* L)
{
	auto path = getPath(L);
	if (!std::filesystem::remove(path))
		luaL_errorL(L, "file does not exist");

	return 0;
}

int carbon_appendfile(lua_State* L)
{
	auto path = getPath(L);

	size_t contentSize;
	auto contentCString = luaL_checklstring(L, 2, &contentSize);

	if (!isExtensionAllowed(path))
		luaL_errorL(L, "forbidden extension");

	if (!std::filesystem::exists(path))
		luaL_errorL(L, "file does not exist");

	std::ofstream out;
	out.open(path, std::ios_base::app | std::ios_base::binary);
	out.write(contentCString, contentSize);
	out.close();

	return 0;
}
