local formatvalue
local layerOutput
local expandedOutput

local function printf(...)
	print(string.format(...))
end

local function errorf(...)
	error(string.format(...), 2)
end

local function islclosure(closure)
	return debug.info(closure, "s") ~= "[C]"
end

local function iscclosure(closure)
	return debug.info(closure, "s") == "[C]"
end

do

	local outputSettings = {
		max_layer = 12,
		use_type_instead_tostring = false,
		ignore_tostring_metatable = true,
		add_instance_class_name = true,
		normalize_string = true,
		add_closure_type = true,
	}
	
	local escape = {
		['\\'] = '\\\\',
		['\a'] = '\\a',
		['\b'] = '\\b',
		['\f'] = '\\f',
		['\n'] = '\\n',
		['\r'] = '\\r',
		['\t'] = '\\t',
		['\v'] = '\\v',
		['\"'] = '\\"',
		['\''] = '\\\''
	}

	function formatvalue(v)
		local vtype = type(v)

		if vtype == "string" then
			v = string.format("\"%s\"", string.gsub(v, "[\\\a\b\f\n\r\t\v\"\']", escape))

			if outputSettings.normalize_string then
				local success, normalized = pcall(utf8.nfcnormalize, v)
				if success then
					return normalized
				end
			end

		elseif vtype == "table" then

			local metatable = getmetatable(v)
			if metatable then

				local __tostringValue = rawget(metatable, "__tostring")
				if __tostringValue then

					if outputSettings.ignore_tostring_metatable then
						return tostring(v)
					end

					rawset(metatable, "__tostring", nil)
					local result = tostring(v)
					rawset(metatable, "__tostring", __tostringValue)

					return result
				end

				return tostring(v)
			end

			if outputSettings.use_type_instead_tostring then
				return "<table>"
			end

		elseif vtype == "userdata" then
			vtype = typeof(v)
			if vtype == "Instance" then

				local className = ""
				if outputSettings.add_instance_class_name then
					className = v.ClassName .. ": "
				end

				v = string.format("Instance: %s\"%s\"", className, string.gsub(v:GetFullName(), "[\\\a\b\f\n\r\t\v\"\']", escape))

				if outputSettings.normalize_string then
					local success, normalized = pcall(utf8.nfcnormalize, v)
					if success then
						return normalized
					end
				end

			else
				if outputSettings.use_type_instead_tostring then
					return "<" .. vtype .. ">"
				end

				return string.format("%s(%s)", vtype, tostring(v))
			end
		elseif vtype == "vector" then
			return string.format("Vector3(%s)", tostring(v))
		elseif vtype == "function" then

			if outputSettings.use_type_instead_tostring then
				if outputSettings.add_closure_type then
					if islclosure(v) then
						return "<lclosure>"
					end
					return "<cclosure>"
				end
				return "<function>"
			end

		end

		return v
	end

	local printedTables = {}

	function expandedOutput(outputFunction, ...)
		local maxLayer = outputSettings.max_layer

		local layer = 0
		table.clear(printedTables)

		local function printl(t)
			if layer == maxLayer then return end

			local tab = string.rep('\t', layer)

			if table.find(printedTables, t) then
				outputFunction(tab, "*** already printed ***")
				return
			end

			table.insert(printedTables, t)

			for i, v in t do
				outputFunction(tab, i, formatvalue(v))
				if type(v) == "table" then
					layer += 1
					printl(v)
					layer -= 1
				end
			end
		end

		for i = 1, select("#", ...) do
			local v = select(i, ...)
			if type(v) == "table" then
				printl(v)
			else
				outputFunction(v)
			end
		end
	end

	function layerOutput(outputFunction, t)
		for i, v in t do
			outputFunction(i, formatvalue(v))
		end
	end

end

local function expandedFormat(...)
	local result = ""
	expandedOutput(function(...)
		local argCount = select("#", ...)
		if argCount == 0 then
			result ..= "\n"
		else
			local v = ...
			result ..= tostring(v)

			for i = 2, argCount do
				local v = select(i, ...)
				result ..= " " .. tostring(v)
			end
		end
	end, ...)

	return result
end

local function printe(...)
	expandedOutput(print, ...)
end

local function printl(...)
	layerOutput(print, ...)
end


local sections = ApplicationSections.new("RobloxStudioBeta.exe")
sections:initialize()
local textSection = sections:get(".text")

local dumpInfo = DumpInfo.new()

--[[
-- main method of finding openbase is hard to port rn
local found = findSequences(textSection, "_VERSION")

if #found == 0 then
	error("unable to find _VERSION")
end

for _, address in found do
	print(address, textSection:getBaseAddress(), textSection:addressToOffset(address))
end
--]]
-- temp hack
tryDumpLuau(address)

local function registerLibItems(lib : LuaLib)
	for name, address in lib:getItems() do
		local dumpedName = lib:getName() .. '_' .. name;
		dumpInfo:add(lib:getName(), dumpedName, address)
	end
end

local function identityUnnamedLibs()
	for address, lib : LuaLib in sections:getLibs() do
		local items = lib:parseItems(sections)
		if items.profileend then
			lib:setName("debug_ex")
		end
		if items.graphemes then
			lib:setName("utf8_ex")
		end
		if items.settings then
			lib:setName("script")
		end
		if items.defer then
			lib:setName("task")
		end
	end
end


do
	local old = getCallingFunctions
	function getCallingFunctions(address)
		old(textSection, address)
	end
	
	local old = getCallingFunctions
	function getCallingFunctionAt(address, index)
		old(textSection, address, index)
	end
end

local function dumpLuauPart1()
	do
		local tforeach = sections:getLib("table").foreach
		local calls = getCallingFunctions(tforeach)

		dumpInfo:newRegistrar("table_foreach")
			:add("luaL_checktype", calls[1])
			:add("luaL_checktype", calls[2])
			:add("lua_pushnil", calls[3])
			:add("lua_next", calls[4])
			:add("lua_pushvalue", calls[5])
			:add("lua_pushvalue", calls[6])
			:add("lua_pushvalue", calls[7])
			:add("lua_call", calls[8])
			:add("lua_type", calls[9])
			:add("lua_settop", calls[10])
			:add("lua_next", calls[11])
	end

	do
		local calls = getCallingFunctions(luaopen_base)

		dumpInfo:newRegistrar("luaopen_base")
			:add("lua_pushvalue", calls[1])
			:add("lua_setfield", calls[2])
			:add("luaL_register", calls[3])
			:add("lua_pushlstring", calls[4])
			:add("lua_setfield", calls[5])
			:add("lua_pushcclosurek", calls[6])
			:add("lua_pushcclosurek", calls[7])
	end

	do
		local calls = getCallingFunctions(dumpInfo:get("luaL_register"))

		dumpInfo:newRegistrar("luaL_register")
			:add("luaL_findtable", calls[1])
			:add("lua_getfield", calls[2])
			:add("lua_type", calls[3])
			:add("lua_settop", calls[4])
			:add("luaL_findtable", calls[5])
			:add("lua_pushvalue", calls[6])
			:add("lua_setfield", calls[7])
			:add("lua_remove", calls[8])
			:add("lua_pushcclosurek", calls[9])
			:add("lua_setfield", calls[10])
			:add("luaL_errorL", calls[11])
	end

	do
		local calls = getCallingFunctions(dumpInfo:get("lua_getfield"))

		dumpInfo:newRegistrar("lua_getfield")
			:add("luaC_barrierback", calls[1])
			:add("pseudo2addr", calls[2])
			:add("luaS_newlstr", calls[3])
			:add("luaV_gettable", calls[4])
	end

	do
		local calls = getCallingFunctions(dumpInfo:get("luaV_gettable"))

		dumpInfo:newRegistrar("luaV_gettable")
			:add("luaH_get", calls[1])
			:add("luaT_gettm", calls[2])
			:add("luaT_gettmbyobj", calls[3])
			:add("callTMres", calls[4])
			:add("luaG_indexerror", calls[5])
			:add("luaG_runerrorL", calls[6])
	end

	do
		local calls = getCallingFunctions(dumpInfo:get("luaG_runerrorL"))

		dumpInfo:newRegistrar("luaG_runerrorL")
			:add("luaD_throw", calls[#calls])
	end

	do
		local calls = getCallingFunctions(dumpInfo:get("luaH_get"))

		dumpInfo:newRegistrar("luaH_get")
			:add("luaH_getstr", calls[1])
			:add("luaH_getnum", calls[2])
	end

	do
		local calls = getCallingFunctions(dumpInfo:get("luaL_findtable"))

		dumpInfo:newRegistrar("luaL_findtable")
			:add("lua_pushvalue", calls[1])
			:add("lua_pushlstring", calls[3])
			:add("lua_rawget", calls[4])
			:add("lua_type", calls[5])
			:add("lua_settop", calls[6])
			:add("lua_createtable", calls[7])
			:add("lua_pushlstring", calls[8])
			:add("lua_pushvalue", calls[9])
			:add("lua_settable", calls[10])
	end
end

local function dumpLuauPart3()
	do
		local calls = getCallingFunctions(base_lib.getfenv)

		dumpInfo:newRegistrar("luaB_getfenv")
			:add("getfunc", calls[1])
			:add("lua_iscfunction", calls[2])
			:add("lua_pushvalue", calls[3])
			:add("lua_getfenv", calls[4])
			:add("lua_setsafeenv", calls[5])
	end

	do
		local calls = getCallingFunctions(base_lib.setfenv)

		dumpInfo:newRegistrar("luaB_setfenv")
			:add("luaL_checktype", calls[1])
			:add("getfunc", calls[2])
			:add("lua_pushvalue", calls[3])
			:add("lua_setsafeenv", calls[4])
			:add("lua_isnumber", calls[5])
			:add("lua_tonumberx", calls[6])
			:add("lua_pushthread", calls[7])
			:add("lua_insert", calls[8])
			:add("lua_setfenv", calls[9])
			:add("lua_iscfunction", calls[10])
			:add("lua_setfenv", calls[11])
			:add("luaL_errorL", calls[12])
	end

	do
		local calls = getCallingFunctions(base_lib.rawequal)

		dumpInfo:newRegistrar("luaB_rawequal")
			:add("luaL_checkany", calls[1])
			:add("luaL_checkany", calls[2])
			:add("lua_rawequal", calls[3])
			:add("lua_pushboolean", calls[4])
	end

	do
		local calls = getCallingFunctions(base_lib.rawget)

		dumpInfo:newRegistrar("luaB_rawget")
			:add("luaL_checktype", calls[1])
			:add("luaL_checkany", calls[2])
			:add("lua_settop", calls[3])
			:add("lua_rawget", calls[4])
	end

	do
		local calls = getCallingFunctions(base_lib.rawset)

		dumpInfo:newRegistrar("luaB_rawset")
			:add("luaL_checktype", calls[1])
			:add("luaL_checkany", calls[2])
			:add("luaL_checkany", calls[3])
			:add("lua_settop", calls[4])
			:add("lua_rawset", calls[5])
	end

	do
		local calls = getCallingFunctions(dumpInfo:get("lua_rawset"))

		dumpInfo:newRegistrar("lua_rawset")
			:add("pseudo2addr", calls[1])
			:add("luaG_readonlyerror", calls[2])
			:add("luaH_set", calls[3])
			:add("luaC_barriertable", calls[4])
	end

	do
		local calls = getCallingFunctions(base_lib.rawlen)

		dumpInfo:newRegistrar("luaB_rawlen")
			:add("lua_type", calls[1])
			:add("lua_objlen", calls[2])
			:add("lua_pushinteger", calls[3])
			:add("luaL_argerrorL", calls[4])
	end

	do
		local calls = getCallingFunctions(base_lib.type)

		dumpInfo:newRegistrar("luaB_type")
			:add("luaL_checkany", calls[1])
			:add("lua_type", calls[2])
			:add("lua_typename", calls[3])
			:add("lua_pushstring", calls[4])
	end

	do
		local calls = getCallingFunctions(base_lib.typeof)

		dumpInfo:newRegistrar("luaB_typeof")
			:add("luaL_checkany", calls[1])
			:add("luaL_typename", calls[2])
			:add("lua_pushstring", calls[3])
	end

	do
		local calls = getCallingFunctions(base_lib.next)

		dumpInfo:newRegistrar("luaB_next")
			:add("luaL_checktype", calls[1])
			:add("lua_settop", calls[2])
			:add("lua_next", calls[3])
			:add("lua_pushnil", calls[4])
	end

	do
		local calls = getCallingFunctions(base_lib.assert)

		dumpInfo:newRegistrar("luaB_assert")
			:add("luaL_checkany", calls[1])
			:add("lua_toboolean", calls[2])
			:add("luaL_optlstring", calls[3])
			:add("luaL_errorL", calls[4])
	end

	do
		local calls = getCallingFunctions(base_lib.select)

		dumpInfo:newRegistrar("luaB_select")
			:add("lua_gettop", calls[1])
			:add("lua_type", calls[2])
			:add("lua_tolstring", calls[3])
			:add("lua_pushinteger", calls[4])
			:add("luaL_checkinteger", calls[5])
			:add("luaL_argerrorL", calls[6])
	end

	do
		local calls = getCallingFunctions(base_lib.tostring)

		dumpInfo:newRegistrar("luaB_tostring")
			:add("luaL_checkany", calls[1])
			:add("luaL_tolstring", calls[2])
	end

	do
		local calls = getCallingFunctions(base_lib.newproxy)

		dumpInfo:newRegistrar("luaB_newproxy")
			:add("lua_type", calls[1])
			:add("lua_toboolean", calls[2])
			:add("lua_newuserdatatagged", calls[3])
			:add("lua_createtable", calls[4])
			:add("lua_setmetatable", calls[5])
			:add("luaL_typeerrorL", calls[6])
	end

	do
		local calls = getCallingFunctions(base_lib.tonumber)

		dumpInfo:newRegistrar("luaB_tonumber")
			:add("luaL_optinteger", calls[1])
			:add("lua_tonumberx", calls[2])
			:add("lua_pushnumber", calls[3])
			:add("luaL_checkany", calls[4])
			:add("lua_pushnil", calls[5])
			:add("luaL_checkstring", calls[6])
	end

	do
		local calls = getCallingFunctions(base_lib.getmetatable)

		dumpInfo:newRegistrar("luaB_getmetatable")
			:add("luaL_checkany", calls[1])
			:add("lua_getmetatable", calls[2])
			:add("lua_pushnil", calls[3])
			:add("luaL_getmetafield", calls[4])
	end

	do
		local calls = getCallingFunctions(base_lib.setmetatable)

		dumpInfo:newRegistrar("luaB_setmetatable")
			:add("lua_type", calls[1])
			:add("luaL_checktype", calls[2])
			:add("luaL_getmetafield", calls[3])
			:add("lua_settop", calls[4])
			:add("lua_setmetatable", calls[5])
			:add("luaL_typeerrorL", calls[6])
			:add("luaL_errorL", calls[7])
	end

	do
		local calls = getCallingFunctions(base_lib.error)

		dumpInfo:newRegistrar("luaB_error")
			:add("luaL_optinteger", calls[1])
			:add("lua_settop", calls[2])
			:add("lua_isstring", calls[3])
			:add("luaL_where", calls[4])
			:add("lua_pushvalue", calls[5])
			:add("lua_concat", calls[6])
			:add("lua_error", calls[7])
	end

	do
		dumpInfo:add("luaL_typename", "luaA_toobject",
			getCallingFunctionAt(dumpInfo:get("luaL_typename"), 1))
	end

	do
		local calls = getCallingFunctions(dumpInfo:get("luaL_typeerrorL"))

		dumpInfo:newRegistrar("luaL_typeerrorL")
			:add("currfuncname", calls[1])
			:add("luaA_toobject", calls[2])
			:add("luaT_objtypename", calls[3])
	end

	do
		local calls = getCallingFunctions(dumpInfo:get("luaL_optinteger"))

		dumpInfo:newRegistrar("luaL_optinteger")
			:add("lua_type", calls[1])
			:add("lua_tointegerx", calls[2])
			:add("tag_error", calls[3])
	end

	do
		local lua_type = dumpInfo:get("lua_type")
		local leas = getLeaTargets(lua_type)

		dumpInfo:add("lua_type lea", "luaO_nilobject", leas[1])

		local calls = getCallingFunctions(lua_type)
		dumpInfo:add("lua_type", "pseudo2addr", calls[1])
	end

	do
		local calls = getCallingFunctions(dumpInfo:get("getfunc"))

		dumpInfo:newRegistrar("getfunc")
			:add("lua_type", calls[1])
			:add("lua_pushvalue", calls[2])
			:add("luaL_optinteger", calls[3])
			:add("luaL_checkinteger", calls[4])
			:add("lua_getinfo", calls[5])
	end

	do
		local calls = getCallingFunctions(dumpInfo:get("lua_pushcclosurek"))

		dumpInfo:newRegistrar("lua_pushcclosurek")
			:add("luaC_barrierback", calls[2])
			:add("luaF_newCclosure", calls[3])
	end
	
	do
		local luaF_newLclosure = getNextFunction(dumpInfo:get("luaF_newCclosure"))
		dumpInfo:add("luaF_newCclosure", "luaF_newLclosure", luaF_newLclosure.prologueRuntimeAddress)
	end
	
	do
		local luaF_newproto = getNextFunction(dumpInfo:get("luaF_newLclosure"));
		dumpInfo:add("luaF_newLclosure", "luaF_newproto", luaF_newproto.prologueRuntimeAddress)
	end
end

local function runDumpFromLibs()

	do
		local coroutineLib = sections:getLib("coroutine")
		local calls = getCallingFunctions(coroutineLib.create));
		dumpInfo:newRegistrar("coroutine_create")
			:add("luaL_checktype", calls[1])
			:add("lua_newthread", calls[2])
			:add("lua_xpush", calls[3])
	end

	local ScriptContext__openState = scriptLib:getLastLoadedFromFunction()
	local scriptLib = sections:getLib("script")
	dumpInfo:newRegistrar("script register")
		:add("ScriptContext__openState", ScriptContext__openState)

	local lua_newstate = getCallingFunctionAt(ScriptContext__openState, 1)
	dumpInfo:newRegistrar(("ScriptContext__openState")
		:add("lua_newstate", lua_newstate)

	local calls = getCallingFunctions(lua_newstate)
	local close_state = calls[3]
	dumpInfo:newRegistrar("lua_newstate")
		:add("luaD_rawrunprotected", calls[2])
		:add("close_state", close_state)

	local calls = getCallingFunctions(close_state)
	local luaC_freeall = calls[2]
	dumpInfo:newRegistrar("close_state")
		:add("luaF_close", calls[1])
		:add("luaC_freeall", luaC_freeall)

	dumpInfo:newRegistrar(("luaC_freeall")
		:add"luaM_visitgco", getFirstJumpDestination(luaC_freeall))

	local table_lib = parseLibItems("table")

	do
		local tforeach = sections:getLib("table").foreach
		local calls = getCallingFunctions(tforeach)

		dumpInfo:newRegistrar("table_foreach")
			:add("luaL_checktype", calls[1])
			:add("luaL_checktype", calls[2])
			:add("lua_pushnil", calls[3])
			:add("lua_next", calls[4])
			:add("lua_pushvalue", calls[5])
			:add("lua_pushvalue", calls[6])
			:add("lua_pushvalue", calls[7])
			:add("lua_call", calls[8])
			:add("lua_type", calls[9])
			:add("lua_settop", calls[10])
			:add("lua_next", calls[11])
	end

	do
		local tclone = sections:getLib("table").clone
		local calls = getCallingFunctions(tclone)
		
		dumpInfo:newRegistrar("table_clone")
			:add("luaL_checktype", calls[1])
			:add("luaL_getmetafield", calls[2])
			:add("luaH_clone", calls[3])
			:add("luaA_pushobject", calls[4])
			:add("luaL_argerrorL", calls[5])
	end

	do
		local script_lib = sections:getLib("script")
		local settings = script_lib.settings
		local calls = getCallingFunctions(settings)
		
		local ScriptContext__getCurrentContext = calls[1];
		local getCurrentContext = getCallingFunctions(ScriptContext__getCurrentContext).at(0);
		dumpInfo:add("ScriptContext__getCurrentContext", "getCurrentContext", getCurrentContext);
		
		dumpInfo:newRegistrar("ScriptContext__settings")
			:add("ScriptContext__getCurrentContext", ScriptContext__getCurrentContext)
			:add("throwLackingCapability", calls[3]);

		local pushnil = dumpInfo:get("lua_pushnil")

		for _, callee in calls do
			-- TODO:
			if isInstanceBridge_push(callee, pushnil) then
				dumpInfo:add("ScriptContext__settings",
					"InstanceBridge_pushshared", callee);
				break
			end
		end

	end

	do
		local lua_setsafeenv = dumpInfo.get("lua_setsafeenv")
		local sloadstring = script_lib.at("loadstring")
		local calls = getCallingFunctions(sloadstring)

		local lua_setsafeenvIndex = 0;

		for i, call in calls do
			if call == lua_setsafeenv then
				lua_setsafeenvIndex = i
				break
			end
		end

		dumpInfo:newRegistrar("ScriptContext__loadstring")
			:add("lua_setsafeenv", calls[lua_setsafeenvIndex])
			:add("std__string", calls[lua_setsafeenvIndex + 1])
			:add("ProtectedString__fromTrustedSource", calls[lua_setsafeenvIndex + 2])
			:add("LuaVM_load", calls[lua_setsafeenvIndex + 3])


		local luau_load = getCallingFunctionAt(dumpInfo:get("LuaVM_load"), 3)
		dumpInfo:add("LuaVM_load", "luau_load", luau_load)
	end
end

for address, lib : LuaLib in sections:getLibs() do
	registerLibItems(lib)
end

identifyUnnamedLibs()

runDumpFromLibs()