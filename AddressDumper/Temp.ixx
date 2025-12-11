export module Temp;

import <vector>;

import Api;
import Disassembler;
import Section;


DisassemblerState createCodeDisasmState(Section& section)
{
	DisassemblerState state(section.newBuffer(), section.address, 0);
	return state;
}

export
{

	void findAllLibs()
	{
		DisassemblerState state = createCodeDisasmState();

		ExternalAddress lastPrologue;

		ExternalAddress lastLastLea;
		ExternalAddress lastLea;

		ExternalAddress lastLeaR8Source; // lib address
		ExternalAddress lastLoadRDXSource; // lib name
		bool lastLoadWasMov = false;
		ExternalAddress lastLoadRDXAt;
		ExternalAddress lastXorRDXAt;

		ExternalAddress luaL_register = dumpInfo.get("luaL_register");

		while (!state.isEmpty())
		{
			if (!state.next())
			{
				state.skipByte();
				continue;
			}

			auto& instruction = state.getInstruction();
			if (state.isPrologue())
			{
				lastPrologue = state.getRuntimeAddress();
			}
			else if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL)
			{
				ExternalAddress callingAddress = state.getCurrentJumpAddress(0);

				if (callingAddress == luaL_register)
				{
					ExternalAddress libAddress = lastLeaR8Source;
					const char* libName = nullptr;
					if (lastLoadRDXAt > lastXorRDXAt)
					{
						if (lastLoadWasMov)
						{
							// basically extracting string from 'const char**' thats all in external addresses
							const char* p1_local = *(const char**)translateExternalPointerNoThrow(lastLoadRDXSource);
							const char* p1 = (const char*)translateExternalPointerNoThrow(ExternalAddress((uintptr_t)p1_local));
							if (auto translated = p1)
								libName = translated;
						}
						else
						{
							libName = (const char*)translateExternalPointerNoThrow(lastLoadRDXSource);
						}
					}

					if (libName)
						libs[libAddress] = std::move(LuaLib::newAsNamed(libName, libAddress, lastPrologue));
					else
						libs[libAddress] = std::move(LuaLib::newAsUnnamed(libAddress, lastPrologue));
				}
			}
			else if (instruction.info.mnemonic == ZYDIS_MNEMONIC_LEA)
			{
				if (instruction.operands[0].reg.value == ZYDIS_REGISTER_R8)
				{
					lastLeaR8Source = state.getCurrentJumpAddress(1);
				}
				else if (instruction.operands[0].reg.value == ZYDIS_REGISTER_RDX)
				{
					lastLoadRDXSource = state.getCurrentJumpAddress(1);
					lastLoadRDXAt = state.getRuntimeAddress();
					lastLoadWasMov = false;
				}
			}
			else if (instruction.info.mnemonic == ZYDIS_MNEMONIC_MOV)
			{
				if (instruction.operands[0].reg.value == ZYDIS_REGISTER_RDX)
				{
					lastLoadRDXSource = state.getCurrentJumpAddress(1);
					lastLoadRDXAt = state.getRuntimeAddress();
					lastLoadWasMov = true;
				}
			}
			else if (instruction.info.mnemonic == ZYDIS_MNEMONIC_XOR)
			{
				if (instruction.operands[0].type == instruction.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
				{
					if (instruction.operands[0].reg.value == ZYDIS_REGISTER_EDX)
					{
						lastXorRDXAt = state.getRuntimeAddress();
					}
				}
			}

			state.post();
		}

	}


	// TODO: this must a script
	void dumpLuau(const DisassemblerState& state, ExternalAddress lea_Version, ExternalAddress luaopen_base_prologue)
	{
		dumpInfo.add("runDumpFromVersion", "lea_VERSION", state.getRuntimeAddress());

		FunctionData luaopen_base = text.createFunctionData(luaopen_base_prologue);

		dumpInfo.add("lea_VERSION", "luaopen_base", luaopen_base.prologueRuntimeAddress);

		// re-adding those functions to keep calls in check and make sure they did not change
		{
			auto calls = getCallingFunctions(luaopen_base);

			dumpInfo.newRegistrar("luaopen_base")
				.add("lua_pushvalue", calls.at(0))
				.add("lua_setfield", calls.at(1))
				.add("luaL_register", calls.at(2))
				.add("lua_pushlstring", calls.at(3))
				.add("lua_setfield", calls.at(4))
				.add("lua_pushcclosurek", calls.at(5))
				.add("lua_pushcclosurek", calls.at(6));
		}

		{
			auto calls = getCallingFunctions(dumpInfo.get("luaL_register"));

			dumpInfo.newRegistrar("luaL_register")
				.add("luaL_findtable", calls.at(0))
				.add("lua_getfield", calls.at(1))
				.add("lua_type", calls.at(2))
				.add("lua_settop", calls.at(3))
				.add("luaL_findtable", calls.at(4))
				.add("lua_pushvalue", calls.at(5))
				.add("lua_setfield", calls.at(6))
				.add("lua_remove", calls.at(7))
				.add("lua_pushcclosurek", calls.at(8))
				.add("lua_setfield", calls.at(9))
				.add("luaL_errorL", calls.at(10));
		}

		{
			auto calls = getCallingFunctions(dumpInfo.get("lua_getfield"));

			dumpInfo.newRegistrar("lua_getfield")
				.add("luaC_barrierback", calls.at(0))
				.add("pseudo2addr", calls.at(1))
				.add("luaS_newlstr", calls.at(2))
				.add("luaV_gettable", calls.at(3));
		}

		{
			auto calls = getCallingFunctions(dumpInfo.get("luaV_gettable"));

			dumpInfo.newRegistrar("luaV_gettable")
				.add("luaH_get", calls.at(0))
				.add("luaT_gettm", calls.at(1))
				.add("luaT_gettmbyobj", calls.at(2))
				.add("callTMres", calls.at(3))
				.add("luaG_indexerror", calls.at(4))
				.add("luaG_runerrorL", calls.at(5));
		}

		{
			auto calls = getCallingFunctions(dumpInfo.get("luaG_runerrorL"));

			dumpInfo.newRegistrar("luaG_runerrorL")
				.add("luaD_throw", calls.back());
		}

		{
			auto calls = getCallingFunctions(dumpInfo.get("luaH_get"));

			dumpInfo.newRegistrar("luaH_get")
				.add("luaH_getstr", calls.at(0))
				.add("luaH_getnum", calls.at(1));
		}

		{
			auto calls = getCallingFunctions(dumpInfo.get("luaL_findtable"));

			dumpInfo.newRegistrar("luaL_findtable")
				.add("lua_pushvalue", calls.at(0))
				.add("lua_pushlstring", calls.at(2))
				.add("lua_rawget", calls.at(3))
				.add("lua_type", calls.at(4))
				.add("lua_settop", calls.at(5))
				.add("lua_createtable", calls.at(6))
				.add("lua_pushlstring", calls.at(7))
				.add("lua_pushvalue", calls.at(8))
				.add("lua_settable", calls.at(9));
		}

		ExternalAddress base_funcs;
		{
			auto tempState = state;
			tempState.travelAbsolute(luaopen_base.prologueOffset);
			FunctionCallAnalyzer_Fastcall callAnal(tempState);
			callAnal.analyze();

			auto& baselibRegistration = callAnal.getCallDetails(2);

			auto& inextRegistration = callAnal.getCallDetails(5);
			auto& pcallRegistration = callAnal.getCallDetails(11);
			auto& xpcallRegistration = callAnal.getCallDetails(13);

			base_funcs = baselibRegistration.getArgumentValueAsAddress(2);

			dumpInfo.newRegistrar("luaopen_base lea")
				.add("luaB_inext", inextRegistration.getArgumentValueAsAddress(1))
				.add("luaB_pcally", pcallRegistration.getArgumentValueAsAddress(1))
				.add("luaB_pcallcont", pcallRegistration.getArgumentValueAsAddress(4))
				.add("luaB_xpcally", xpcallRegistration.getArgumentValueAsAddress(1))
				.add("luaB_xpcallcont", xpcallRegistration.getArgumentValueAsAddress(4));
		}

		{
			auto calls = getCallingFunctions(dumpInfo.get("luaB_xpcally"));

			dumpInfo.newRegistrar("luaB_xpcally")
				.add("luaL_checktype", calls.at(0))
				.add("lua_pushvalue", calls.at(1))
				.add("lua_pushvalue", calls.at(2))
				.add("lua_replace", calls.at(3))
				.add("lua_replace", calls.at(4))
				.add("luaD_pcall", calls.at(5))
				.add("lua_rawcheckstack", calls.at(6));
		}

		{
			auto luaB_xpcallcont = text.createFunctionData(dumpInfo.get("luaB_xpcallcont"));
			auto leas = getLeaTargets(luaB_xpcallcont);
			auto luaB_xpcallerr = leas.at(0);
			dumpInfo.add("luaB_xpcallcont lea", "luaB_xpcallerr", luaB_xpcallerr);
			dumpInfo.add("luaB_xpcallerr", "luaD_call", getFirstJumpDestination(luaB_xpcallerr));
		}

		{
			dumpInfo.newRegistrar("luaD_call")
				.add("luau_precall", getCallingFunctionAt(dumpInfo.get("luaD_call"), 0));
		}

		{
			auto calls = getCallingFunctions(dumpInfo.get("luau_precall"));

			dumpInfo.newRegistrar("luau_precall")
				.add("luaV_tryfuncTM", calls.at(0))
				.add("luaD_growCI", calls.at(1));
		}

		{
			dumpInfo.newRegistrar("luaD_growCI")
				.add("luaD_reallocCI", getCallingFunctionAt(dumpInfo.get("luaD_growCI"), 0));
		}

		{
			auto calls = getCallingFunctions(dumpInfo.get("luaB_inext"));

			dumpInfo.newRegistrar("luaB_inext")
				.add("luaL_checkinteger", calls.at(0))
				.add("luaL_checktype", calls.at(1))
				.add("lua_pushinteger", calls.at(2))
				.add("lua_rawgeti", calls.at(3))
				.add("lua_type", calls.at(4));
		}

		auto base_lib = parseLuaLib(base_funcs, "base_funcs");

		for (auto& [name, funcAddress] : base_lib)
			dumpInfo.add("base_funcs", "luaB_" + name, funcAddress);

		{
			auto calls = getCallingFunctions(base_lib.at("getfenv"));

			dumpInfo.newRegistrar("luaB_getfenv")
				.add("getfunc", calls.at(0))
				.add("lua_iscfunction", calls.at(1))
				.add("lua_pushvalue", calls.at(2))
				.add("lua_getfenv", calls.at(3))
				.add("lua_setsafeenv", calls.at(4));
		}

		{
			auto calls = getCallingFunctions(base_lib.at("setfenv"));

			dumpInfo.newRegistrar("luaB_setfenv")
				.add("luaL_checktype", calls.at(0))
				.add("getfunc", calls.at(1))
				.add("lua_pushvalue", calls.at(2))
				.add("lua_setsafeenv", calls.at(3))
				.add("lua_isnumber", calls.at(4))
				.add("lua_tonumberx", calls.at(5))
				.add("lua_pushthread", calls.at(6))
				.add("lua_insert", calls.at(7))
				.add("lua_setfenv", calls.at(8))
				.add("lua_iscfunction", calls.at(9))
				.add("lua_setfenv", calls.at(10))
				.add("luaL_errorL", calls.at(11));
		}

		{
			auto calls = getCallingFunctions(base_lib.at("rawequal"));

			dumpInfo.newRegistrar("luaB_rawequal")
				.add("luaL_checkany", calls.at(0))
				.add("luaL_checkany", calls.at(1))
				.add("lua_rawequal", calls.at(2))
				.add("lua_pushboolean", calls.at(3));
		}

		{
			auto calls = getCallingFunctions(base_lib.at("rawget"));

			dumpInfo.newRegistrar("luaB_rawget")
				.add("luaL_checktype", calls.at(0))
				.add("luaL_checkany", calls.at(1))
				.add("lua_settop", calls.at(2))
				.add("lua_rawget", calls.at(3));
		}

		{
			auto calls = getCallingFunctions(base_lib.at("rawset"));

			dumpInfo.newRegistrar("luaB_rawset")
				.add("luaL_checktype", calls.at(0))
				.add("luaL_checkany", calls.at(1))
				.add("luaL_checkany", calls.at(2))
				.add("lua_settop", calls.at(3))
				.add("lua_rawset", calls.at(4));
		}

		{
			auto calls = getCallingFunctions(dumpInfo.get("lua_rawset"));

			dumpInfo.newRegistrar("lua_rawset")
				.add("pseudo2addr", calls.at(0))
				.add("luaG_readonlyerror", calls.at(1))
				.add("luaH_set", calls.at(2))
				.add("luaC_barriertable", calls.at(3));
		}

		{
			auto calls = getCallingFunctions(base_lib.at("rawlen"));

			dumpInfo.newRegistrar("luaB_rawlen")
				.add("lua_type", calls.at(0))
				.add("lua_objlen", calls.at(1))
				.add("lua_pushinteger", calls.at(2))
				.add("luaL_argerrorL", calls.at(3));
		}

		{
			auto calls = getCallingFunctions(base_lib.at("type"));

			dumpInfo.newRegistrar("luaB_type")
				.add("luaL_checkany", calls.at(0))
				.add("lua_type", calls.at(1))
				.add("lua_typename", calls.at(2))
				.add("lua_pushstring", calls.at(3));
		}

		{
			auto calls = getCallingFunctions(base_lib.at("typeof"));

			dumpInfo.newRegistrar("luaB_typeof")
				.add("luaL_checkany", calls.at(0))
				.add("luaL_typename", calls.at(1))
				.add("lua_pushstring", calls.at(2));
		}

		{
			auto calls = getCallingFunctions(base_lib.at("next"));

			dumpInfo.newRegistrar("luaB_next")
				.add("luaL_checktype", calls.at(0))
				.add("lua_settop", calls.at(1))
				.add("lua_next", calls.at(2))
				.add("lua_pushnil", calls.at(3));
		}

		{
			auto calls = getCallingFunctions(base_lib.at("assert"));

			dumpInfo.newRegistrar("luaB_assert")
				.add("luaL_checkany", calls.at(0))
				.add("lua_toboolean", calls.at(1))
				.add("luaL_optlstring", calls.at(2))
				.add("luaL_errorL", calls.at(3));
		}

		{
			auto calls = getCallingFunctions(base_lib.at("select"));

			dumpInfo.newRegistrar("luaB_select")
				.add("lua_gettop", calls.at(0))
				.add("lua_type", calls.at(1))
				.add("lua_tolstring", calls.at(2))
				.add("lua_pushinteger", calls.at(3))
				.add("luaL_checkinteger", calls.at(4))
				.add("luaL_argerrorL", calls.at(5));
		}

		{
			auto calls = getCallingFunctions(base_lib.at("tostring"));

			dumpInfo.newRegistrar("luaB_tostring")
				.add("luaL_checkany", calls.at(0))
				.add("luaL_tolstring", calls.at(1));
		}

		{
			auto calls = getCallingFunctions(base_lib.at("newproxy"));

			dumpInfo.newRegistrar("luaB_newproxy")
				.add("lua_type", calls.at(0))
				.add("lua_toboolean", calls.at(1))
				.add("lua_newuserdatatagged", calls.at(2))
				.add("lua_createtable", calls.at(3))
				.add("lua_setmetatable", calls.at(4))
				.add("luaL_typeerrorL", calls.at(5));
		}

		{
			auto calls = getCallingFunctions(base_lib.at("tonumber"));

			dumpInfo.newRegistrar("luaB_tonumber")
				.add("luaL_optinteger", calls.at(0))
				.add("lua_tonumberx", calls.at(1))
				.add("lua_pushnumber", calls.at(2))
				.add("luaL_checkany", calls.at(3))
				.add("lua_pushnil", calls.at(4))
				.add("luaL_checkstring", calls.at(5));
		}

		{
			auto calls = getCallingFunctions(base_lib.at("getmetatable"));

			dumpInfo.newRegistrar("luaB_getmetatable")
				.add("luaL_checkany", calls.at(0))
				.add("lua_getmetatable", calls.at(1))
				.add("lua_pushnil", calls.at(2))
				.add("luaL_getmetafield", calls.at(3));
		}

		{
			auto calls = getCallingFunctions(base_lib.at("setmetatable"));

			dumpInfo.newRegistrar("luaB_setmetatable")
				.add("lua_type", calls.at(0))
				.add("luaL_checktype", calls.at(1))
				.add("luaL_getmetafield", calls.at(2))
				.add("lua_settop", calls.at(3))
				.add("lua_setmetatable", calls.at(4))
				.add("luaL_typeerrorL", calls.at(5))
				.add("luaL_errorL", calls.at(6));
		}

		{
			auto calls = getCallingFunctions(base_lib.at("error"));

			dumpInfo.newRegistrar("luaB_error")
				.add("luaL_optinteger", calls.at(0))
				.add("lua_settop", calls.at(1))
				.add("lua_isstring", calls.at(2))
				.add("luaL_where", calls.at(3))
				.add("lua_pushvalue", calls.at(4))
				.add("lua_concat", calls.at(5))
				.add("lua_error", calls.at(6));
		}

		{
			dumpInfo.add("luaL_typename", "luaA_toobject",
				getCallingFunctionAt(dumpInfo.get("luaL_typename"), 0));
		}

		{
			auto calls = getCallingFunctions(dumpInfo.get("luaL_typeerrorL"));

			dumpInfo.newRegistrar("luaL_typeerrorL")
				.add("currfuncname", calls.at(0))
				.add("luaA_toobject", calls.at(1))
				.add("luaT_objtypename", calls.at(2));

		}

		{
			auto calls = getCallingFunctions(dumpInfo.get("luaL_optinteger"));

			dumpInfo.newRegistrar("luaL_optinteger")
				.add("lua_type", calls.at(0))
				.add("lua_tointegerx", calls.at(1))
				.add("tag_error", calls.at(2));
		}

		{
			auto lua_type = dumpInfo.get("lua_type");
			auto leas = getLeaTargets(lua_type);

			dumpInfo.add("lua_type lea", "luaO_nilobject", leas.at(0));

			auto calls = getCallingFunctions(lua_type);

			dumpInfo.add("lua_type", "pseudo2addr", calls.at(0));
		}

		{
			auto calls = getCallingFunctions(dumpInfo.get("getfunc"));

			dumpInfo.newRegistrar("getfunc")
				.add("lua_type", calls.at(0))
				.add("lua_pushvalue", calls.at(1))
				.add("luaL_optinteger", calls.at(2))
				.add("luaL_checkinteger", calls.at(3))
				.add("lua_getinfo", calls.at(4));
		}

		{
			auto calls = getCallingFunctions(dumpInfo.get("lua_pushcclosurek"));

			dumpInfo.newRegistrar("lua_pushcclosurek")
				.add("luaC_barrierback", calls.at(1))
				.add("luaF_newCclosure", calls.at(2));
		}

		{
			auto luaF_newLclosure = getNextFunction(dumpInfo.get("luaF_newCclosure"));
			dumpInfo.add("luaF_newCclosure", "luaF_newLclosure", luaF_newLclosure.prologueRuntimeAddress);
		}

		{
			auto luaF_newproto = getNextFunction(dumpInfo.get("luaF_newLclosure"));
			dumpInfo.add("luaF_newLclosure", "luaF_newproto", luaF_newproto.prologueRuntimeAddress);
		}
	}



	void dumpFlog1()
	{
		const BYTE createDataModel_log[] = "[FLog::CloseDataModel] Create DataModel - heartbeat";
		auto createDataModel_log_address = rdata.address + findSequence(rdata.newBuffer(), { createDataModel_log, sizeof(createDataModel_log) - 1 });

		DisassemblerState state = createCodeDisasmState();

		bool foundMessage = false;
		while (!state.isEmpty())
		{
			if (!state.next())
			{
				state.skipByte();
				continue;
			}

			auto& instruction = state.getInstruction();
			if (instruction.info.mnemonic == ZYDIS_MNEMONIC_LEA)
			{
				auto lea_source = state.getCurrentJumpAddress(1);
				if (lea_source == createDataModel_log_address)
					foundMessage = true;
			}
			else if (foundMessage && instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL)
			{
				auto callingAddress = state.getCurrentJumpAddress(0);
				dumpInfo.add("createDataModel_log", "FLOG1", callingAddress);
				break;
			}

			state.post();
		}
	}



	void dumpLuauFromVersion(Section& section, const std::vector<ExternalAddress>& _VERSION_possibleAddresses)
	{
		ExternalAddress lastPrologue;

		DisassemblerState state = createCodeDisasmState(section);


		// returns on found
		// failure will segfault
		while (true)
		{
			if (!state.next())
			{
				state.skipByte();
				continue;
			}

			auto& instruction = state.getInstruction();

			if (state.isPrologue())
			{
				lastPrologue = state.getRuntimeAddress();
			}
			else if (instruction.info.mnemonic == ZYDIS_MNEMONIC_LEA)
			{
				auto lea_VERSION = state.getCurrentJumpAddress(1);

				// its safe to do so, as others are pointing at the middles of random strings
				if (std::find(_VERSION_possibleAddresses.begin(), _VERSION_possibleAddresses.end(), lea_VERSION)
					!= _VERSION_possibleAddresses.end())
				{
					std::cout << "_VERSION at " << (void*)lea_VERSION << std::endl;
					dumpLuau(state, lea_VERSION, lastPrologue);
					break;
				}
			}

			state.post();
		}
	}

}