export module Temp;

import <vector>;

import Api;
import Disassembler;
import Section;
import DumpInfo;
import ApplicationSections;
import FunctionCallAnalyzer;

DisassemblerState createCodeDisasmState(const Section& section)
{
	DisassemblerState state(section.newBuffer(), section.address, 0);
	return state;
}

export
{

	void findAllLibs(const ApplicationSections& sections, const Section& section, DumpInfo& dumpInfo)
	{
		DisassemblerState state = createCodeDisasmState(section);

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
							const char* p1_local = *(const char**)sections.translateExternalPointerNoThrow(lastLoadRDXSource);
							const char* p1 = (const char*)sections.translateExternalPointerNoThrow(ExternalAddress((uintptr_t)p1_local));
							if (auto translated = p1)
								libName = translated;
						}
						else
						{
							libName = (const char*)sections.translateExternalPointerNoThrow(lastLoadRDXSource);
						}
					}

					auto& lib = dumpInfo.addLib(libAddress);
					lib.lastLoadedFromFunction = lastPrologue;

					if (libName)
						lib.setName(libName);
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
	void dumpLuau(
		const ApplicationSections& sections, const Section& section, DumpInfo& dumpInfo,
		const DisassemblerState& state,
		ExternalAddress lea_Version,
		ExternalAddress luaopen_base_prologue
	)
	{
		dumpInfo.add("runDumpFromVersion", "lea_VERSION", state.getRuntimeAddress());

		FunctionData luaopen_base = section.createFunctionData(luaopen_base_prologue);

		dumpInfo.add("lea_VERSION", "luaopen_base", luaopen_base.prologueRuntimeAddress);

		// re-adding those functions to keep calls in check and make sure they did not change
		

		// see dumpLuauPart1

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
			auto luaB_xpcallcont = section.createFunctionData(dumpInfo.get("luaB_xpcallcont"));
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

		// see dumpLuauPart3
	}

	void dumpFlog1(const Section& rdata, const Section& text, DumpInfo& dumpInfo)
	{
		const BYTE createDataModel_log[] = "[FLog::CloseDataModel] Create DataModel - heartbeat";
		auto createDataModel_log_address = rdata.address + findSequence(rdata.newBuffer(), { createDataModel_log, sizeof(createDataModel_log) - 1 });

		DisassemblerState state = createCodeDisasmState(text);

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

	void dumpLuauFromVersion(Section& text, const std::vector<ExternalAddress>& _VERSION_possibleAddresses)
	{
		ExternalAddress lastPrologue;

		DisassemblerState state = createCodeDisasmState(text);


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