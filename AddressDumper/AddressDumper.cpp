#include "../Common/CarbonWindows.h"

#include <psapi.h>
#include <inttypes.h>

extern "C"
{
	#include "Zydis.h"
}

import <vector>;
import <fstream>;
import <string>;
import <functional>;
import <map>;
import <iostream>;
import <mutex>;

import StringUtils;
import Memory;
import ExceptionBase;
import Formatter;

struct MainInfo
{
	MODULEENTRY32 module;
	IMAGE_SECTION_HEADER text;
	IMAGE_SECTION_HEADER rdata;
	IMAGE_SECTION_HEADER data;
};

MainInfo getCodeSection(HANDLE hProcess, DWORD processId, const std::wstring& moduleName)
{
	MODULEENTRY32 module = getFirstModule(processId, moduleName);
	if (module.modBaseSize == 0)
		raise("failed to get first module");

	IMAGE_DOS_HEADER dosHeader;
	if (!ReadProcessMemory(hProcess, module.modBaseAddr, &dosHeader, sizeof(dosHeader), nullptr))
		raise("failed to read DOS header; error code:", formatLastError());

	IMAGE_NT_HEADERS ntHeaders;
	if (!ReadProcessMemory(
		hProcess,
		reinterpret_cast<LPVOID>(uintptr_t(module.modBaseAddr) + dosHeader.e_lfanew),
		&ntHeaders,
		sizeof(ntHeaders),
		nullptr
	))
		raise("failed to read to read NT headers; error code:", formatLastError());

	IMAGE_SECTION_HEADER sectionHeaders[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	if (!ReadProcessMemory(hProcess,
		reinterpret_cast<LPVOID>(uintptr_t(module.modBaseAddr)
			+ dosHeader.e_lfanew
			+ sizeof(DWORD)
			+ sizeof(IMAGE_FILE_HEADER)
			+ ntHeaders.FileHeader.SizeOfOptionalHeader
		),
		&sectionHeaders,
		sizeof(sectionHeaders),
		nullptr
	))
		raise("failed to read to read section headers; error code:", formatLastError());

	MainInfo result{ module };

	for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {
		auto& section = sectionHeaders[i];

		if (strcmp((char*)section.Name, ".text") == 0)
			result.text = section;
		else if (strcmp((char*)section.Name, ".rdata") == 0)
			result.rdata = section;
		else if (strcmp((char*)section.Name, ".data") == 0)
			result.data = section;
	}

	return result;
}

struct FunctionData
{
	ByteArray buffer;
	ExternalAddress prologueRuntimeAddress;
	Offset prologueOffset;
};

class DisassemblerState
{
public:

	DisassemblerState(const FunctionData& functionData)
		: buffer(functionData.buffer)
		, runtimeAddress(functionData.prologueRuntimeAddress)
		, offset(functionData.prologueOffset)
		, initialRuntimeAddress(functionData.prologueRuntimeAddress)
	{

	}

	DisassemblerState(ByteArray buffer, ExternalAddress runtimeAddress, Offset offset)
		: buffer(buffer)
		, runtimeAddress(runtimeAddress)
		, offset(offset)
		, initialRuntimeAddress(runtimeAddress)
	{

	}

	ZydisDisassembledInstruction instruction;
	ByteArray buffer;
	ExternalAddress runtimeAddress;
	Offset offset;

	bool currentIsAlign = false;
	bool currentIsReturn = false;

	bool lastWasAlign = false;
	bool lastWasReturn = false;

	bool isFirstPrologueInstruction = false;

	const unsigned functionAlignment = 16;

	bool next(bool addText = false)
	{
		if (!disassemble(addText))
			return false;
		
		currentIsAlign = false;
		currentIsReturn = false;

		if (isAlignInstruction(instruction))
			currentIsAlign = true;
		else if (isReturnInstruction(instruction))
			currentIsReturn = true;
		
		isFirstPrologueInstruction = false;

		if (offset % functionAlignment == 0)
		{
			if (lastWasAlign || lastWasReturn)
			{
				isFirstPrologueInstruction = isPrologueCandidate(instruction);
			}
			// otherwise we are in the middle of function
		}

		return true;
	}

	ExternalAddress getCurrentJumpAddress(uint8_t operandIndex) const
	{
		ExternalAddress result;
		ZydisCalcAbsoluteAddress(&instruction.info, &instruction.operands[operandIndex], runtimeAddress, &result.value);
		return result;
	}

	bool disassemble(bool addText)
	{
		if (addText)
		{
			return ZYAN_SUCCESS(DisassembleInstructionWithText(runtimeAddress,
				/* buffer:          */ buffer.array + offset,
				/* length:          */ buffer.size - offset,
				/* instruction:     */ &instruction
			));
		}
		else
		{
			return ZYAN_SUCCESS(DisassembleInstruction(runtimeAddress,
				/* buffer:          */ buffer.array + offset,
				/* length:          */ buffer.size - offset,
				/* instruction:     */ &instruction
			));
		}
	}

	void reset()
	{
		offset.set(0);
		runtimeAddress = initialRuntimeAddress;
		currentIsAlign = false;
		currentIsReturn = false;

		lastWasAlign = false;
		lastWasReturn = false;

		isFirstPrologueInstruction = false;
	}

	void post()
	{
		travel(instruction.info.length);

		lastWasAlign = currentIsAlign;
		lastWasReturn = currentIsReturn;
	}

	void skip()
	{
		if (next())
			post();
		else
			skipByte();
	}

	bool isEmpty() const {
		return buffer.size <= offset.value;
	}

	void travel(int64_t distance)
	{
		if (distance < 0 && offset.value < uint64_t(-distance))
			raise("back travel underflow");
		offset += distance;
		runtimeAddress += distance;
	}

	void travelAbsolute(Offset atOffset) {
		travel(atOffset - offset);
	}

	void travelAbsolute(ExternalAddress atAddress) {
		travel((atAddress - initialRuntimeAddress) - offset);
	}

	void skipByte() { travel(1); }
	bool isPrologue() const { return isFirstPrologueInstruction; }
	const ZydisDisassembledInstruction& getInstruction() const { return instruction; }
	ExternalAddress getRuntimeAddress() const { return runtimeAddress; }
	Offset getOffset() const { return offset; }

private:

	ExternalAddress initialRuntimeAddress;

	static bool isAlignInstruction(ZydisDisassembledInstruction& instruction)
	{
		return instruction.info.mnemonic == ZYDIS_MNEMONIC_INT3
			|| (instruction.info.mnemonic == ZYDIS_MNEMONIC_NOP && instruction.info.length == 1);
	}

	static bool isReturnInstruction(ZydisMnemonic mnemonic) {
		return mnemonic == ZYDIS_MNEMONIC_RET;
	}

	static bool isReturnInstruction(ZydisDisassembledInstruction& instruction) {
		return isReturnInstruction(instruction.info.mnemonic);
	}

	static bool isPrologueCandidate(ZydisDisassembledInstruction& instruction)
	{
		if (instruction.info.mnemonic == ZYDIS_MNEMONIC_PUSH)
		{
			// push rdi/rbx
			return instruction.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
				&& (instruction.operands[0].reg.value == ZYDIS_REGISTER_RDI
					|| instruction.operands[0].reg.value == ZYDIS_REGISTER_RBX);
		}
		else if (instruction.info.mnemonic == ZYDIS_MNEMONIC_SUB)
		{
			// sub rsp, ?
			return instruction.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
				&& instruction.operands[0].reg.value == ZYDIS_REGISTER_RSP
				&& instruction.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
		}
		else if (instruction.info.mnemonic == ZYDIS_MNEMONIC_MOV)
		{
			// mov [rsp + ?], rbx
			return instruction.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY
				&& instruction.operands[0].mem.base == ZYDIS_REGISTER_RSP
				&& instruction.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
				&& instruction.operands[1].reg.value == ZYDIS_REGISTER_RBX;

		}

		return false;
	}

};

struct getInstructionResult
{
	ZydisDisassembledInstruction instruction;
	ExternalAddress runtimeAddress;
	Offset offset;
};

std::vector<ExternalAddress> getCallingFunctions(const FunctionData& functionData)
{
	std::vector<ExternalAddress> result;

	DisassemblerState state(functionData);

	do
	{
		if (!state.next())
			raise("getInstruction disassemble failed");

		auto& instruction = state.getInstruction();
		if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL)
		{
			result.push_back(state.getCurrentJumpAddress(0));
		}

		state.post();

	} while (!state.isPrologue());

	return result;
}

ExternalAddress getCallingFunctionAt(const FunctionData& functionData, size_t index)
{
	DisassemblerState state(functionData);
	size_t currentIndex = 0;
	do
	{
		if (!state.next())
			raise("getInstruction disassemble failed");

		auto& instruction = state.getInstruction();
		if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL)
		{
			if (index == currentIndex)
				return state.getCurrentJumpAddress(0);
			currentIndex++;
		}

		state.post();

	} while (!state.isPrologue());

	raise("getCallingFunctionAt didnt find", index, "'th call");
}

std::vector<ExternalAddress> getLeaSources(const FunctionData& functionData)
{
	std::vector<ExternalAddress> result;

	DisassemblerState state(functionData);

	do
	{
		if (!state.next())
			raise("getInstruction disassemble failed");

		auto& instruction = state.getInstruction();
		if (instruction.info.mnemonic == ZYDIS_MNEMONIC_LEA)
		{
			result.push_back(state.getCurrentJumpAddress(1));
		}

		state.post();

	} while (!state.isPrologue());

	return result;
}

getInstructionResult getInstruction(const FunctionData& functionData,
	std::function<bool(const ZydisDisassembledInstruction&)> callback)
{
	DisassemblerState state(functionData);

	do
	{
		if (!state.next())
			raise("getInstruction disassemble failed");

		auto& instruction = state.getInstruction();
		if (callback(instruction))
			return { instruction, state.getRuntimeAddress(), state.getOffset() };

		state.post();

	} while (!state.isPrologue());

	raise("getInstruction disassemble failed");
}

FunctionData getNextFunction(const FunctionData& functionData)
{
	DisassemblerState state(functionData);

	while (true)
	{
		if (!state.next())
			raise("getNextFunction disassemble failed");

		// avoid incrementing offset by .post() as we need to return first instruction in prologue
		if (state.isPrologue())
			return { functionData.buffer, state.getRuntimeAddress(), state.getOffset() };

		state.post();
	}
}

// build specially for luaopen_base
// may not be perfect but works fine on that simple jumpless function
class FunctionCallAnalyzer_Fastcall
{
public:
	struct ArgumentData
	{
		ExternalAddress functionAddress;
		uint64_t argumentRCX = 0;
		uint64_t argumentRDX = 0;
		uint64_t argumentR8 = 0;
		uint64_t argumentR9 = 0;
		std::vector<uint64_t> stackArguments;

		// keep in mind that getting correct amount of arguments is impossible and junk may be added
		uint64_t getValue(uint8_t argumentIndex) const
		{
			switch (argumentIndex)
			{
			case 0: return argumentRCX;
			case 1: return argumentRDX;
			case 2: return argumentR8;
			case 3: return argumentR9;
			default:
				if (argumentIndex >= 4 && argumentIndex < 4 + stackArguments.size())
					return stackArguments[argumentIndex - 4];
				raise("Invalid argument index");
				break;
			}
		}
	};

	struct CallData
	{
		ExternalAddress location;
		ArgumentData arguments;

		uint64_t getArgumentValue(uint8_t argumentIndex) const {
			return arguments.getValue(argumentIndex);
		}

		ExternalAddress getArgumentValueAsAddress(uint8_t argumentIndex) const {
			return ExternalAddress(arguments.getValue(argumentIndex));
		}
	};

	FunctionCallAnalyzer_Fastcall(const DisassemblerState& state)
		: state(state)
	{
		allocateStack(8 * 20);
	}

	void analyze()
	{
		do
		{
			if (!state.next(true))
				raise("getInstruction disassemble failed");

			registers.set(ZYDIS_REGISTER_RIP, state.getRuntimeAddress());
			const auto& instruction = state.getInstruction();

			std::cout << instruction.text << std::endl;

			if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL)
				analyzeCall(instruction);
			else
				analyzeInstruction(instruction);

			state.post();
		} while (!state.isPrologue());
	}

	const CallData& getCallDetails(size_t callIndex) const {
		return callDetails.at(callIndex);
	}

private:

	struct Registers
	{
		struct {
			uint64_t rax;
			uint64_t rcx;
			uint64_t rdx;
			uint64_t rbx;
			uint64_t rsp;
			uint64_t rbp;
			uint64_t rsi;
			uint64_t rdi;

			uint64_t r8;
			uint64_t r9;
			uint64_t r10;
			uint64_t r11;
			uint64_t r12;
			uint64_t r13;
			uint64_t r14;
			uint64_t r15;

			uint64_t rip;
		};

		struct RegisterInfo
		{
			uint8_t* address;
			size_t size;
		};

		RegisterInfo getRegisterInfo(ZydisRegister reg)
		{
			constexpr bool isBigEndian = (std::endian::native == std::endian::big);

			auto getOffset = [&](uint64_t& reg, size_t size)
			{
				if (isBigEndian)
					return reinterpret_cast<uint8_t*>(&reg) + (8 - size);
				else
					return reinterpret_cast<uint8_t*>(&reg);
			};

			switch (reg)
			{
			case ZYDIS_REGISTER_RAX: return { reinterpret_cast<uint8_t*>(&rax), 8 };
			case ZYDIS_REGISTER_EAX: return { getOffset(rax, 4), 4 };
			case ZYDIS_REGISTER_AX: return { getOffset(rax, 2), 2 };
			case ZYDIS_REGISTER_AL: return { getOffset(rax, 1), 1 };
			case ZYDIS_REGISTER_AH: return { getOffset(rax, 1) + (isBigEndian ? -1 : 1), 1 };

			case ZYDIS_REGISTER_RBX: return { reinterpret_cast<uint8_t*>(&rbx), 8 };
			case ZYDIS_REGISTER_EBX: return { getOffset(rbx, 4), 4 };
			case ZYDIS_REGISTER_BX: return { getOffset(rbx, 2), 2 };
			case ZYDIS_REGISTER_BL: return { getOffset(rbx, 1), 1 };
			case ZYDIS_REGISTER_BH: return { getOffset(rbx, 1) + (isBigEndian ? -1 : 1), 1 };

			case ZYDIS_REGISTER_RCX: return { reinterpret_cast<uint8_t*>(&rcx), 8 };
			case ZYDIS_REGISTER_ECX: return { getOffset(rcx, 4), 4 };
			case ZYDIS_REGISTER_CX: return { getOffset(rcx, 2), 2 };
			case ZYDIS_REGISTER_CL: return { getOffset(rcx, 1), 1 };
			case ZYDIS_REGISTER_CH: return { getOffset(rcx, 1) + (isBigEndian ? -1 : 1), 1 };

			case ZYDIS_REGISTER_RDX: return { reinterpret_cast<uint8_t*>(&rdx), 8 };
			case ZYDIS_REGISTER_EDX: return { getOffset(rdx, 4), 4 };
			case ZYDIS_REGISTER_DX: return { getOffset(rdx, 2), 2 };
			case ZYDIS_REGISTER_DL: return { getOffset(rdx, 1), 1 };
			case ZYDIS_REGISTER_DH: return { getOffset(rdx, 1) + (isBigEndian ? -1 : 1), 1 };

			case ZYDIS_REGISTER_RSP: return { reinterpret_cast<uint8_t*>(&rsp), 8 };
			case ZYDIS_REGISTER_ESP: return { getOffset(rsp, 4), 4 };
			case ZYDIS_REGISTER_SP: return { getOffset(rsp, 2), 2 };
			case ZYDIS_REGISTER_SPL: return { getOffset(rsp, 1), 1 };

			case ZYDIS_REGISTER_RBP: return { reinterpret_cast<uint8_t*>(&rbp), 8 };
			case ZYDIS_REGISTER_EBP: return { getOffset(rbp, 4), 4 };
			case ZYDIS_REGISTER_BP: return { getOffset(rbp, 2), 2 };
			case ZYDIS_REGISTER_BPL: return { getOffset(rbp, 1), 1 };

			case ZYDIS_REGISTER_RSI: return { reinterpret_cast<uint8_t*>(&rsi), 8 };
			case ZYDIS_REGISTER_ESI: return { getOffset(rsi, 4), 4 };
			case ZYDIS_REGISTER_SI: return { getOffset(rsi, 2), 2 };
			case ZYDIS_REGISTER_SIL: return { getOffset(rsi, 1), 1 };

			case ZYDIS_REGISTER_RDI: return { reinterpret_cast<uint8_t*>(&rdi), 8 };
			case ZYDIS_REGISTER_EDI: return { getOffset(rdi, 4), 4 };
			case ZYDIS_REGISTER_DI: return { getOffset(rdi, 2), 2 };
			case ZYDIS_REGISTER_DIL: return { getOffset(rdi, 1), 1 };

			case ZYDIS_REGISTER_R8: return { reinterpret_cast<uint8_t*>(&r8), 8 };
			case ZYDIS_REGISTER_R8D: return { getOffset(r8, 4), 4 };
			case ZYDIS_REGISTER_R8W: return { getOffset(r8, 2), 2 };
			case ZYDIS_REGISTER_R8B: return { getOffset(r8, 1), 1 };

			case ZYDIS_REGISTER_R9: return { reinterpret_cast<uint8_t*>(&r9), 8 };
			case ZYDIS_REGISTER_R9D: return { getOffset(r9, 4), 4 };
			case ZYDIS_REGISTER_R9W: return { getOffset(r9, 2), 2 };
			case ZYDIS_REGISTER_R9B: return { getOffset(r9, 1), 1 };

			case ZYDIS_REGISTER_R10: return { reinterpret_cast<uint8_t*>(&r10), 8 };
			case ZYDIS_REGISTER_R10D: return { getOffset(r10, 4), 4 };
			case ZYDIS_REGISTER_R10W: return { getOffset(r10, 2), 2 };
			case ZYDIS_REGISTER_R10B: return { getOffset(r10, 1), 1 };

			case ZYDIS_REGISTER_R11: return { reinterpret_cast<uint8_t*>(&r11), 8 };
			case ZYDIS_REGISTER_R11D: return { getOffset(r11, 4), 4 };
			case ZYDIS_REGISTER_R11W: return { getOffset(r11, 2), 2 };
			case ZYDIS_REGISTER_R11B: return { getOffset(r11, 1), 1 };

			case ZYDIS_REGISTER_R12: return { reinterpret_cast<uint8_t*>(&r12), 8 };
			case ZYDIS_REGISTER_R12D: return { getOffset(r12, 4), 4 };
			case ZYDIS_REGISTER_R12W: return { getOffset(r12, 2), 2 };
			case ZYDIS_REGISTER_R12B: return { getOffset(r12, 1), 1 };

			case ZYDIS_REGISTER_R13: return { reinterpret_cast<uint8_t*>(&r13), 8 };
			case ZYDIS_REGISTER_R13D: return { getOffset(r13, 4), 4 };
			case ZYDIS_REGISTER_R13W: return { getOffset(r13, 2), 2 };
			case ZYDIS_REGISTER_R13B: return { getOffset(r13, 1), 1 };

			case ZYDIS_REGISTER_R14: return { reinterpret_cast<uint8_t*>(&r14), 8 };
			case ZYDIS_REGISTER_R14D: return { getOffset(r14, 4), 4 };
			case ZYDIS_REGISTER_R14W: return { getOffset(r14, 2), 2 };
			case ZYDIS_REGISTER_R14B: return { getOffset(r14, 1), 1 };

			case ZYDIS_REGISTER_R15: return { reinterpret_cast<uint8_t*>(&r15), 8 };
			case ZYDIS_REGISTER_R15D: return { getOffset(r15, 4), 4 };
			case ZYDIS_REGISTER_R15W: return { getOffset(r15, 2), 2 };
			case ZYDIS_REGISTER_R15B: return { getOffset(r15, 1), 1 };

			case ZYDIS_REGISTER_RIP: return { reinterpret_cast<uint8_t*>(&rip), 8 };

			default:
				raise("unknown register");
			}
		}

		uint64_t get(ZydisRegister reg)
		{
			RegisterInfo info = getRegisterInfo(reg);
			uint64_t value = 0;
			std::memcpy(&value, info.address, info.size);
			return value;
		}

		void set(ZydisRegister reg, uint64_t value)
		{
			RegisterInfo info = getRegisterInfo(reg);
			std::memcpy(info.address, &value, info.size);
		}
	};

	Registers registers;
	std::vector<BYTE> stack;
	std::unordered_map<uint64_t, uint64_t> memory;
	std::vector<CallData> callDetails;
	DisassemblerState state;

	void allocateStack(size_t size)
	{
		checkStackAlign(size);
		stack.resize(size);

		// junk for readability
		BYTE i = 0;
		for (auto& v : stack)
			v = i++;

		registers.set(ZYDIS_REGISTER_RSP, size - 8);
	}

	void checkStackAccess(Offset at) const
	{
		if (!canAccessStack(at))
			raise("stack overread");
	}

	void checkStackAlign(Offset at) const {
		assert(std::div((int)at, 8).rem == 0);
	}

	bool canAccessStack(Offset at) const
	{
		checkStackAlign(at);
		return stack.size() >= at;
	}

	uint64_t* accessStack(Offset at) const
	{
		checkStackAccess(at);
		return (uint64_t*)(stack.data() + at.value);
	}

	bool isInStack(Address at) const {
		return (uintptr_t)stack.data() <= at.value 
			&& at.value < (uintptr_t)stack.data() + stack.size();
	}

	void analyzeInstruction(const ZydisDisassembledInstruction& instruction)
	{
		switch (instruction.info.mnemonic)
		{
		case ZYDIS_MNEMONIC_MOV:
			handleMov(instruction);
			break;
		case ZYDIS_MNEMONIC_ADD:
			handleAdd(instruction);
			break;
		case ZYDIS_MNEMONIC_SUB:
			handleSub(instruction);
			break;
		case ZYDIS_MNEMONIC_PUSH:
			handlePush(instruction);
			break;
		case ZYDIS_MNEMONIC_POP:
			handlePop(instruction);
			break;
		case ZYDIS_MNEMONIC_XOR:
			handleXor(instruction);
			break;
		case ZYDIS_MNEMONIC_LEA:
			handleLea(instruction);
			break;
		default:
			std::cout << "cannot emulate `" << instruction.text << "`\n";
		}
	}

	void analyzeCall(const ZydisDisassembledInstruction& instruction)
	{
		ArgumentData args;

		args.functionAddress = state.getCurrentJumpAddress(0);

		args.argumentRCX = registers.get(ZYDIS_REGISTER_RCX);
		args.argumentRDX = registers.get(ZYDIS_REGISTER_RDX);
		args.argumentR8 = registers.get(ZYDIS_REGISTER_R8);
		args.argumentR9 = registers.get(ZYDIS_REGISTER_R9);

		addStackArguments(args);

		callDetails.emplace_back(CallData{ state.getRuntimeAddress(), args });
	}

	void handleAdd(const ZydisDisassembledInstruction& instruction)
	{
		auto& op0 = instruction.operands[0];
		auto& op1 = instruction.operands[1];

		if (op0.type == ZYDIS_OPERAND_TYPE_REGISTER)
		{
			ZydisRegister target = op0.reg.value;

			uint64_t value = registers.get(target);

			if (op1.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
				value += op1.imm.value.u;
			else if (op1.type == ZYDIS_OPERAND_TYPE_REGISTER)
				value += registers.get(op1.reg.value);
			else
				raise("invalid operand type");

			registers.set(target, value);
		}
		else
			raise("invalid operand type");
	}

	void handleSub(const ZydisDisassembledInstruction& instruction)
	{
		auto& op0 = instruction.operands[0];
		auto& op1 = instruction.operands[1];

		if (op0.type == ZYDIS_OPERAND_TYPE_REGISTER)
		{
			ZydisRegister targetReg = op0.reg.value;

			uint64_t targetValue = registers.get(targetReg);

			if (op1.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
				targetValue -= op1.imm.value.u;
			else if (op1.type == ZYDIS_OPERAND_TYPE_REGISTER)
				targetValue -= registers.get(op1.reg.value);
			else
				raise("invalid operand type");

			registers.set(targetReg, targetValue);
		}
		else
			raise("invalid operand type");
	}


	void handleLea(const ZydisDisassembledInstruction& instruction)
	{
		auto& op0 = instruction.operands[0];
		auto& op1 = instruction.operands[1];

		if (op0.type == ZYDIS_OPERAND_TYPE_REGISTER &&
			op1.type == ZYDIS_OPERAND_TYPE_MEMORY)
		{
			uint64_t value = state.getCurrentJumpAddress(1);
			registers.set(op0.reg.value, value);
		}
		else
			raise("invalid operand type");
	}

	void handleMov(const ZydisDisassembledInstruction& instruction)
	{
		auto& op0 = instruction.operands[0];
		auto& op1 = instruction.operands[1];

		if (op0.type == ZYDIS_OPERAND_TYPE_REGISTER)
		{
			uint64_t value = 0;

			if (op1.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
				value = op1.imm.value.u;
			else if (op1.type == ZYDIS_OPERAND_TYPE_REGISTER)
				value = registers.get(normalizeRegister(op1.reg.value));
			else if (op1.type == ZYDIS_OPERAND_TYPE_MEMORY)
				value = *getMemory(evaluateMemoryOperand(op1));
			else
				raise("invalid operand type");

			auto target = normalizeRegister(op0.reg.value);
			registers.set(target, value);
		}
		else if (op0.type == ZYDIS_OPERAND_TYPE_MEMORY)
		{
			uint64_t value = 0;

			if (op1.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
				value = op1.imm.value.u;
			else if (op1.type == ZYDIS_OPERAND_TYPE_REGISTER)
				value = registers.get(normalizeRegister(op1.reg.value));
			else
				raise("invalid operand type");

			auto at = writeMemory(evaluateMemoryOperand(op0));
			*at = value;
		}
		else
			raise("invalid operand type");
	}

	void handlePush(const ZydisDisassembledInstruction& instruction)
	{
		auto& op0 = instruction.operands[0];
		auto& op1 = instruction.operands[1];

		registers.set(ZYDIS_REGISTER_RSP, registers.get(ZYDIS_REGISTER_RSP) - 8);

		uint64_t value = 0;

		if (op0.type == ZYDIS_OPERAND_TYPE_REGISTER)
			value = registers.get(normalizeRegister(op0.reg.value));
		else if (op0.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
			value = op0.imm.value.u;
		else if (op0.type == ZYDIS_OPERAND_TYPE_MEMORY)
			value = *getMemory(evaluateMemoryOperand(op0));
		else
			raise("invalid operand type");

		auto at = accessStack(registers.get(ZYDIS_REGISTER_RSP));
		*at = value;
	}

	void handlePop(const ZydisDisassembledInstruction& instruction)
	{
		auto& op0 = instruction.operands[0];
		auto& op1 = instruction.operands[1];

		if (op0.type == ZYDIS_OPERAND_TYPE_REGISTER)
		{
			auto target = normalizeRegister(op0.reg.value);
			registers.set(target, *accessStack(registers.get(ZYDIS_REGISTER_RSP)));
		}
		else if (op0.type == ZYDIS_OPERAND_TYPE_MEMORY)
		{
			Address address = evaluateMemoryOperand(op0);
			*writeMemory(address) = *accessStack(registers.get(ZYDIS_REGISTER_RSP));
		}
		else
			raise("invalid operand type");

		registers.set(ZYDIS_REGISTER_RSP, registers.get(ZYDIS_REGISTER_RSP) + 8);
	}

	void handleXor(const ZydisDisassembledInstruction& instruction)
	{
		auto& op0 = instruction.operands[0];
		auto& op1 = instruction.operands[1];

		if (op0.type == ZYDIS_OPERAND_TYPE_REGISTER &&
			op1.type == ZYDIS_OPERAND_TYPE_REGISTER)
		{
			auto target = normalizeRegister(op0.reg.value);
			auto source = normalizeRegister(op1.reg.value);

			registers.set(target, registers.get(target) ^ registers.get(source));
		}
		else if (op0.type == ZYDIS_OPERAND_TYPE_MEMORY &&
			op1.type == ZYDIS_OPERAND_TYPE_REGISTER)
		{
			auto source = normalizeRegister(op1.reg.value);
			Address address = evaluateMemoryOperand(op0);
			*writeMemory(address) ^= registers.get(source);
		}
		else
			raise("invalid operand type");
	}

	uint64_t* writeMemory(Address at)
	{
		if (isInStack(at))
		{
			if (isInStack(at + 8))
			{
				return at.ptr();
			}
			else
			{
				raise("pointer will partially write out of bounds");
			}
		}

		return &memory[at];
	}

	uint64_t* getMemory(Address at)
	{
		return &memory[at];
	}

	ZydisRegister normalizeRegister(ZydisRegister reg)
	{
		return ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
	}
	
	Address evaluateMemoryOperand(const ZydisDecodedOperand& operand)
	{
		BYTE* base = 0;
		if (operand.mem.base != ZYDIS_REGISTER_NONE)
		{
			auto reg = normalizeRegister(operand.mem.base);
			if (reg == ZYDIS_REGISTER_RSP)
				base = (BYTE*)accessStack(registers.get(ZYDIS_REGISTER_RSP));
			else
				raise("unsupported mem eval");
		}
		else
			raise("unsupported mem eval");

		uint64_t index = (operand.mem.index != ZYDIS_REGISTER_NONE)
			? registers.get(normalizeRegister(operand.mem.index)) * operand.mem.scale
			: 0;

		BYTE* result = base + index + operand.mem.disp.value;
		return (uint64_t)result;
	}

	void addStackArguments(ArgumentData& args)
	{
		uint64_t argumentIndex = 0;

		uint64_t currentRsp = registers.get(ZYDIS_REGISTER_RSP);
		const uint64_t maxArguments = 4;
		const uint64_t shadowSpace = 32;

		while (argumentIndex < maxArguments)
		{
			uint64_t offset = currentRsp + shadowSpace + (argumentIndex * 8);

			if (!canAccessStack(offset))
				break;

			uint64_t* argumentAddress = accessStack(offset);
			if (argumentAddress)
			{
				args.stackArguments.push_back(*argumentAddress);
			}
			
			argumentIndex++;
		}
	}
};

class Dumper
{
public:
	using LuaLibItems = std::map<std::string, ExternalAddress>;

	FunctionData functionDataFromAddress(ExternalAddress function) const
	{
		FunctionData result;
		result.buffer = text.newBuffer();
		result.prologueRuntimeAddress = function;
		result.prologueOffset = function - text.address;
		return result;
	};

	std::vector<ExternalAddress> getCallingFunctions(const FunctionData& functionData) const {
		return ::getCallingFunctions(functionData);
	}

	std::vector<ExternalAddress> getCallingFunctions(ExternalAddress inFunction) const {
		return ::getCallingFunctions(functionDataFromAddress(inFunction));
	}

	std::vector<ExternalAddress> getLeaSources(const FunctionData& functionData) const {
		return ::getLeaSources(functionData);
	}

	std::vector<ExternalAddress> getLeaSources(ExternalAddress inFunction) const {
		return ::getLeaSources(functionDataFromAddress(inFunction));
	}

	FunctionData getNextFunction(ExternalAddress firstFunction) const {
		return ::getNextFunction(functionDataFromAddress(firstFunction));
	}

	ExternalAddress getFirstJumpDestination(const FunctionData& functionData) const
	{
		auto [instruction, runtimeAddress, offset] = getInstruction(functionData,
			[&](const ZydisDisassembledInstruction& instruction) {
				return instruction.info.mnemonic == ZYDIS_MNEMONIC_JMP;
			});

		ExternalAddress result;
		ZydisCalcAbsoluteAddress(&instruction.info, &instruction.operands[0], runtimeAddress, &result.value);
		return result;
	}

	ExternalAddress getFirstJumpDestination(ExternalAddress inFunction) const {
		return getFirstJumpDestination(functionDataFromAddress(inFunction));
	}

	ExternalAddress getCallingFunctionAt(ExternalAddress inFunction, size_t index) const {
		return ::getCallingFunctionAt(functionDataFromAddress(inFunction), index);
	}

	const LuaLibItems& parseLibItems(const std::string& libName)
	{
		auto& lib = getLib(libName);
		lib.items = parseLuaLib(lib.address, libName);

		for (auto& [itemName, funcAddress] : lib.items)
			dumpInfo.add(libName, libName + '_' + itemName, funcAddress);

		return lib.items;
	}

	void runDumpFromLibs()
	{
		parseLibItems("task");

		{
			auto& coroutine_lib = parseLibItems("coroutine");

			auto calls = getCallingFunctions(coroutine_lib.at("create"));
			dumpInfo.newRegistrar("coroutine_create")
				.add("luaL_checktype", calls.at(0))
				.add("lua_newthread", calls.at(1))
				.add("lua_xpush", calls.at(2));
		}

		{
			auto ScriptContext__openState = getLib("script").lastLoadedFromFunction;
			dumpInfo.add("script register", "ScriptContext__openState", ScriptContext__openState);

			auto lua_newstate = getCallingFunctionAt(ScriptContext__openState, 0);
			dumpInfo.add("ScriptContext__openState", "lua_newstate", lua_newstate);

			auto calls = getCallingFunctions(lua_newstate);
			auto close_state = calls.at(2);
			dumpInfo.newRegistrar("lua_newstate")
				.add("luaD_rawrunprotected", calls.at(1))
				.add("close_state", close_state);

			calls = getCallingFunctions(close_state);
			auto luaC_freeall = calls.at(1);
			dumpInfo.newRegistrar("close_state")
				.add("luaF_close", calls.at(0))
				.add("luaC_freeall", luaC_freeall);

			dumpInfo.add("luaC_freeall", "luaM_visitgco", getFirstJumpDestination(luaC_freeall));
		}

		{
			auto& table_lib = parseLibItems("table");

			{
				auto tforeach = table_lib.at("foreach");
				auto calls = getCallingFunctions(tforeach);

				dumpInfo.newRegistrar("table_foreach")
					.add("luaL_checktype", calls.at(0))
					.add("luaL_checktype", calls.at(1))
					.add("lua_pushnil", calls.at(2))
					.add("lua_next", calls.at(3))
					.add("lua_pushvalue", calls.at(4))
					.add("lua_pushvalue", calls.at(5))
					.add("lua_pushvalue", calls.at(6))
					.add("lua_call", calls.at(7))
					.add("lua_type", calls.at(8))
					.add("lua_settop", calls.at(9))
					.add("lua_next", calls.at(10));
			}

			{
				auto tclone = table_lib.at("clone");
				auto calls = getCallingFunctions(tclone);

				dumpInfo.newRegistrar("table_clone")
					.add("luaL_checktype", calls.at(0))
					.add("luaL_getmetafield", calls.at(1))
					.add("luaH_clone", calls.at(2))
					.add("luaA_pushobject", calls.at(3))
					.add("luaL_argerrorL", calls.at(4));
			}
		}

		{
			auto& script_lib = parseLibItems("script");

			{
				auto settings = script_lib.at("settings");
				auto calls = getCallingFunctions(settings);

				auto ScriptContext__getCurrentContext = calls.at(0);
				auto getCurrentContext = getCallingFunctions(ScriptContext__getCurrentContext).at(0);
				dumpInfo.add("ScriptContext__getCurrentContext", "getCurrentContext", getCurrentContext);

				dumpInfo.newRegistrar("ScriptContext__settings")
					.add("ScriptContext__getCurrentContext", ScriptContext__getCurrentContext)
					.add("throwLackingCapability", calls.at(2))
					.add("InstanceBridge_pushshared", calls.at(4));
			}

			{
				auto lua_setsafeenv = dumpInfo.get("lua_setsafeenv");
				auto sloadstring = script_lib.at("loadstring");
				auto calls = getCallingFunctions(sloadstring);

				int lua_setsafeenvIndex = 0;

				for (auto call : calls)
				{
					if (call == lua_setsafeenv)
						break;
					else
						lua_setsafeenvIndex++;
				}

				dumpInfo.newRegistrar("ScriptContext__loadstring")
					.add("lua_setsafeenv", calls.at(lua_setsafeenvIndex))
					.add("std__string", calls.at(lua_setsafeenvIndex + 1))
					.add("ProtectedString__fromTrustedSource", calls.at(lua_setsafeenvIndex + 2))
					.add("LuaVM_load", calls.at(lua_setsafeenvIndex + 3));


				auto luau_load = getCallingFunctionAt(dumpInfo.get("LuaVM_load"), 2);
				dumpInfo.add("LuaVM_load", "luau_load", luau_load);
			}
		}
	}

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
							const char* p1_local = *(const char**)translatePointerNoThrow(lastLoadRDXSource);
							const char* p1 = (const char*)translatePointerNoThrow(ExternalAddress((uintptr_t)p1_local));
							if (auto translated = p1)
								libName = translated;
						}
						else
						{
							libName = (const char*)translatePointerNoThrow(lastLoadRDXSource);
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

	DisassemblerState createCodeDisasmState()
	{
		DisassemblerState state(text.newBuffer(), text.address, 0);
		return state;
	}

	void dumpLuau(const DisassemblerState& state, ExternalAddress lea_Version, ExternalAddress luaopen_base_prologue)
	{
		dumpInfo.add("runDumpFromVersion", "lea_VERSION", state.getRuntimeAddress());

		FunctionData luaopen_base = functionDataFromAddress(luaopen_base_prologue);

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
			auto luaB_xpcallcont = functionDataFromAddress(dumpInfo.get("luaB_xpcallcont"));
			auto leas = getLeaSources(luaB_xpcallcont);
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
			auto leas = getLeaSources(lua_type);

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

	void dumpLuauFromVersion(const std::vector<ExternalAddress>& _VERSION_possibleAddresses)
	{
		ExternalAddress lastPrologue;

		DisassemblerState state = createCodeDisasmState();


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

	void run()
	{
		setupMemoryData();

		auto _VERSION_possibleAddresses = getPossibleAddresses_VERSION();
		dumpLuauFromVersion(_VERSION_possibleAddresses);
		findAllLibs();
		identifyUnnamedLibs();
		runDumpFromLibs();
		dumpFlog1();
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

	void writeToFile(const std::string& fileName) const
	{
		std::ofstream outFile(fileName);
		if (!outFile)
			raise("unable to open file", fileName, "for writing");

		for (auto& info : dumpInfo.getResult())
			printAddress(outFile, info);

		outFile.close();
	}

	void print() const
	{
		for (auto& info : dumpInfo.getResult())
			printAddress(std::cout, info);
	}

	void printAddress(std::ostream& stream, const std::pair<std::string, ExternalAddress>& info) const
	{
		// name=address|value
		stream << info.first <<
			"=" << (void*)(info.second - imageStart) <<
			"|" << *(void**)translatePointer(info.second) << std::endl;
	}

	void identifyUnnamedLibs()
	{
		for (auto& [libAddress, lib] : libs)
		{
			if (lib.isNamed())
				continue;

			lib.items = parseLuaLib(libAddress, "unnamed");

			if (lib.hasItem("profileend"))
				lib.libName = "debug_ex";

			if (lib.hasItem("graphemes"))
				lib.libName = "utf8_ex";

			if (lib.hasItem("settings"))
				lib.libName = "script";

			if (lib.hasItem("defer"))
				lib.libName = "task";
		}
	}
private:

	const void parseLuaLibTo(ExternalAddress start, const std::string& debugName, LuaLibItems& items)
	{
		std::cout << defaultFormatter.format("parsing", debugName, "at", (void*)start, '\n');

		LocalAddress currentPtr = translatePointer(start);

		// luaL_Reg uses nullptrs as array terminating element
		while (currentPtr.deref())
		{
			std::string name = (const char*)translatePointer(currentPtr.getStoredPointer());
			currentPtr += 8;
			auto funcAddress = currentPtr.getStoredPointer();
			items[name] = funcAddress;
			currentPtr += 8;
		}
	}

	const LuaLibItems parseLuaLib(ExternalAddress start, const std::string& debugName)
	{
		LuaLibItems result;
		parseLuaLibTo(start, debugName, result);
		return result;
	}

	LocalAddress translatePointerNoThrow(ExternalAddress original) const
	{
		if (text.address.value <= original && original < text.address.value + text.header.Misc.VirtualSize)
		{
			ptrdiff_t offset = original - text.address;
			return LocalAddress((uintptr_t)text.data.get() + offset);
		}

		if (rdata.address.value <= original && original < rdata.address.value + rdata.header.Misc.VirtualSize)
		{
			ptrdiff_t offset = original - rdata.address;
			return LocalAddress((uintptr_t)rdata.data.get() + offset);
		}

		if (data.address.value <= original && original < data.address.value + data.header.Misc.VirtualSize)
		{
			ptrdiff_t offset = original - data.address;
			return LocalAddress((uintptr_t)data.data.get() + offset);
		}

		return {};
	};

	LocalAddress translatePointer(ExternalAddress original) const
	{
		if (auto result = translatePointerNoThrow(original))
			return result;

		raise("pointer does not point to a valid section");
	};

	void setupMemoryData()
	{
		std::wstring processName(L"RobloxStudioBeta.exe");

		auto processId = getProcessId(processName);
		if (!processId)
			raise(processName.c_str(), "not found");

		HandleScope process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
		if (!process)
			raise("failed to open processId", processId, "; error code:", formatLastError());

		auto [module, textHeader, rdataHeader, dataHeader] = getCodeSection(process, processId, processName);

		imageStart = ExternalAddress((uintptr_t)module.modBaseAddr);
		dumpInfo.setImageStart(imageStart);

		text = { textHeader, imageStart, process, ".text" };
		rdata = { rdataHeader, imageStart, process, ".rdata" };
		data = { dataHeader, imageStart, process, ".data" };
	}

	std::vector<ExternalAddress> getPossibleAddresses_VERSION() const
	{
		const BYTE toFind[] = "_VERSION";
		std::vector<Offset> offsets = findSequences(rdata.newBuffer(), {toFind, sizeof(toFind) - 1});
		
		if (offsets.empty())
			raise("unable to find _VERSION");

		std::vector<ExternalAddress> result;
		result.reserve(offsets.size());

		for (auto offset : offsets)
		{
			result.push_back(ExternalAddress(rdata.address + offset));
		}

		return result;
	}

	class DumpInfo
	{
	public:
		friend class Registrar;

		DumpInfo()
		{

		}

		void add(const std::string& source, const std::string& name, ExternalAddress object)
		{
			Name key{ source, name };
			auto containingIter = registered.find(key);
			if (containingIter != registered.end())
			{
				if (containingIter->second != object)
				{
					std::string discoveredName;
					for (auto& [key, val] : registered)
						if (val == object)
							discoveredName = key.name;

					raise(
						"registered function", name,
						"differs from new address"
						"\n\tlast source:", containingIter->first.source,
						"\n\tat", (void*)containingIter->second, (void*)(containingIter->second - imageStart),
						"\n\tnew source:", source,
						"\n\tat", (void*)object, (void*)(object - imageStart),
						(discoveredName.empty() ? "" : "\n\tnew address was already discovered as " + discoveredName)
					);
				}
			}
			else
			{
				std::cout << defaultFormatter.format("added", name, "from", source, "at", (void*)object, (void*)(object - imageStart)) << std::endl;
				registered[key] = object;
			}
		}

		ExternalAddress get(const std::string& name) const
		{
			for (auto& [key, address] : registered)
				if (key.name == name)
					return address;

			raise("function", name, "was not registered");
		}

		std::map<std::string, ExternalAddress> getResult() const
		{
			std::map<std::string, ExternalAddress> result;

			for (auto& [key, address] : registered)
				result[key.name] = address;

			return result;
		}

		void setImageStart(ExternalAddress imageStart_)
		{
			imageStart = imageStart_;
		}

	private:

		class Registrar
		{
			friend class DumpInfo;

		public:

			Registrar& add(const std::string& name, ExternalAddress address)
			{
				self->add(source, name, address);
				return *this;
			}

		private:

			Registrar(const std::string& name, DumpInfo* self)
				: source(name)
				, self(self)
			{

			}

			std::string source;
			DumpInfo* self;
		};

	public:

		Registrar newRegistrar(const std::string& name)
		{
			return Registrar(name, this);
		}

	private:

		struct Name
		{
			std::string source;
			std::string name;

			bool operator<(const Name& other) const
			{
				return name < other.name;
			}
		};

		ExternalAddress imageStart;
		std::map<Name, ExternalAddress> registered;
	};

	DumpInfo dumpInfo;

	struct LuaLib
	{
		static LuaLib newAsNamed(
			const std::string& libName,
			ExternalAddress address,
			ExternalAddress lastLoadedFromFunction
		)
		{
			LuaLib result;
			result.libName = libName;
			result.address = address;
			result.lastLoadedFromFunction = lastLoadedFromFunction;
			return result;
		}

		static LuaLib newAsUnnamed(
			ExternalAddress address,
			ExternalAddress lastLoadedFromFunction
		)
		{
			LuaLib result;
			result.address = address;
			result.lastLoadedFromFunction = lastLoadedFromFunction;
			return result;
		}

		bool operator==(const LuaLib& other) const
		{
			return address == other.address;
		}

		bool isNamed() const
		{
			return !libName.empty();
		}

		bool hasItem(const std::string& name) const
		{
			return items.find(name) != items.end();
		}

		ExternalAddress getItem(const std::string& name) const
		{
			return items.at(name);
		}

		std::string libName;
		ExternalAddress address;
		ExternalAddress lastLoadedFromFunction;
		LuaLibItems items;
	};

	struct Section
	{
		Section() = default;

		Section(
			const IMAGE_SECTION_HEADER& header,
			ExternalAddress imageStart,
			HANDLE processHandle,
			const char* debugName
		)
			: header(header)
		{
			address = imageStart + header.VirtualAddress;

			size = header.Misc.VirtualSize;
			data = std::make_unique<BYTE[]>(size);

			if (!ReadProcessMemory(processHandle,
				(LPVOID)address,
				data.get(),
				size,
				nullptr
			))
				raise("failed to read", debugName, "segment; error code:", formatLastError());
		}

		ByteArray newBuffer() const
		{
			return { data.get(), size };
		}

		IMAGE_SECTION_HEADER header;
		size_t size = 0;
		ExternalAddress address;
		std::unique_ptr<BYTE[]> data;

	};

	LuaLib* findLib(const std::string& name) const
	{
		for (auto& [_, lib] : libs)
			if (lib.libName == name)
				return const_cast<LuaLib*>(&lib);

		return nullptr;
	}

	const LuaLib& getLib(const std::string& name) const
	{
		if (auto lib = findLib(name))
			return *lib;

		raise("attempt to get unknown lib", name);
	}

	LuaLib& getLib(const std::string& name)
	{
		if (auto lib = findLib(name))
			return *lib;

		raise("attempt to get unknown lib", name);
	}

	Section text;
	Section rdata;
	Section data;

	ExternalAddress imageStart;
	std::map<ExternalAddress, LuaLib> libs;
};

int main(int argc, char** argv)
{
	// Assume if no arguments are provided
	bool launchedFromExplorer = argc == 1;

	try
	{
		Dumper dumper;
		dumper.run();
		dumper.print();
		std::string filename = (argc > 1) ? argv[1] : "dumpresult.txt";
		dumper.writeToFile(filename);
	}
	catch (const std::exception& exception)
	{
		std::cout << exception.what() << std::endl;
		if (launchedFromExplorer)
			getchar();
	}

	return 0;
}