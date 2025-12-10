module;
#include <Zydis/Zydis.h>
export module FunctionCallAnalyzer;

import <vector>;
import <unordered_map>;
import <iostream>;

import Memory;
import ExceptionBase;
import Disassembler;

// built specially for luaopen_base
// may not be perfect but works fine on that simple jumpless function
export class FunctionCallAnalyzer_Fastcall
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