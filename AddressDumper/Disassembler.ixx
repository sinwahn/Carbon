module;
#include <Zydis/Zydis.h>
#include "Zydis.h"
export module Disassembler;

import ExceptionBase;

export import Memory;

export class DisassemblerState
{
public:

	DisassemblerState(const FunctionData& functionData)
		: buffer(functionData.buffer)
		, runtimeAddress(functionData.prologueRuntimeAddress)
		, offset(functionData.prologueOffset)
		, initialRuntimeAddress(functionData.prologueRuntimeAddress)
	{

	}

	DisassemblerState(ByteArray buffer, Address runtimeAddress, Offset offset)
		: buffer(buffer)
		, runtimeAddress(runtimeAddress)
		, offset(offset)
		, initialRuntimeAddress(runtimeAddress)
	{

	}

	ZydisDisassembledInstruction instruction;
	ByteArray buffer;
	Address runtimeAddress;
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

	Address getCurrentJumpAddress(uint8_t operandIndex) const
	{
		Address result;
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

	void travelAbsolute(Address atAddress) {
		travel((atAddress - initialRuntimeAddress) - offset);
	}

	void skipByte() { travel(1); }
	bool isPrologue() const { return isFirstPrologueInstruction; }
	const ZydisDisassembledInstruction& getInstruction() const { return instruction; }
	Address getRuntimeAddress() const { return runtimeAddress; }
	Offset getOffset() const { return offset; }

private:

	Address initialRuntimeAddress;

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