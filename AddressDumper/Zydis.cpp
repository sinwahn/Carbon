#include "Zydis.h"

ZyanStatus DisassembleInstruction(ZyanU64 runtime_address,
	const void* buffer, ZyanUSize length,
	ZydisDisassembledInstruction* instruction)
{
	if (!buffer || !instruction)
	{
		return ZYAN_STATUS_INVALID_ARGUMENT;
	}

	ZydisDisassembledInstruction instr;
	instruction = &instr;
	instruction->runtime_address = runtime_address;

	ZydisDecoder decoder;
	ZYAN_CHECK(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64));

	ZydisDecoderContext ctx;
	ZYAN_CHECK(ZydisDecoderDecodeInstruction(&decoder, &ctx, buffer, length, &instruction->info));
	ZYAN_CHECK(ZydisDecoderDecodeOperands(&decoder, &ctx, &instruction->info,
		instruction->operands, instruction->info.operand_count));

	if (0)
	{
		ZydisFormatter formatter;
		ZYAN_CHECK(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL));
		ZYAN_CHECK(ZydisFormatterFormatInstruction(&formatter, &instruction->info,
			instruction->operands, instruction->info.operand_count_visible, instruction->text,
			sizeof(instruction->text), runtime_address, ZYAN_NULL));
	}

	return ZYAN_STATUS_SUCCESS;
}


ZyanStatus DisassembleInstructionWithText(ZyanU64 runtime_address,
	const void* buffer, ZyanUSize length,
	ZydisDisassembledInstruction* instruction)
{
	if (!buffer || !instruction)
	{
		return ZYAN_STATUS_INVALID_ARGUMENT;
	}

	ZydisDisassembledInstruction instr;
	instruction = &instr;
	instruction->runtime_address = runtime_address;

	ZydisDecoder decoder;
	ZYAN_CHECK(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64));

	ZydisDecoderContext ctx;
	ZYAN_CHECK(ZydisDecoderDecodeInstruction(&decoder, &ctx, buffer, length, &instruction->info));
	ZYAN_CHECK(ZydisDecoderDecodeOperands(&decoder, &ctx, &instruction->info,
		instruction->operands, instruction->info.operand_count));

	if (1)
	{
		ZydisFormatter formatter;
		ZYAN_CHECK(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL));
		ZYAN_CHECK(ZydisFormatterFormatInstruction(&formatter, &instruction->info,
			instruction->operands, instruction->info.operand_count_visible, instruction->text,
			sizeof(instruction->text), runtime_address, ZYAN_NULL));
	}

	return ZYAN_STATUS_SUCCESS;
}