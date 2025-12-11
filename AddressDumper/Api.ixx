module;
#include "Zydis.h"
export module Api;


import <vector>;
import <string>;
import <vector>;
import <functional>;
import <map>;
import <mutex>;
import <iostream>;

import ExceptionBase;
import Memory;
import Disassembler;

std::pair<int, size_t> getThreadCountAndChunkSizeForSearch(ByteArray buffer)
{
	const size_t chunkMinSize = 0x10000;

	int nThreads;
	size_t chunkSize = chunkMinSize;

	if (buffer.size <= chunkMinSize || 1)
	{
		nThreads = 1;
	}
	else
	{
		nThreads = std::thread::hardware_concurrency();
		chunkSize = buffer.size / nThreads;
		while (chunkSize < chunkMinSize)
		{
			size_t chunkSize = buffer.size / nThreads;
			nThreads--;
		}
	}

	return { nThreads, chunkSize };
}

export
{
	std::vector<Address> getCallingFunctions(const FunctionData& functionData)
	{
		std::vector<Address> result;

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

	Address getCallingFunctionAt(const FunctionData& functionData, size_t index)
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

	std::vector<Address> getLeaTargets(const FunctionData& functionData)
	{
		std::vector<Address> result;

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

	// scans entire buffer for sequence
	std::vector<Offset> findSequences(ByteArray buffer, ByteArray sequence)
	{
		auto [nThreads, chunkSize] = getThreadCountAndChunkSizeForSearch(buffer);

		std::vector<std::thread> threads;
		threads.reserve(nThreads);
		std::mutex mutex;

		std::vector<Offset> result;
		
		auto searchSequences = [](ByteArray sequence, const BYTE* bytes,
			Offset start, Offset end,
			std::vector<Offset>& resultIndices, std::mutex& mutex
		)
		{
			for (Offset i = start; i <= end; i++)
			{
				if (!memcmp(bytes + i, sequence.array, sequence.size))
				{
					std::scoped_lock lock(mutex);
					resultIndices.push_back(i);
				}
			}
		};

		for (size_t i = 0; i < nThreads; i++)
		{
			Offset start = Offset(i * chunkSize);
			Offset end = Offset((i == nThreads - 1) ? buffer.size - 1 : start.get() + chunkSize - 1);
			threads.push_back(
				std::thread(
					searchSequences, sequence, buffer.array,
					start, end, std::ref(result), std::ref(mutex)
				)
			);
		}

		for (auto& thread : threads)
			thread.join();

		return result;
	}

	// returns whatever finds first, nullptr if nothing
	Offset findSequence(ByteArray buffer, ByteArray sequence)
	{
		auto [nThreads, chunkSize] = getThreadCountAndChunkSizeForSearch(buffer);

		std::vector<std::thread> threads;
		threads.reserve(nThreads);
		std::mutex mutex;

		Offset result;

		auto searchSequence = [](ByteArray sequence, const BYTE* bytes,
			Offset start, Offset end,
			Offset& resultIndex, std::mutex& mutex
		)
		{
			for (Offset i = start; i <= end; i++)
			{
				if (memcmp(bytes + i, sequence.array, sequence.size) == 0)
				{
					std::scoped_lock lock(mutex);
					resultIndex = i;
					return;
				}
			}
		};

		for (size_t i = 0; i < nThreads; i++)
		{
			Offset start = Offset(i * chunkSize);
			Offset end = Offset((i == nThreads - 1) ? buffer.size - 1 : start.get() + chunkSize - 1);
			threads.push_back(
				std::thread(searchSequence, sequence, buffer.array,
					start, end,
					std::ref(result), std::ref(mutex)
				)
			);
		}

		for (auto& thread : threads)
			thread.join();

		return result;
	}

	void printMemoryRange(const BYTE* startAddress, int numBytes)
	{
		for (int i = 0; i < numBytes; ++i)
			std::cout << startAddress[i];
		std::cout << std::endl;
	}

	void skipZeros(const BYTE* data, Offset& offset)
	{
		while (!*(data + offset))
			offset++;
	}

	void tryDumpLuau_api();
}