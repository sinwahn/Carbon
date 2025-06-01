export module Memory;

import <vector>;
import <string>;
import <vector>;
import <functional>;
import <map>;
import <mutex>;
import <iostream>;

import StringUtils;
import ExceptionBase;
export import Address;

typedef unsigned char BYTE;

export 
{

	struct Offset : Address
	{
		constexpr Offset() = default;
		constexpr Offset(const Address& other) { value = other.value; }
		constexpr Offset(uintptr_t v) : Address(v) {}
	};

	struct _ContextualAddress : Address
	{
		constexpr _ContextualAddress() = default;
		constexpr _ContextualAddress(uintptr_t v) : Address(v) {}
	};

	struct ExternalAddress : _ContextualAddress
	{
		constexpr ExternalAddress() = default;
		explicit constexpr ExternalAddress(const Address& other) { value = other.value; }
		explicit constexpr ExternalAddress(uintptr_t v) : _ContextualAddress(v) {}

		constexpr Offset operator+(ExternalAddress v) { return Offset(value + v.value); }
		constexpr Offset operator-(ExternalAddress v) { return Offset(value - v.value); }

		constexpr ExternalAddress operator+(auto v) { return ExternalAddress(value + v); }
		constexpr ExternalAddress operator-(auto v) { return ExternalAddress(value - v); }

		constexpr ExternalAddress operator+(Offset v) { return ExternalAddress(value + v.value); }
		constexpr ExternalAddress operator-(Offset v) { return ExternalAddress(value - v.value); }
	};

	struct LocalAddress : _ContextualAddress
	{
		constexpr LocalAddress() = default;
		explicit constexpr LocalAddress(const Address& other) { value = other.value; }
		explicit constexpr LocalAddress(uintptr_t v) : _ContextualAddress(v) {}

		constexpr Offset operator+(LocalAddress v) { return Offset(value + v.value); }
		constexpr Offset operator-(LocalAddress v) { return Offset(value - v.value); }

		constexpr LocalAddress operator+(auto v) { return LocalAddress(value + v); }
		constexpr LocalAddress operator-(auto v) { return LocalAddress(value - v); }

		constexpr LocalAddress operator+(Offset v) { return LocalAddress(value + v.value); }
		constexpr LocalAddress operator-(Offset v) { return LocalAddress(value - v.value); }

		ExternalAddress getStoredPointer() const { return ExternalAddress(deref()); }
	};

	struct ByteArray
	{
		const BYTE* array = nullptr;
		size_t size = 0;
	};

	std::pair<int, size_t> getThreadCountAndChunkSize(ByteArray buffer)
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

	void searchSequence(ByteArray sequence, const BYTE* bytes,
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
	}

	void searchSequences(ByteArray sequence, const BYTE* bytes,
		Offset start, Offset end,
		std::vector<Offset>& resultIndices, std::mutex& mutex
	)
	{
		for (Offset i = start; i <= end; i++)
		{
			if (memcmp(bytes + i, sequence.array, sequence.size) == 0)
			{
				std::scoped_lock lock(mutex);
				resultIndices.push_back(i);
			}
		}
	}

	std::vector<Offset> findSequences(ByteArray buffer, ByteArray sequence)
	{
		auto [nThreads, chunkSize] = getThreadCountAndChunkSize(buffer);

		std::vector<std::thread> threads;
		threads.reserve(nThreads);
		std::mutex mutex;

		std::vector<Offset> result;

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

	Offset findSequence(ByteArray buffer, ByteArray sequence)
	{
		auto [nThreads, chunkSize] = getThreadCountAndChunkSize(buffer);

		std::vector<std::thread> threads;
		threads.reserve(nThreads);
		std::mutex mutex;

		Offset result;

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
}
