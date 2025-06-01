// tool to help you find out how you can access X from Y

#include "CarbonWindows.h"

#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

import <map>;
import <memory>;
import <sstream>;
import <iostream>;
import <set>;
import <queue>;
import <ranges>;
import <list>;
import <fstream>;

template <typename T = int>
constexpr T c_floor(double num)
{
	return double(T(num)) == num
		? T(num)
		: T(num) - ((num > 0) ? 1 : 0);
}

template <typename T = int>
constexpr T c_ceil(double num)
{
	return double(T(num)) == num
		? T(num)
		: T(num) + ((num > 0) ? 1 : 0);
}

using depth_t = unsigned char;
template <depth_t depthLimit, unsigned range>
class Scanner
{
public:
	using offset_t = unsigned short;
	using bufferIndex_t = unsigned short;

	static constexpr double const kAddressesInRange = range / sizeof(uintptr_t);
	// we cannot get bytes out of range, so we are slicing away last pointer
	static constexpr size_t const kAddressesInBuffer = c_floor<size_t>(kAddressesInRange);
	static constexpr offset_t const kNoUpperLimit = std::numeric_limits<offset_t>::max();

	// TODO: data seems to get corrupted for some reason, dont use it for now
	class Path : public std::array<offset_t, depthLimit>
	{
	public:
		bufferIndex_t size = 0;

		Path()
		{

		}

		Path(const Path& other)
			: std::array<offset_t, depthLimit>(other)
			, size(other.size)
		{
			std::memcpy(this, &other, other.size);
		}

		Path(Path&& other) noexcept
			: std::array<offset_t, depthLimit>(std::move(other))
			, size(other.size)
		{
			std::memcpy(this, &other, other.size);
		}

		Path& operator=(Path&& other) noexcept
		{
			if (this != &other)
			{
				std::array<offset_t, depthLimit>::operator=(std::move(other));
				other.size = 0;
				size = other.size;
			}
			return *this;
		}

		Path& operator=(const Path& other) noexcept
		{
			if (this != &other)
			{
				std::array<offset_t, depthLimit>::operator=(other);
				size = other.size;
			}
			return *this;
		}

		void push_back(offset_t offset)
		{
			(*this)[size++] = offset;
		}
	};

	using path_t = std::vector<offset_t>;

	Scanner(HandleScope& process)
		: process(process)
	{
		resetUpperLimits();
	}

	std::vector<path_t> doScan(uintptr_t start, uintptr_t target, bool doBreadth = true)
	{
		startAddress = start;
		targetAddress = target;

		visited.insert(start);

		if (doBreadth)
			breadthFirst();
		else
			depthFirst(startAddress, 0, {});

		return result;
	}

	void resetUpperLimits()
	{
		upperLimits.fill(kNoUpperLimit);
	}

#pragma warning(push)
#pragma warning(disable : 4838) // conversion from 'int' to '_Ty' requires a narrowing conversion
	template <typename... Offsets>
	void setLowerLimits(Offsets... offsets)
	{
		static_assert(sizeof...(offsets) <= depthLimit, "lower limit array is bigger than scanner depth");
		std::array<offset_t, sizeof...(offsets)> from{ offsets... };

		for (auto [index, offset] : std::ranges::views::enumerate(from))
		{
#pragma warning(push)
#pragma warning(disable : 4244) // conversion from 'size_t' to 'double', possible loss of data
			lowerLimits[index] = (offset_t)c_ceil(offset / sizeof(uintptr_t)) * sizeof(uintptr_t);
#pragma warning(pop)
		}
	}

	template <typename... Offsets>
	void setUpperLimits(Offsets... offsets)
	{
		static_assert(sizeof...(offsets) <= depthLimit, "upper limit array is bigger than scanner depth");
		std::array<offset_t, sizeof...(offsets)> from{ offsets... };

		resetUpperLimits();

		for (auto [index, limit] : std::ranges::views::enumerate(from))
			upperLimits[index] = limit;
	}
#pragma warning(pop)

	volatile bool stop = false;
	std::vector<path_t> result;

private:

	path_t createPath(short index, const path_t& basePath)
	{
#pragma warning( push )
#pragma warning( disable : 4244) // conversion from 'uintptr_t' to 'int', possible loss of data
		offset_t offset = index * sizeof(uintptr_t);
		auto newPath = basePath;
		newPath.push_back(offset);
#pragma warning( pop ) 
		return newPath;
	};

	void depthFirst(uintptr_t currentBase, depth_t currentDepth, path_t currentPath)
	{
		uintptr_t endAddress = currentBase + range;
		uintptr_t buffer[kAddressesInBuffer];

		if (!ReadProcessMemory(process, (void*)currentBase, buffer, sizeof(buffer), nullptr))
			return;

		auto [startBufferIndex, endBufferIndex] = getStartEnd(currentDepth);

		for (auto index = startBufferIndex; index < endBufferIndex; index++)
		{
			uintptr_t address = buffer[index];

			if (address == targetAddress)
			{
				result.push_back(std::move(createPath(index, currentPath)));
				continue;
			}

			if (currentDepth + 1 >= depthLimit)
				continue;

			if (address == 0)
				continue;

			if (!ReadProcessMemory(process, (void*)address, nullptr, 0, nullptr))
				continue;

			if (visited.find(address) != visited.end())
				continue;

			visited.insert(address);

			if (stop)
				return;

			depthFirst(address, currentDepth + 1, std::move(createPath(index, currentPath)));
		}
	}

	std::pair<bufferIndex_t, bufferIndex_t> getStartEnd(short depth)
	{
		bufferIndex_t startBufferIndex = lowerLimits[depth] / sizeof(uintptr_t);
		bufferIndex_t endBufferIndex = upperLimits[depth] == std::numeric_limits<offset_t>::max()
			? kAddressesInBuffer
			: (upperLimits[depth] / sizeof(uintptr_t)) + 1;

		return { startBufferIndex, endBufferIndex };
	}

	void breadthFirst()
	{
		struct Node
		{
			uintptr_t address;
			depth_t depth;
			path_t path;

			Node(uintptr_t address, depth_t depth, path_t&& path)
				: address(address)
				, depth(depth)
				, path(path)
			{}

			bool operator==(uintptr_t address) const
			{
				return this->address == address;
			}
		};

		std::list<Node> queue;
		queue.emplace_back(startAddress, 0, path_t{});

		while (!queue.empty())
		{
			Node current = queue.front();
			queue.pop_front();

			uintptr_t buffer[kAddressesInBuffer];
			if (!ReadProcessMemory(process, (void*)current.address, buffer, sizeof(buffer), nullptr))
				continue;

			auto [startBufferIndex, endBufferIndex] = getStartEnd(current.depth);
			for (auto index = startBufferIndex; index < endBufferIndex; index++)
			{
				uintptr_t address = buffer[index];

				if (address == targetAddress)
				{
					result.push_back(std::move(createPath(index, current.path)));
					continue;
				}

				if (address == 0)
					continue;

				if (current.depth + 1 >= depthLimit)
					continue;

				if (visited.find(address) != visited.end())
					continue;

				if (std::find(queue.begin(), queue.end(), address) != queue.end())
					continue;

				if (!ReadProcessMemory(process, (void*)address, nullptr, 0, nullptr))
					continue;

				visited.insert(address);

				if (stop)
					return;

				queue.emplace_back(address, current.depth + 1, createPath(index, current.path));
			}
		}
	}

	HandleScope& process;

	std::array<offset_t, depthLimit> lowerLimits = 0;
	std::array<offset_t, depthLimit> upperLimits = 0;

	uintptr_t startAddress;
	uintptr_t targetAddress;

	std::set<uintptr_t> visited;
};

std::optional<uintptr_t> tryDereference(HandleScope& process, uintptr_t address, int offset = 0)
{
	uintptr_t pointerAddress = address + offset;

	uintptr_t pointerValue;
	if (!ReadProcessMemory(process, (void*)pointerAddress, &pointerValue, sizeof(pointerValue), nullptr))
		return std::nullopt;

	return pointerValue;
}

uintptr_t dereference(HandleScope& process, uintptr_t address, int offset = 0)
{
	if (auto result = tryDereference(process, address, offset))
		return result.value();

	throw std::exception("address or offset is wrong");
	return address;
}

class RttiDescriptorContainer
{
public:

	RttiDescriptorContainer(uintptr_t moduleBase)
		: moduleBase(moduleBase)
	{

	}

	const std::string* tryGetName(HandleScope& process, uintptr_t object)
	{
		if (!object)
			return nullptr;

		auto vftable = tryDereference(process, object);
		if (!vftable)
			return nullptr;

		uintptr_t locatorVftableAddress = vftable.value() - sizeof(uintptr_t);

		auto locatorAddress = tryDereference(process, locatorVftableAddress);
		if (!locatorAddress)
			return nullptr;

		auto pos = locatorToName.find(locatorAddress.value());
		if (pos != locatorToName.end())
			return &pos->second;

		return tryRegisterNewLocator(process, locatorAddress.value());
	}

	const std::string* tryRegisterNewLocator(HandleScope& process, uintptr_t locatorAddress)
	{
		RTTICompleteObjectLocator locator;
		if (!ReadProcessMemory(process, (void*)locatorAddress, &locator, sizeof(locator), nullptr))
			return nullptr;

		auto descriptorAddress = locator.getTypeDescriptorAddress(moduleBase);

		TypeDescriptor descriptor;
		if (!ReadProcessMemory(process, (void*)descriptorAddress, &descriptor, sizeof(descriptor), nullptr))
			return nullptr;

		auto name = descriptor.getName();
		auto pos = locatorToName.emplace(locatorAddress, name);
		return &pos.first->second;
	}

private:

	struct TypeDescriptor;

	struct RTTICompleteObjectLocator
	{
		unsigned signature;
		unsigned offset;
		unsigned cdOffset;

		int typeDescriptorOffset;
		int classDescriptorOffset;
		int selfOffset;

		uintptr_t getTypeDescriptorAddress(uintptr_t moduleBase)
		{
			return moduleBase + typeDescriptorOffset;
		}
	};

	struct TypeDescriptor
	{
		static constexpr int nameMaxSize = 400; // varies, may be not even full

		void* vftable;
		void* spare;
		char name[nameMaxSize];

		std::string getName()
		{
			int i = 0;
			while (i < nameMaxSize && name[i] != '\0')
				i++;

			auto mangled = std::string(name, i);

			if (auto pos = mangled.find("AV"); pos != std::string::npos)
				mangled.erase(pos, 2);

			char result[nameMaxSize];
			UnDecorateSymbolName(mangled.c_str() + 1, result, sizeof(result), UNDNAME_NAME_ONLY);

			return result;
		}

	};

	std::map<uintptr_t, std::string> locatorToName;

	const uintptr_t moduleBase;
};

template <typename offset_t>
class Tree
{
public:

	struct Node
	{
		Node(offset_t offset = 0)
			: offset(offset)
		{

		}

		using children_t = std::map<offset_t, Node>;

		offset_t offset;
		std::map<offset_t, Node> children;
	};

	Tree(HandleScope& process, RttiDescriptorContainer& rttiDescriptorContainer)
		: process(process)
		, rttiDescriptorContainer(rttiDescriptorContainer)
		, root(0)
	{
		symbol.MaxNameLen = symbolNameMaxSize;
		symbol.SizeOfStruct = sizeof(SYMBOL_INFO);
	}

	template <typename path_t>
	void addPath(const path_t& path)
	{
		Node* current = &root;
		for (auto& offset : path)
		{
			if (current->children.find(offset) == current->children.end())
				current->children[offset] = Node(offset);
			current = &current->children[offset];
		}
	}

	void printTree(uintptr_t from, uintptr_t target)
	{
		if (root.children.empty())
		{
			std::cout << "empty tree\n";
			return;
		}

		SymInitialize(process, NULL, true);
		std::cout << tab << from << '\n';
		printChildren(root.children, "", true, target, from);
		std::cout.flush();
	}

private:

	HandleScope& process;
	Node root;

	static const int symbolNameMaxSize = 255;

	// last character is null terminated and not filled by SymFromAddr
	// as total buffer capacity is 'symbolNameMaxSize + 1'
	SYMBOL_INFO symbol;
	char __nameBuffer[symbolNameMaxSize] = { 0 };

	void printNode(
		const Node* node,
		const std::string& prefix,
		bool isLast,
		uintptr_t printTarget,
		uintptr_t address
	)
	{
		std::cout << prefix;

		if (isLast)
			std::cout << (const char*)u8"└── ";
		else
			std::cout << (const char*)u8"├── ";

		std::cout << "0x" << node->offset;

		if (node->children.empty())
		{
			std::cout << " = " << printTarget << '\n';
		}
		else
		{
			if (auto rttiName = rttiDescriptorContainer.tryGetName(process, address))
			{
				std::cout << " " << *rttiName;
			}
			else if (SymFromAddr(process, address, 0, &symbol))
			{
				std::cout << " " << symbol.Name;
			}

			std::cout << '\n';
			printChildren(node->children, prefix, isLast, printTarget, address);
		}
	}

	void printChildren(const Node::children_t& children,
		const std::string& prefix,
		bool isLast,
		uintptr_t printTarget,
		uintptr_t address
	)
	{
		for (auto it = children.begin(); it != children.end(); it++)
		{
			auto newAddress = dereference(process, address, it->second.offset);
			printNode(
				&it->second,
				prefix + (isLast ? tab : (const char*)u8"│   "),
				std::next(it) == children.end(),
				printTarget,
				newAddress
			);
		}
	}

	inline static const char* const tab = "    ";
	RttiDescriptorContainer& rttiDescriptorContainer;
};

int main() {

	std::wstring processName = L"RobloxStudioBeta.exe";
	auto processId = getProcessId(processName);

	HandleScope process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (process == INVALID_HANDLE_VALUE)
		throw std::exception("failed to open process");

	auto moduleBase = (uintptr_t)getFirstModule(processId, processName).modBaseAddr;

	using scanner_t = Scanner<6, 500>;
	scanner_t scanner(process);

	scanner.setLowerLimits(0x78, 0);
	scanner.setUpperLimits(200, 200);

	uintptr_t start = 0x24733E69048;
	uintptr_t target = 0x2479B1C7BE0;

	auto paths = scanner.doScan(start, target, 1);

	{
		std::ofstream output("list.txt");
		std::cout.rdbuf(output.rdbuf());

		std::cout << std::hex;
		for (auto& path : paths)
		{
			std::cout << (void*)start;
			for (auto offset : path)
				std::cout << " + 0x" << offset;

			std::cout << " = " << (void*)target << '\n';
		}
		std::cout.flush();
	}

	{
		std::ofstream output("map.txt");
		std::cout.rdbuf(output.rdbuf());

		RttiDescriptorContainer rttiDescriptorContainer(moduleBase);
		Tree<scanner_t::offset_t> tree(process, rttiDescriptorContainer);
		for (const auto& path : paths)
			tree.addPath(path);

		tree.printTree(start, target);
		std::cout.flush();
	}

	return 0;
}
