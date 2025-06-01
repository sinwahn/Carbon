module;
#include <stdio.h>
export module Formatter;

import <string>;
import <algorithm>;

export class Formatter
{
public:

	template <typename... Args>
	inline std::string format(const Args&... args) const
	{
		std::string output;
		formatArgs(output, args...);
		return output;
	}

	inline static std::string pointerToString(void* pointer)
	{
		char buffer[20];
		sprintf_s(buffer, sizeof(buffer), "%p", pointer);
		return std::string(buffer);
	}

	inline static uintptr_t stringToPointer(const std::string& str)
	{
		return stringToPointer(str.c_str());
	}

	inline static uintptr_t stringToPointer(const char* str)
	{
		return std::strtoull(str, nullptr, 16);
	}

	inline static std::string pointerToString(uintptr_t pointer)
	{
		return pointerToString((void*)pointer);
	}
protected:

	template <typename T, typename... Args>
	inline void formatArgs(std::string& output, const T& arg, const Args&... args) const
	{
		_format(output, arg);
		output += ' ';
		if constexpr (sizeof...(args) > 0)
			formatArgs(output, args...);
	}

	inline void _format(std::string& output, char character) const
	{
		output += character;
	}


	inline void _format(std::string& output, void* pointer) const
	{
		output += pointerToString(pointer);
	}

	inline void _format(std::string& output, const std::string& string) const
	{
		output += string;
	}

	inline void _format(std::string& output, const std::wstring& string) const
	{
		std::string temp(string.length(), 0);
		std::transform(string.begin(), string.end(), temp.begin(), [](wchar_t c) {
			return (char)c;
		});
		_format(output, temp);
	}

	template <typename T>
	inline void _format(std::string& output, T number) const
		requires (std::is_arithmetic_v<std::remove_cvref_t<T>> && !std::is_same_v<T, char>)
	{
		output += std::to_string(number);
	}
};

export inline Formatter defaultFormatter;