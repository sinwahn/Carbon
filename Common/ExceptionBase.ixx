export module ExceptionBase;

import <exception>;
import Formatter;

export
{
	template <typename... Args>
	[[noreturn]] void raise(const Args&... args)
	{
		throw std::exception(defaultFormatter.format(args...).c_str());
	}
}