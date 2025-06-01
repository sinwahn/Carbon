export module Exception;

import <string>;
import Logger;
export import ExceptionBase;

export
{
	template <typename Callable>
	void basicTryWrapper(const std::string& name, Callable&& function)
	{
		try
		{
			function();
		}
		catch (std::exception& e)
		{
			logger.log(name, e.what());
		}
		catch (...)
		{
			logger.log(name, "caught something bad");
		}
	}
}