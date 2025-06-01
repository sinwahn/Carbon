export module Logger;

import <filesystem>;
import <fstream>;
import <iostream>;
import <mutex>;
import Formatter;

class Logger
{
public:
	Logger()
	{

	}

	~Logger()
	{
		if (output.is_open())
			output.close();
	}

	void initialize(const std::wstring& _outputPath)
	{
		outputPath = _outputPath;
		openBuffer();
	}

	template <typename... Args>
	void log(const Args&... args)
	{
		std::scoped_lock lock(mutex);
		if (output.is_open())
			output << formatter.format(args...) << std::endl;
	}

private:

	void openBuffer()
	{
		output.open(outputPath, std::ios::out);
	}

	std::wstring outputPath;
	std::ofstream output;
	Formatter formatter;
	std::mutex mutex;
};

export inline Logger logger;