module;
#include "../Common/CarbonWindows.h"
export module Console;

import <iomanip>;
import <iostream>;

export class Console
{
public:
	enum class Color
	{
		Grey,
		Blue,
		Green,
		Cyan,
		Red,
		Pink,
		Yellow,
		White,
	};

	static Console& getInstance();
	static Console* createConsole(const std::string& title = defaultTitle);
	~Console();

	void setDec() const;
	void setHex() const;
	void setColor(Color color);
	Color getColor() const;

	template <typename T>
	decltype(std::cout)& operator <<(const T& value)
	{
		createConsole();
		std::cout << value;
		return std::cout;
	}
private:

	Console(const std::string& title);

	FILE* file = nullptr;
	HANDLE handle = nullptr;
	Color currentColor = Color::White;

	static inline Console* instance = nullptr;
	static inline const std::string defaultTitle = "carbon";

};

Console* Console::createConsole(const std::string& title)
{
	if (instance)
		return instance;

	instance = new Console(title);
	return instance;
}

Console& Console::getInstance()
{
	if (instance)
		return *instance;

	return *createConsole(defaultTitle);
}

Console::Console(const std::string& title)
{
	AllocConsole();
	freopen_s(&file, "CONOUT$", "w", stdout);
	freopen_s(&file, "CONOUT$", "w", stderr);
	freopen_s(&file, "CONIN$", "r", stdin);

	SetConsoleTitleA(title.c_str());
	handle = GetStdHandle(STD_OUTPUT_HANDLE);
}

Console::~Console()
{
	fclose(file);
	FreeConsole();
}

void Console::setDec() const
{
	std::cout << std::setbase(10);
}

void Console::setHex() const
{
	std::cout << std::setbase(16);
}

void Console::setColor(Color color)
{
	currentColor = color;
	switch (color)
	{
	case Color::Grey: SetConsoleTextAttribute(handle, 8); break;
	case Color::Blue: SetConsoleTextAttribute(handle, 9); break;
	case Color::Green: SetConsoleTextAttribute(handle, 10); break;
	case Color::Cyan: SetConsoleTextAttribute(handle, 11); break;
	case Color::Red: SetConsoleTextAttribute(handle, 12); break;
	case Color::Pink: SetConsoleTextAttribute(handle, 13); break;
	case Color::Yellow: SetConsoleTextAttribute(handle, 14); break;
	case Color::White:
	default: SetConsoleTextAttribute(handle, 7); break;
	}
}

Console::Color Console::getColor() const
{
	return currentColor;
}