module;
#include "Compiler/Compiler.h"
export module Luau.Compile;

export std::string compile(const std::string& source)
{
	return Luau::compile(source);
}