module Api;

import Temp;

import Section;

void tryDumpLuau_api(Section& textSection)
{
	auto _VERSION_possibleAddresses = getPossibleAddresses_VERSION();
	dumpLuauFromVersion(_VERSION_possibleAddresses);
	findAllLibs();
	identifyUnnamedLibs();
	runDumpFromLibs();
	dumpFlog1();
}