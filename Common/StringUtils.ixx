export module StringUtils;

import <string>;
import <algorithm>;
import <iterator>;

export
{
	inline bool strcmp_caseInsensitive(const std::string& str1, const std::string& str2) {
		return std::equal(str1.begin(), str1.end(), str2.begin(), str2.end(),
			[](char c1, char c2) {
				return tolower(c1) == tolower(c2);
			});
	}

	inline bool strcmp_caseInsensitive(const char* str1, const char* str2) {
		while (*str1 && *str2) {
			if (tolower(*str1) != tolower(*str2))
				return false;

			str1++;
			str2++;
		}

		return (*str1 == '\0' && *str2 == '\0');
	}

	inline std::string tostring(const std::wstring& from)
	{
		std::string result;
		std::transform(from.begin(), from.end(), std::back_inserter(result), [](wchar_t c) {
			return (char)c;
		});
		return result;
	}
}