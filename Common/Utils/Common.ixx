export module Utils.Common;

import <type_traits>;

export
{
	template <typename T, typename... Args>
	constexpr void checkConstructible(Args&&...) {
		static_assert(std::is_constructible_v<T, Args...>, "Value must be constructible from the provided arguments");
	}

	template <typename T, typename... Args>
	constexpr T* constructAt(T* const location, Args&&... args)
	{
		checkConstructible<T>(std::forward<Args>(args)...);
		return new (static_cast<void*>(location)) T(std::forward<Args>(args)...);
	}

	template <typename T>
	constexpr T* allocate() {
		return static_cast<T*>(operator new(sizeof(T)));
	}
}
