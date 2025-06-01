export module Address;

export import <cstdint>;
import <compare>;

export
{

	struct Address
	{
		constexpr Address() = default;
		constexpr Address(uintptr_t value) : value(value) {}

		template <typename T>
		constexpr Address(T* value) : value((uintptr_t)value) {}

		constexpr void set(uintptr_t v) { value = v; }
		constexpr uintptr_t get() const { return value; }

		constexpr auto operator<=>(const Address&) const = default;
		constexpr auto operator<=>(uintptr_t other) const { return value <=> other; }

		constexpr Address& operator=(const Address& other) { value = other.value; return *this; }
		constexpr Address& operator+=(const Address& other) { value += other.value; return *this; }
		constexpr Address& operator-=(const Address& other) { value -= other.value; return *this; }
		constexpr Address operator+(auto v) { return Address(value + v); }
		constexpr Address operator-(auto v) { return Address(value - v); }
		constexpr void operator++() { value++; }
		constexpr void operator--() { value--; }
		constexpr void operator++(int) { value++; }
		constexpr void operator--(int) { value--; }

		constexpr operator uintptr_t() const { return value; }
		template <typename T>
		constexpr operator T* () const { return (T*)value; }

		template <typename T = uintptr_t>
		T* ptr() const { return (T*)value; }

		template <typename T = uintptr_t>
		T& ref() const { return *reinterpret_cast<T*>(value); }

		template <typename T = uintptr_t>
		T& refAt(ptrdiff_t offset) const { return *reinterpret_cast<T*>(value + offset); }

		template <typename T = uintptr_t>
		T& deref() const { return *(T*)value; }

		template <typename T = uintptr_t>
		T& derefAt(ptrdiff_t offset) const { return *(T*)(value + offset); }

		uintptr_t value = 0;
	};

}