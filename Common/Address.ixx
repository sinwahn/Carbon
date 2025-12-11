export module Address;

export import <cstdint>;
import <compare>;
import <excpt.h>;
import <utility>;

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

		template <typename T = uintptr_t>
		std::pair<bool, T*> tryDeref() const
		{
			if (isLocalValid())
				return { true, (T*)value };
			return { false, nullptr };
		}

		template <typename T = uintptr_t>
		std::pair<bool, T*> tryDerefAt(ptrdiff_t offset) const
		{
			if (isLocalValid(value + offset))
				return { true, (T*)(value + offset) };
			return { false, {} };
		}

		bool isLocalValid() const {
			return isLocalValid(value);
		}

		static bool isLocalValid(uintptr_t address)
		{
			__try {
				*(volatile const char*)address;
				return true;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				return false;
			}
		}

		bool isNullptr() const { return value == 0; }

		uintptr_t value = 0;
	};

	namespace std {
		template <>
		struct hash<Address> {
			std::size_t operator()(const Address& of) const noexcept {
				return std::hash<uintptr_t>()(of.value);
			}
		};
	}
}