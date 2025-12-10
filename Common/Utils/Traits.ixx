export module Utils.Traits;

export import <type_traits>;

export
{
	template <typename Value>
	using ValueHandler = void(*)(Value&);

	template <typename Value>
	using ConstValueHandler = void(*)(const Value&);

	template <typename Key>
	using ErrorKeyHandler = ConstValueHandler<Key>;

	template <typename Index>
	using ErrorIndexHandler = ConstValueHandler<Index>;

	template <typename T, typename Hasher>
	concept Hashable_c = requires(T t, Hasher h)
	{
		{ h(t) } -> std::convertible_to<size_t>;
	};

	template <typename T>
	concept Eq_c = requires(T a, T b)
	{
		a == b;
	};
}