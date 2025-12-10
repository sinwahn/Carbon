export module Utils.UnorderedMap;

import <unordered_map>;
export import <stdexcept>;
import <functional>;

import Utils.Traits;
import Utils.Common;

export template<
	typename Key,
	typename Value,
	typename Hasher = std::hash<Key>,
	typename Base = Key,
	ErrorKeyHandler<Base> invalidKeyHandler = nullptr,
	ErrorKeyHandler<Base> duplicateKeyHandler = nullptr
>
class UnorderedMap_PolymorphicErrorHandlers
{
protected:
	using container_t = std::unordered_map<Key, Value, Hasher>;
	container_t map;
public:
	using key_t = Key;
	using value_t = Value;

	using iter_t = typename container_t::iterator;
	using citer_t = typename container_t::const_iterator;

	static_assert(
		Eq_c<Key>,
		"Key type must have '==' operator defined"
	);

	static_assert(
		Hashable_c<Key, Hasher>,
		"Key type must be hashable (provide std::hash<Key> specialization, SEE !!copy-paste one bellow!! OR write custom hasher)"
	);
	/*
	namespace std {
		template <>
		struct hash<Key> {
			std::size_t operator()(const Key& value) const noexcept {
				return std::hash<std::string>()(value);
			}
		};
	}
	*/

	Value* find(const Key& key)
	{
		auto pos = findPos(key);
		if (isEnd(pos))
			return nullptr;
		return &pos->second;
	}

	const Value* find(const Key& key) const
	{
		auto pos = findPos(key);
		if (isEnd(pos))
			return nullptr;
		return &pos->second;
	}

	iter_t findPos(const Key& key) {
		return map.find(key);
	}

	citer_t findPos(const Key& key) const {
		return map.find(key);
	}

	iter_t findPosByValue(const Value& value)
	{
		auto it = begin();
		for (; it != end(); it++)
			if (it->second == value)
				break;
		return it;
	}

	citer_t findPosByValue(const Value& value) const
	{
		auto it = begin();
		for (; it != end(); it++)
			if (it->second == value)
				break;
		return it;
	}

	Value& get(const Key& key)
	{
		if (auto existing = find(key))
			return *existing;
		throwInvalidKey(key);
	}

	const Value& get(const Key& key) const
	{
		if (auto existing = find(key))
			return *existing;
		throwInvalidKey(key);
	}

	void remove(const Key& key)
	{
		auto pos = findPos(key);
		if (isEnd(pos))
			throwInvalidKey(key);
		erase(pos);
	}

	Value removeAndCreateCopy(const Key& key)
	{
		auto pos = findPos(key);
		if (isEnd(pos))
			throwInvalidKey(key);
		Value value = std::move(pos->second);
		erase(pos);
		return value;
	}

	bool isFront(const citer_t& pos) const {
		return pos == cbegin();
	}

	bool isEnd(const citer_t& pos) const {
		return pos == cend();
	}

	iter_t erase(iter_t pos) {
		return map.erase(pos);
	}

	bool tryRemoveByValue(const Value& value)
	{
		auto pos = findPosByValue(value);
		if (isEnd(pos))
			return false;
		erase(pos);
		return true;
	}

	void removeByValue(const Value& value)
	{
		if (!tryRemoveByValue(value))
			throw std::runtime_error("value does not exist");
	}

	[[nodiscard]] constexpr auto begin() noexcept {
		return map.begin();
	}

	[[nodiscard]] constexpr auto end() noexcept {
		return map.end();
	}

	[[nodiscard]] constexpr const auto begin() const noexcept {
		return map.begin();
	}

	[[nodiscard]] constexpr const auto end() const noexcept {
		return map.end();
	}
	
	[[nodiscard]] constexpr auto cbegin() const noexcept {
		return map.cbegin();
	}

	[[nodiscard]] constexpr auto cend() const noexcept {
		return map.cend();
	}

	[[nodiscard]] constexpr bool isEmpty() const noexcept {
		return map.empty();
	}

	size_t removeAllByValue(const Value& value)
	{
		size_t count = 0;
		auto it = map.begin();
		while (it != map.end())
		{
			if (it->second == value)
			{
				it = map.erase(it);
				count++;
			}
			else
				it++;
		}
		return count;
	}

	template <typename... Args>
	Value& create(const Key& key, Args&&... args)
	{
		if (auto existing = find(key))
			throwDuplicateKey(key);
		
		return setOrCreate(key, std::forward<Args>(args)...);
	}

	void forEach(const std::function<void(const Key&, Value&)>& func)
	{
		for (auto& pair : map)
			func(pair.first, pair.second);
	}

	void forEach(const std::function<void(const Key&, const Value&)>& func) const
	{
		for (const auto& pair : map)
			func(pair.first, pair.second);
	}

	void insert(const Key& key, const Value& value) {
		map[key] = value;
	}

	Value& getOrCreate(const Key& key) {
		return map[key];
	}

	template <typename... Args>
	Value& setOrCreate(const Key& key, Args&&... args)
	{
		checkConstructible<Value>(std::forward<Args>(args)...);
		return emplace(key, std::forward<Args>(args)...).first->second;
	}

	void insert(std::move_iterator<iter_t> begin, std::move_iterator<iter_t> end) {
		map.insert(begin, end);
	}

	bool contains(const Key& key) const {
		return !isEnd(findPos(key));
	}

	size_t size() const {
		return map.size();
	}

	void clear() {
		map.clear();
	}

protected:

	template <typename... Args>
	auto emplace(const Key& key, Args&&... args)
	{
		static_assert(std::is_constructible_v<Value, Args...>, "Value must be constructible from the provided arguments");
		return map.emplace(
			std::piecewise_construct,
			std::forward_as_tuple(key),
			std::forward_as_tuple(std::forward<Args>(args)...)
		);
	}

	[[noreturn]] void throwInvalidKey(const Key& key) const
	{
		if constexpr (invalidKeyHandler)
			invalidKeyHandler(key);
		else
			throw std::runtime_error("key does not exist");
	}

	[[noreturn]] void throwDuplicateKey(const Key& key) const
	{
		if constexpr (duplicateKeyHandler)
			duplicateKeyHandler(key);
		else
			throw std::runtime_error("duplicate key");
	}

};

export template<
	typename Key,
	typename Value,
	ErrorKeyHandler<Key> invalidKeyHandler = nullptr,
	ErrorKeyHandler<Key> duplicateKeyHandler = nullptr
>
class UnorderedMap : public UnorderedMap_PolymorphicErrorHandlers<Key, Value, std::hash<Key>, Key, invalidKeyHandler, duplicateKeyHandler>
{

};

export template<
	typename Key,
	typename Value,
	typename Hasher,
	ErrorKeyHandler<Key> invalidKeyHandler = nullptr,
	ErrorKeyHandler<Key> duplicateKeyHandler = nullptr
>

class UnorderedMap_Hasher : public UnorderedMap_PolymorphicErrorHandlers<Key, Value, Hasher, Key, invalidKeyHandler, duplicateKeyHandler>
{

};