#pragma once

#include <string.h>
extern "C" {
	#include <stddef.h>
	#include <stdint.h>
	#include <stdlib.h>
	#include <stdio.h>
	void *malloc(size_t length);
	void free(void *ptr);
	 
	void *realloc(void *ptr, size_t size);
	
}

// for things we need but can't have... yet...
// these are not identical to the standard ones and will have unexpected behavior

#ifdef DEBUG
void printBacktrace();
#ifdef CAN_EXIT
#pragma clang diagnostic ignored "-Wformat-security"
template <typename ...Types>
[[noreturn]] static void fatalf(const char *msg, Types... values) {
	__builtin_printf(msg, values...);
	//printBacktrace();
	exit(0);
}
#else
#pragma clang diagnostic ignored "-Wformat-security"
template <typename ...Types>
static void fatalf(const char *msg, Types... values) {
	__builtin_printf(msg, values...);
	//printBacktrace();
}
#endif
#endif

template <typename T>
class UniquePtr {

	T *ptr;

	public:
		explicit UniquePtr() : ptr(nullptr) {}
		UniquePtr(decltype(nullptr)) : ptr(nullptr) {}
		UniquePtr(T *ptr) : ptr(ptr) {}
		UniquePtr(const UniquePtr &rhs) = delete;
		UniquePtr &operator=(const UniquePtr &rhs) = delete;
		UniquePtr(UniquePtr &&rhs) noexcept : ptr(rhs.ptr) {
			rhs.ptr = nullptr;
		}
		UniquePtr &operator=(UniquePtr &&rhs) noexcept {
			delete ptr;
			ptr = rhs.ptr;
			rhs.ptr = nullptr;
			return *this;
		}
		~UniquePtr() { delete ptr;}

		explicit operator bool() const {
			return ptr != nullptr;
		}

		T &operator*() {
			#ifdef DEBUG
			if (ptr == nullptr) [[unlikely]] {
				fatalf("nullptr dereference\n");
			}
			#endif
			return *ptr;
		}

		const T &operator*() const {
			#ifdef DEBUG
			if (ptr == nullptr) [[unlikely]] {
				fatalf("nullptr dereference\n");
			}
			#endif
			return *ptr;
		}

		T *operator->() const {
			#ifdef DEBUG
			if (ptr == nullptr) [[unlikely]] {
				fatalf("nullptr dereference\n");
			}
			#endif
			return ptr;
		}

		bool operator==(decltype(nullptr)) const { return ptr == nullptr; }
		bool operator!=(decltype(nullptr)) const { return ptr != nullptr; }

		T *get() const {
			return ptr;
		}

		T *release() {
			T *tmp = ptr;
			ptr = nullptr;
			return tmp;
		}
};

template <typename T>
class UniquePtr<T[]> {

	T *ptr;

	public:
		UniquePtr() = delete;
		UniquePtr(decltype(nullptr)) : ptr(nullptr) {}
		UniquePtr(T *ptr) : ptr(ptr) {}
		UniquePtr(const UniquePtr &rhs) = delete;
		UniquePtr &operator=(const UniquePtr &rhs) = delete;
		UniquePtr(UniquePtr &&rhs) noexcept : ptr(rhs.ptr) {
			rhs.ptr = nullptr;
		}
		UniquePtr &operator=(UniquePtr &&rhs) noexcept {
			delete[] ptr;
			ptr = rhs.ptr;
			rhs.ptr = nullptr;
			return *this;
		}
		~UniquePtr() { delete[] ptr; }

		explicit operator bool() const {
			return ptr;
		}

		T &operator[](size_t i ) const {
			#ifdef DEBUG
			if (ptr == nullptr) [[unlikely]] {
				fatalf("nullptr dereference\n");
			}
			#endif
			return ptr[i];
		}

		bool operator==(decltype(nullptr)) const { return ptr == nullptr; }
		bool operator!=(decltype(nullptr)) const { return ptr != nullptr; }

		T *get() const {
			#ifdef DEBUG
			if (ptr == nullptr) [[unlikely]] {
				fatalf("nullptr dereference\n");
			}
			#endif
			return ptr;
		}

		T *release() {
			T *tmp = ptr;
			ptr = nullptr;
			return tmp;
		}
};


class StringView {
	const char * str;
	size_t size;

	public:
		constexpr StringView() : str(nullptr), size(0) {}
		constexpr StringView(decltype(nullptr)) : str(nullptr), size(0) {}

		constexpr StringView(const char *str) : str(str), size(__builtin_strlen(str)) {}

		constexpr StringView(const char *str, unsigned long length) : str(str), size(length) {}

		constexpr char operator[](size_t i) const {
			return str[i];
		}

		explicit operator bool() const {
			return str;
		}

		constexpr size_t length() const {
			return size;
		}

		operator const char*() const {
			return str;
		}

		constexpr const char *c_str() const {
			return str;
		}

		constexpr bool operator==(decltype(nullptr)) const {
			return str == nullptr;
		}

		constexpr bool operator==(const StringView &rhs) const {
			if (size != rhs.size) {
				return false;
			}
			if (str == rhs.str) {
				return true;
			}
			if (str == nullptr || rhs.str == nullptr) {
				return false;
			}
			return __builtin_memcmp(str, rhs.str, size) == 0;
		}

		bool contains(const char *needle) const {
			return __builtin_strstr(str, needle);
		}

		constexpr bool endswith(const StringView &view) const {
			const size_t sz = view.length();
			const char *buf = view.c_str();
			return sz > size ? false : __builtin_memcmp(str + (size - sz), buf, sz) == 0;
		}

		constexpr bool startswith(const StringView &view) const {
			const size_t sz = view.length();
			const char *buf = view.c_str();
			return sz > size ? false : __builtin_memcmp(str, buf, sz) == 0;
		}

		constexpr int32_t operator<=>(const StringView &rhs) const {
			return __builtin_strcmp(str, rhs.str);
		}
};

constexpr StringView operator"" _sv(const char *str, unsigned long len) { return {str, len}; }

// NOLINTBEGIN(cppcoreguidelines-owning-memory, cppcoreguidelines-pro-type-member-init)

//
class String {

	static constexpr size_t SSO_MAX = 16;

	union StringBuf {
		char *ptr;
		char buf[SSO_MAX];
	};

	StringBuf data;
	size_t size;
	size_t capacity;

	static constexpr size_t align(size_t x) {
		auto r = x % SSO_MAX;
    	return r ? x + (SSO_MAX - r) : x;
	}

	bool is_sso() const { return capacity == SSO_MAX; }

	void grow(size_t target) {
		const size_t newCapacity = align(target);
		if (capacity >= newCapacity) {
			return;
		}
		if (is_sso()) {
			char *tmp = new char[newCapacity];
			__builtin_memcpy(tmp, data.buf, size);
			tmp[size] = '\0';
			data.ptr = tmp;
		} else {
			char *tmp = new char[newCapacity];
			__builtin_memcpy(tmp, data.ptr, size);
			tmp[size] = '\0';
			delete[] data.ptr;
			data.ptr = tmp;
		}
		capacity = newCapacity;
	}

	char *buffer() {
		return is_sso() ? data.buf : data.ptr;
	}

	const char *buffer() const {
		return is_sso() ? data.buf : data.ptr;
	}

	public:
		explicit String() noexcept : data(), size(0), capacity(SSO_MAX) { data.buf[0] = '\0'; }
		String(int v) noexcept : data(), size(snprintf(data.buf, SSO_MAX, "%d", v)), capacity(SSO_MAX) {
		}
		String(uint32_t v) noexcept : data(), size(snprintf(data.buf, SSO_MAX, "%u", v)), capacity(SSO_MAX) {
		}
		String(const StringView &view) noexcept : size(view.length()), capacity(align(view.length()+1)) {
			if (is_sso()) {
				__builtin_memcpy(data.buf, view.c_str(), size);
				*(data.buf + size) = '\0';
			} else {
				data.ptr = new char[capacity];
				__builtin_memcpy(data.ptr, view.c_str(), size);
				data.ptr[size] = '\0';
			}
		}
		String(const String &rhs) : size(rhs.size), capacity(rhs.capacity) {
			if (is_sso()) {
				__builtin_memcpy(data.buf, rhs.c_str(), size+1);
				capacity = SSO_MAX;
			} else {
				data.ptr = new char[rhs.capacity];
				__builtin_memcpy(data.ptr, rhs.c_str(), size+1);
			}
		}
		String &operator=(const String &rhs) {
			size = rhs.size;
			capacity = rhs.capacity;
			if (is_sso()) {
				__builtin_memcpy(data.buf, rhs.c_str(), size+1);
				capacity = SSO_MAX;
			} else {
				data.ptr = new char[rhs.capacity];
				__builtin_memcpy(data.ptr, rhs.c_str(), size+1);
			}
			return *this;
		}
		String(String &&rhs) noexcept : size(rhs.size), capacity(rhs.capacity) {
			if (is_sso()) {
				__builtin_memcpy(data.buf, rhs.c_str(), size+1);
				capacity = SSO_MAX;
			} else {
				capacity = rhs.capacity;
				data.ptr = rhs.data.ptr;
				rhs.data.ptr = nullptr;
			}
		}
		String &operator=(String &&rhs) noexcept {
			size = rhs.size;
			capacity = rhs.capacity;
			if (is_sso()) {
				__builtin_memcpy(data.buf, rhs.c_str(), size+1);
				capacity = SSO_MAX;
			} else {
				capacity = rhs.capacity;
				data.ptr = rhs.data.ptr;
				rhs.data.ptr = nullptr;
			}
			return *this;
		}
		~String() {
			if (!is_sso()) {
				delete[] data.ptr;
			}
		}

		String &operator+=(const String &rhs) {
			const size_t newsz = size + rhs.length();
			if (newsz >= capacity) {
				grow(newsz + 1); // an additional character must be reserved for '\0'
			}
			char *__restrict ptr = buffer();
			__builtin_memcpy(ptr + size, rhs.c_str(), rhs.length());
			size = newsz; // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
			ptr[size] = '\0';
			return *this; // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
		}

		String &operator+=(const StringView &rhs) {
			const size_t newsz = size + rhs.length();
			if (newsz >= capacity) {
				grow(newsz + 1); // an additional character must be reserved for '\0'
			}
			char *__restrict ptr = buffer();
			__builtin_memcpy(ptr + size, rhs.c_str(), rhs.length());
			size = newsz; // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
			ptr[size] = '\0';
			return *this; // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
		}

		String operator+(const StringView &rhs) const noexcept {
			String res = *this;
			res += rhs;
			return res;
		}

		String &operator+=(const char c) {
			const size_t newsz = size + 1;
			if (newsz >= capacity) {
				grow(newsz + 1); // an additional character must be reserved for '\0'
			}
			char *__restrict ptr = buffer();
			ptr[size++] = c;
			ptr[size] = '\0';
			return *this; // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
		}

		bool operator==(const StringView &rhs) const {
			if (size != rhs.length()) {
				return false;
			}
			return __builtin_memcmp(buffer(), rhs.c_str(), size) == 0;
		}

		const char *c_str() const {
			return is_sso() ? data.buf : data.ptr;
		}

		size_t length() const {
			return size;
		}

		bool contains(const char *needle) const {
			return __builtin_strstr(buffer(), needle);
		}

		bool endswith(const StringView &view) const {
			const size_t sz = view.length();
			const char *buf = view.c_str();
			return sz > size ? false : __builtin_memcmp(buffer() + (size - sz), buf, sz) == 0;
		}

		bool startswith(const StringView &view) const {
			const size_t sz = view.length();
			const char *buf = view.c_str();
			return sz > size ? false : __builtin_memcmp(buffer(), buf, sz) == 0;
		}

		operator StringView() const {
			return {buffer(), size};
		}

		StringView subview(size_t from) const {
			return subview(from, size);
		}

		StringView subview(size_t from, size_t to) const {
			return {buffer() + from, to - from};
		}

		String substring(size_t from) const {
			return substring(from, size);
		}

		String substring(size_t from, size_t to) const {
			return StringView{buffer() + from, to - from};
		}

		ssize_t rfind(char c) const noexcept {
			const char *ptr = strrchr(buffer(), c);
			if (ptr == nullptr) {
				return -1;
			}
			return ptr - buffer();
		}

		void reserve(size_t i) {
			if (i > 0) [[likely]] {
				grow(i);
			}
		}

		String operator+(const String& rhs) const noexcept {
			String cpy{*this};
			cpy += rhs;
			return cpy;
		}
};

inline String operator+(const StringView& lhs, const StringView& rhs) noexcept {
	String cpy{lhs};
	cpy += rhs;
	return cpy;
}

// NOLINTEND(cppcoreguidelines-owning-memory, cppcoreguidelines-pro-type-member-init)

//
template <typename T>
class Array {

	UniquePtr<T[]> ptr;
	size_t size;

	public:
		Array(decltype(nullptr)) : ptr(nullptr), size(0) {}
		Array(size_t size) : ptr(new T[size]), size(size) {}
		Array(const Array &rhs) = delete;
		Array &operator=(const Array &rhs) = delete;
		Array(Array &&rhs) noexcept = default;
		Array &operator=(Array &&rhs) noexcept = default;
		~Array() noexcept = default;

		size_t length() const {
			return size;
		}
		T &operator[](size_t i) const {
			#ifdef DEBUG
			if (i >= size) [[unlikely]] {
				fatalf("index %llu is out of bounds for length %llu\n", i, size);
			}
			#endif
			return ptr[i];
		}
		T *begin() const {
			return ptr.get();
		}
		T *end() const {
			return ptr.get() + size;
		}
		explicit operator bool() const {
			return (bool)ptr && size > 0;
		}
		bool operator==(decltype(nullptr)) const {
			return ptr == nullptr;
		}
		T *data() { return ptr.get(); }
		size_t shrink(size_t newSize) {
			if (newSize < size) {
				size = newSize;
			}
			return size;
		}
};

template <typename T>
class List;

template <typename T>
class _List_iterator;

template <typename T>
class _List_node {
	friend class List<T>;
	friend class _List_iterator<T>;

	UniquePtr<_List_node<T>> next;
	// don't need a doubly linked list
	T value;

	public:
		_List_node(T t) : next(nullptr), value(t) {}
		_List_node(_List_node<T> *next, T t) : next(next), value(t) {}

		template <typename ...Types>
		_List_node(_List_node<T> *next, Types ...values) : next(next), value(values...) {}

		T &operator*() { return value; }
};

template <typename T>
class _List_iterator {
	_List_node<T> *it;

	public:
		_List_iterator(decltype(nullptr)) :it(nullptr) {}
		_List_iterator(_List_node<T> *it) : it(it) {}
		T &operator*() const { return **it; }
		_List_iterator<T> operator++(int) {
			_List_iterator<T> tmp = *this;
			it = it->next;
			return tmp;
		}
		_List_iterator<T> &operator++() {
			it = it->next.get();
			return *this;
		}
		bool operator!=(const _List_iterator<T> &rhs) const {
			// use reference equality of the nodes
			return it != rhs.it;
		}
};

template <typename T>
class List {
	UniquePtr<_List_node<T>> head;
	size_t size;

	public:
		List() : head(nullptr), size(0) {}

		size_t length() const { return size; }

		template<typename ...Types>
		T &emplace_front(Types ...values) {
			// much cheaper to emplace in front
			size++;
			head = {new _List_node<T>(head.release(), values...)};
			return head->value;
		}

		T &push_front(const T &value) {
			size++;
			head = {new _List_node<T>(head.release(), value)};
			return head->value;
		}

		_List_iterator<T> begin() const {
			return head.get();
		}

		_List_iterator<T> end() const {
			return nullptr;
		}

		const T& operator[](size_t i) const {
			auto it = begin();
			for (size_t j = 0; j < i; j++) {
				it++;
			}
			return *it;
		}
};

template <typename T>
class Vector {

	static constexpr size_t DEFAULT_CAPACITY = 16;

	T *first;
	T *last;
	T *eos;

	size_t available() const noexcept {
		return eos - last;
	}

	void grow(size_t cap) noexcept {
		if (cap <= capacity()) {
			return;
		}
		first = reallocate(first, cap);
		eos = first + cap;
	}

	constexpr void setSize(const size_t count, const size_t length, const T &value) noexcept {
		if (length > count) {
			if constexpr(!__is_trivially_destructible(T)) {
				for (size_t i = count; i < length; i++) {
					first[i].~T();
				}
			}
		} else {
			grow(count);
			for (size_t i = length; i < count; i++) {
				first[i] = value;
			}
		}
		last = first + count;
	}

	static T *allocate(size_t n) noexcept {
		return reinterpret_cast<T *>(malloc(n * sizeof(T))); // NOLINT
	}

	static T *reallocate(T *ptr, size_t n) noexcept {
		// if it fails we're screwed anyway
		// no exceptions so we'll just run until fault
		return reinterpret_cast<T *>(realloc(ptr, n * sizeof(T))); // NOLINT
	}

	public:
		Vector() noexcept : first(allocate(DEFAULT_CAPACITY)), last(first), eos(first + DEFAULT_CAPACITY) {} // NOLINT

		Vector(const Vector<T> &rhs) noexcept : first(allocate(rhs.capacity())), last(first), eos(first + rhs.capacity()) { // NOLINT
			if constexpr(__is_trivially_copyable(T)) {
				__builtin_memcpy(first, rhs.first, rhs.size() * sizeof(T));
			} else {
				const size_t length = rhs.size();
				for (size_t i = 0; i < length; i++) {
					first[i] = rhs[i];
				}
			}
		}

		Vector &operator=(const Vector<T> &rhs) noexcept {
			if (this == &rhs) [[unlikely]] {
				return *this;
			}

			const size_t length = rhs.size();

			if (capacity() < length) {
				clear();
			}

			first = grow(rhs.capacity()); // NOLINT
			last = first + length;

			if constexpr(__is_trivially_copyable(T)) {
				__builtin_memcpy(first, rhs.first, length * sizeof(T));
			} else {
				for (size_t i = 0; i < length; i++) {
					first[i] = rhs[i];
				}
			}

			return *this;
		}

		Vector(Vector<T> &&rhs) noexcept : first(rhs.first), last(rhs.last), eos(rhs.eos) {
			rhs.first = nullptr;
		}

		Vector &operator=(Vector<T> &&rhs) noexcept {
			free(first);
			first = rhs.first;
			last = rhs.last;
			eos = rhs.eos;
			rhs.first = nullptr;
			return *this;
		}

		~Vector() noexcept {
			free(first);
		}

		constexpr T &at(size_t i) noexcept {
			return first[i];
		}

		constexpr const T &at(size_t i) const noexcept {
			return first[i];
		}

		constexpr T &operator[](size_t i) noexcept {
			return first[i];
		}

		constexpr const T &operator[](size_t i) const noexcept {
			return first[i];
		}

		constexpr T &front() noexcept {
			return *first;
		}

		constexpr const T &front() const noexcept {
			return *first;
		}

		constexpr T &back() noexcept {
			return *last;
		}

		constexpr const T &back() const noexcept {
			return *last;
		}

		constexpr T *data() noexcept {
			return first;
		}

		constexpr const T *data() const noexcept {
			return first;
		}

		constexpr T *begin() noexcept {
			return first;
		}

		constexpr const T *begin() const noexcept {
			return first;
		}

		constexpr const T *cbegin() const noexcept {
			return first;
		}

		constexpr T *end() noexcept {
			return last;
		}

		constexpr const T *end() const noexcept {
			return last;
		}

		constexpr const T *cend() const noexcept {
			return last;
		}

		constexpr bool empty() const noexcept {
			return first == last;
		}

		constexpr size_t size() const noexcept {
			return last - first;
		}

		constexpr void reserve(size_t length) noexcept {
			if (length <= capacity()) {
				return;
			}
			grow(length);
		}

		constexpr size_t capacity() const noexcept {
			return eos - first;
		}

		constexpr void shrink_to_fit() noexcept {
			if (size() <= capacity()) {
				return;
			}
			first = reallocate(first, size());
		}

		constexpr void clear() noexcept {
			if constexpr(!__is_trivially_destructible(T)) {
				const size_t length = size();
				for (size_t i = 0; i < length; i++) {
					first[i].~T();
				}
			}
			last = first;
		}

		// ok I got lazy

		//

		constexpr T *erase(const T *pos) noexcept {
			const size_t i = pos - first;
			if constexpr(!__is_trivially_destructible(T)) {
				first[i].~T();
			}
			if (first + i != --last) {
				__builtin_memcpy(last - i, first + i, size() * sizeof(T));
			}
			return last;
		}

		template<class... Args>
		constexpr T &emplace_back(Args&&... args) noexcept {
			return *last++ = T{args...};
		}

		constexpr void push_back(const T &value) noexcept {
			*last++ = value;
		}

		constexpr void push_back(T &&value) noexcept {
			*last++ = static_cast<T&&>(value);
		}

		constexpr void pop_back() noexcept {
			last--;
			if constexpr(!__is_trivially_destructible(T)) {
				(*last)->~T();
			}
		}

		constexpr void resize(size_t count) noexcept {
			const size_t length = size();
			if (length == count) {
				return;
			}
			setSize(count, length, T());
		}

		constexpr void resize(size_t count, const T &value) noexcept {
			const size_t length = size();
			if (length == count) {
				return;
			}
			setSize(count, length, value);
		}

		constexpr void swap(Vector<T> &other) noexcept {
			swap(*this, other);
		}
};

// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers)

//
[[maybe_unused]] static void hexdump(const void *ptr, size_t len) {
	const uint8_t *buf = reinterpret_cast<const uint8_t *>(ptr);
	auto rows = len / 16;
	for (size_t i = 0; i < rows; i++) {
		auto j = i * 16;
		__builtin_printf(
			"%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
			buf[j], buf[j+1], buf[j+2], buf[j+3], buf[j+4], buf[j+5], buf[j+6], buf[j+7],
			buf[j+8], buf[j+9], buf[j+10], buf[j+11], buf[j+12], buf[j+13], buf[j+14], buf[j+15]
		);
	}
	buf += rows * 16;
	for (size_t i = 0; i < len % 16; i++) {
		__builtin_printf("%02X ", buf[i]);
	}
	puts("");
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


// NOLINTEND(cppcoreguidelines-avoid-magic-numbers)
