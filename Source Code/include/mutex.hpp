#pragma once

#include <pthread.h>

template <typename T>
concept MutexType = requires(T &t) {
	{ t.lock() };
	{ t.unlock() };
};

template <MutexType Mtx>
class LockGuard {
	Mtx *mtx;

public:
	LockGuard(Mtx &mtx) noexcept : mtx(&mtx) {
		mtx.lock();
	}
	LockGuard(const LockGuard&) = delete;
	LockGuard &operator=(const LockGuard&) = delete;
	LockGuard(LockGuard &&rhs) noexcept : mtx(rhs.mtx) { rhs.mtx = nullptr; }
	LockGuard &operator=(LockGuard &&rhs) noexcept {
		if (mtx) {
			mtx->unlock();
		}
		mtx = rhs.mtx;
		rhs.mtx = nullptr;
	}
	~LockGuard() noexcept {
		if (mtx) [[likely]] {
			mtx->unlock();
			mtx = nullptr;
		}
	}
};

template <
	typename native_handle_type,
	typename attr_type,
	int initializer(native_handle_type*, const attr_type*),
	int destroyer(native_handle_type*),
	int locker(native_handle_type*),
	int try_locker(native_handle_type*),
	int unlocker(native_handle_type*),
	pthread_mutextype mutextype = pthread_mutextype(0)
>
class BaseMutex {

protected:
	native_handle_type handle;

	void init() noexcept {
		if (handle) [[likely]] {
			return;
		}
		attr_type attr = nullptr;
		if constexpr(mutextype != 0) {
			pthread_mutexattr_init(&attr);
			pthread_mutexattr_settype(&attr, mutextype);
		}
		initializer(&handle, &attr);
		if constexpr(mutextype != 0) {
			pthread_mutexattr_destroy(&attr);
		}
	}

public:
	constexpr BaseMutex() noexcept : handle(nullptr) {}
	BaseMutex(const BaseMutex&) = delete;
	BaseMutex &operator=(const BaseMutex&) = delete;
	constexpr BaseMutex(BaseMutex &&rhs) noexcept : handle(rhs.handle) { rhs.handle = nullptr; }
	BaseMutex &operator=(BaseMutex &&rhs) noexcept {
		if (handle) {
			destroyer(&handle);
		}
		handle = rhs.handle;
		return *this;
	}
	~BaseMutex() noexcept {
		if (handle) [[likely]] {
			destroyer(&handle);
			handle = nullptr;
		}
	}

	native_handle_type native_handle() noexcept { return handle; }
	void lock() noexcept {
		init();
		locker(&handle);
	}
	bool try_lock() noexcept {
		init();
		return try_locker(&handle) == 0;
	}
	void unlock() noexcept {
		unlocker(&handle);
	}
};

class Mutex :
	public BaseMutex<
		pthread_mutex_t,
		pthread_mutexattr_t,
		pthread_mutex_init,
		pthread_mutex_destroy,
		pthread_mutex_lock,
		pthread_mutex_trylock,
		pthread_mutex_unlock
	>
{};

class RecursiveMutex :
	public BaseMutex<
		pthread_mutex_t,
		pthread_mutexattr_t,
		pthread_mutex_init,
		pthread_mutex_destroy,
		pthread_mutex_lock,
		pthread_mutex_trylock,
		pthread_mutex_unlock,
		PTHREAD_MUTEX_RECURSIVE
	>
{};

class RWMutex :
	public BaseMutex<
		pthread_rwlock_t ,
		pthread_rwlockattr_t ,
		pthread_rwlock_init,
		pthread_rwlock_destroy,
		pthread_rwlock_wrlock,
		pthread_rwlock_trywrlock,
		pthread_rwlock_unlock
	> {

	class RLocker {
		pthread_rwlock_t *handle;
	public:
		RLocker(pthread_rwlock_t *handle) noexcept : handle(handle) {}
		RLocker(const RLocker&) = delete;
		RLocker &operator=(const RLocker&) = delete;
		RLocker(RLocker &&rhs) noexcept : handle(rhs.handle) { rhs.handle = nullptr; }
		RLocker &operator=(RLocker &&rhs) noexcept = delete;
		~RLocker() noexcept = default;
		void lock() noexcept {
			pthread_rwlock_rdlock(handle);
		}
		void unlock() noexcept {
			pthread_rwlock_unlock(handle);
		}
	};

public:
	void rdlock() noexcept {
		init();
		pthread_rwlock_rdlock(&handle);
	}
	bool try_rdlock() noexcept {
		init();
		return pthread_rwlock_tryrdlock(&handle) == 0;
	}
	RLocker rlocker() noexcept {
		init();
		return &handle;
	}
};
