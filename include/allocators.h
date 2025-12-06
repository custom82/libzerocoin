// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_ALLOCATORS_H
#define BITCOIN_ALLOCATORS_H

#include <string.h>
#include <string>
#include <memory>
#include <mutex>
#include <map>
#include <openssl/crypto.h> // for OPENSSL_cleanse()

#ifdef WIN32
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN 1
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// This is used to attempt to keep keying material out of swap
// Note that VirtualLock does not provide this as a guarantee on Windows,
// but, in practice, memory that has been VirtualLock'd almost never gets written to
// the pagefile except in rare circumstances where memory is extremely low.
#else
#include <sys/mman.h>
#include <limits.h> // for PAGESIZE
#include <unistd.h> // for sysconf
#endif

/**
 * Thread-safe class to keep track of locked (ie, non-swappable) memory pages.
 *
 * Memory locks do not stack, that is, pages which have been locked several times by calls to mlock()
 * will be unlocked by a single call to munlock(). This can result in keying material ending up in swap when
 * those functions are used naively. This class simulates stacking memory locks by keeping a counter per page.
 *
 * @note By using a map from each page base address to lock count, this class is optimized for
 * small objects that span up to a few pages, mostly smaller than a page. To support large allocations,
 * something like an interval tree would be the preferred data structure.
 */
template <class Locker> class LockedPageManagerBase
{
public:
    LockedPageManagerBase(size_t page_size):
    page_size(page_size)
    {
        // Determine bitmask for extracting page from address
        assert(!(page_size & (page_size-1))); // size must be power of two
        page_mask = ~(page_size - 1);
    }

    // For all pages in affected range, increase lock count
    void LockRange(void *p, size_t size)
    {
        std::scoped_lock lock(mutex);
        if(!size) return;
        const size_t base_addr = reinterpret_cast<size_t>(p);
        const size_t start_page = base_addr & page_mask;
        const size_t end_page = (base_addr + size - 1) & page_mask;
        for(size_t page = start_page; page <= end_page; page += page_size)
        {
            Histogram::iterator it = histogram.find(page);
            if(it == histogram.end()) // Newly locked page
            {
                if (!locker.Lock(reinterpret_cast<void*>(page), page_size)) {
                    throw std::runtime_error("Failed to lock memory page");
                }
                histogram.insert(std::make_pair(page, 1));
            }
            else // Page was already locked; increase counter
            {
                it->second += 1;
            }
        }
    }

    // For all pages in affected range, decrease lock count
    void UnlockRange(void *p, size_t size)
    {
        std::scoped_lock lock(mutex);
        if(!size) return;
        const size_t base_addr = reinterpret_cast<size_t>(p);
        const size_t start_page = base_addr & page_mask;
        const size_t end_page = (base_addr + size - 1) & page_mask;
        for(size_t page = start_page; page <= end_page; page += page_size)
        {
            Histogram::iterator it = histogram.find(page);
            if(it == histogram.end()) {
                throw std::runtime_error("Cannot unlock an area that was not locked");
            }
            // Decrease counter for page, when it is zero, the page will be unlocked
            it->second -= 1;
            if(it->second == 0) // Nothing on the page anymore that keeps it locked
            {
                // Unlock page and remove the count from histogram
                if (!locker.Unlock(reinterpret_cast<void*>(page), page_size)) {
                    throw std::runtime_error("Failed to unlock memory page");
                }
                histogram.erase(it);
            }
        }
    }

    // Get number of locked pages for diagnostics
    int GetLockedPageCount()
    {
        std::scoped_lock lock(mutex);
        return static_cast<int>(histogram.size());
    }

    // Check if memory is locked
    bool IsLocked(void* p, size_t size)
    {
        std::scoped_lock lock(mutex);
        if(!size) return false;
        const size_t base_addr = reinterpret_cast<size_t>(p);
        const size_t start_page = base_addr & page_mask;
        const size_t end_page = (base_addr + size - 1) & page_mask;

        for(size_t page = start_page; page <= end_page; page += page_size)
        {
            if (histogram.find(page) == histogram.end()) {
                return false;
            }
        }
        return true;
    }

private:
    Locker locker;
    mutable std::mutex mutex;
    size_t page_size, page_mask;
    // map of page base address to lock count
    typedef std::map<size_t,int> Histogram;
    Histogram histogram;
};

/** Determine system page size in bytes */
static inline size_t GetSystemPageSize()
{
    size_t page_size;
    #if defined(WIN32)
    SYSTEM_INFO sSysInfo;
    GetSystemInfo(&sSysInfo);
    page_size = static_cast<size_t>(sSysInfo.dwPageSize);
    #elif defined(PAGESIZE) // defined in limits.h
    page_size = static_cast<size_t>(PAGESIZE);
    #else // assume some POSIX OS
    page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    #endif
    return page_size;
}

/**
 * OS-dependent memory page locking/unlocking.
 * Defined as policy class to make stubbing for test possible.
 */
class MemoryPageLocker
{
public:
    /** Lock memory pages.
     * addr and len must be a multiple of the system page size
     */
    bool Lock(const void *addr, size_t len)
    {
        #ifdef WIN32
        return VirtualLock(const_cast<void*>(addr), static_cast<SIZE_T>(len)) != 0;
        #else
        return mlock(addr, len) == 0;
        #endif
    }

    /** Unlock memory pages.
     * addr and len must be a multiple of the system page size
     */
    bool Unlock(const void *addr, size_t len)
    {
        #ifdef WIN32
        return VirtualUnlock(const_cast<void*>(addr), static_cast<SIZE_T>(len)) != 0;
        #else
        return munlock(addr, len) == 0;
        #endif
    }
};

/**
 * Singleton class to keep track of locked (ie, non-swappable) memory pages, for use in
 * std::allocator templates.
 */
class LockedPageManager: public LockedPageManagerBase<MemoryPageLocker>
{
public:
    static LockedPageManager& Instance()
    {
        static LockedPageManager instance;
        return instance;
    }

    // Delete copy constructor and assignment operator
    LockedPageManager(const LockedPageManager&) = delete;
    LockedPageManager& operator=(const LockedPageManager&) = delete;

private:
    LockedPageManager():
    LockedPageManagerBase<MemoryPageLocker>(GetSystemPageSize())
    {}
};

//
// Allocator that locks its contents from being paged
// out of memory and clears its contents before deletion.
//
template<typename T>
class secure_allocator
{
public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;

    secure_allocator() noexcept = default;

    template<typename U>
    secure_allocator(const secure_allocator<U>&) noexcept {}

    ~secure_allocator() noexcept = default;

    template<typename U>
    struct rebind {
        using other = secure_allocator<U>;
    };

    T* allocate(std::size_t n)
    {
        if (n > max_size()) {
            throw std::bad_alloc();
        }

        T* p = static_cast<T*>(::operator new(n * sizeof(T)));
        if (p != nullptr) {
            try {
                LockedPageManager::Instance().LockRange(p, n * sizeof(T));
            } catch (...) {
                ::operator delete(p);
                throw;
            }
        }
        return p;
    }

    void deallocate(T* p, std::size_t n) noexcept
    {
        if (p != nullptr) {
            // Clear memory securely
            OPENSSL_cleanse(p, n * sizeof(T));

            // Unlock memory pages
            LockedPageManager::Instance().UnlockRange(p, n * sizeof(T));

            ::operator delete(p);
        }
    }

    std::size_t max_size() const noexcept
    {
        return std::numeric_limits<std::size_t>::max() / sizeof(T);
    }

    template<typename U, typename... Args>
    void construct(U* p, Args&&... args)
    {
        ::new (static_cast<void*>(p)) U(std::forward<Args>(args)...);
    }

    template<typename U>
    void destroy(U* p)
    {
        p->~U();
    }
};

template<typename T, typename U>
bool operator==(const secure_allocator<T>&, const secure_allocator<U>&) noexcept
{
    return true;
}

template<typename T, typename U>
bool operator!=(const secure_allocator<T>&, const secure_allocator<U>&) noexcept
{
    return false;
}

//
// Allocator that clears its contents before deletion.
//
template<typename T>
class zero_after_free_allocator
{
public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;

    zero_after_free_allocator() noexcept = default;

    template<typename U>
    zero_after_free_allocator(const zero_after_free_allocator<U>&) noexcept {}

    ~zero_after_free_allocator() noexcept = default;

    template<typename U>
    struct rebind {
        using other = zero_after_free_allocator<U>;
    };

    T* allocate(std::size_t n)
    {
        if (n > max_size()) {
            throw std::bad_alloc();
        }
        return static_cast<T*>(::operator new(n * sizeof(T)));
    }

    void deallocate(T* p, std::size_t n) noexcept
    {
        if (p != nullptr) {
            // Clear memory securely
            OPENSSL_cleanse(p, n * sizeof(T));
            ::operator delete(p);
        }
    }

    std::size_t max_size() const noexcept
    {
        return std::numeric_limits<std::size_t>::max() / sizeof(T);
    }

    template<typename U, typename... Args>
    void construct(U* p, Args&&... args)
    {
        ::new (static_cast<void*>(p)) U(std::forward<Args>(args)...);
    }

    template<typename U>
    void destroy(U* p)
    {
        p->~U();
    }
};

template<typename T, typename U>
bool operator==(const zero_after_free_allocator<T>&, const zero_after_free_allocator<U>&) noexcept
{
    return true;
}

template<typename T, typename U>
bool operator!=(const zero_after_free_allocator<T>&, const zero_after_free_allocator<U>&) noexcept
{
    return false;
}

// This is exactly like std::string, but with a custom allocator.
typedef std::basic_string<char, std::char_traits<char>, secure_allocator<char>> SecureString;

// Secure vector type
template<typename T>
using secure_vector = std::vector<T, secure_allocator<T>>;

// Zero-after-free vector type
template<typename T>
using zero_after_free_vector = std::vector<T, zero_after_free_allocator<T>>;

#endif
