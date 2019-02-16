// Copyright (c) 2012-2013 The Bitcoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/system.h>
#include <util/memory.h>

#include <support/allocators/secure.h>
#include <test/test_wispr.h>

#include <memory>
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(allocator_tests)

/** Mock LockedPageAllocator for testing */
class TestLockedPageAllocator: public LockedPageAllocator
{
public:
  TestLockedPageAllocator(int count_in, int lockedcount_in): count(count_in), lockedcount(lockedcount_in) {}
  void* AllocateLocked(size_t len, bool *lockingSuccess) override
  {
      *lockingSuccess = false;
      if (count > 0) {
          --count;

          if (lockedcount > 0) {
              --lockedcount;
              *lockingSuccess = true;
          }

          return reinterpret_cast<void*>(uint64_t{static_cast<uint64_t>(0x08000000) + (count << 24)}); // Fake address, do not actually use this memory
      }
      return nullptr;
  }
  void FreeLocked(void* addr, size_t len) override
  {
  }
  size_t GetLimit() override
  {
      return std::numeric_limits<size_t>::max();
  }
private:
  int count;
  int lockedcount;
};

BOOST_AUTO_TEST_CASE(lockedpool_tests_mock)
{
    // Test over three virtual arenas, of which one will succeed being locked
    std::unique_ptr<LockedPageAllocator> x = MakeUnique<TestLockedPageAllocator>(3, 1);
    LockedPool pool(std::move(x));
    BOOST_CHECK(pool.stats().total == 0);
    BOOST_CHECK(pool.stats().locked == 0);

    // Ensure unreasonable requests are refused without allocating anything
    void *invalid_toosmall = pool.alloc(0);
    BOOST_CHECK(invalid_toosmall == nullptr);
    BOOST_CHECK(pool.stats().used == 0);
    BOOST_CHECK(pool.stats().free == 0);
    void *invalid_toobig = pool.alloc(LockedPool::ARENA_SIZE+1);
    BOOST_CHECK(invalid_toobig == nullptr);
    BOOST_CHECK(pool.stats().used == 0);
    BOOST_CHECK(pool.stats().free == 0);

    void *a0 = pool.alloc(LockedPool::ARENA_SIZE / 2);
    BOOST_CHECK(a0);
    BOOST_CHECK(pool.stats().locked == LockedPool::ARENA_SIZE);
    void *a1 = pool.alloc(LockedPool::ARENA_SIZE / 2);
    BOOST_CHECK(a1);
    void *a2 = pool.alloc(LockedPool::ARENA_SIZE / 2);
    BOOST_CHECK(a2);
    void *a3 = pool.alloc(LockedPool::ARENA_SIZE / 2);
    BOOST_CHECK(a3);
    void *a4 = pool.alloc(LockedPool::ARENA_SIZE / 2);
    BOOST_CHECK(a4);
    void *a5 = pool.alloc(LockedPool::ARENA_SIZE / 2);
    BOOST_CHECK(a5);
    // We've passed a count of three arenas, so this allocation should fail
    void *a6 = pool.alloc(16);
    BOOST_CHECK(!a6);

    pool.free(a0);
    pool.free(a2);
    pool.free(a4);
    pool.free(a1);
    pool.free(a3);
    pool.free(a5);
    BOOST_CHECK(pool.stats().total == 3*LockedPool::ARENA_SIZE);
    BOOST_CHECK(pool.stats().locked == LockedPool::ARENA_SIZE);
    BOOST_CHECK(pool.stats().used == 0);
}

// These tests used the live LockedPoolManager object, this is also used
// by other tests so the conditions are somewhat less controllable and thus the
// tests are somewhat more error-prone.
BOOST_AUTO_TEST_CASE(lockedpool_tests_live)
{
    LockedPoolManager &pool = LockedPoolManager::Instance();
    LockedPool::Stats initial = pool.stats();

    void *a0 = pool.alloc(16);
    BOOST_CHECK(a0);
    // Test reading and writing the allocated memory
    *((uint32_t*)a0) = 0x1234;
    BOOST_CHECK(*((uint32_t*)a0) == 0x1234);

    pool.free(a0);
    try { // Test exception on double-free
        pool.free(a0);
        BOOST_CHECK(0);
    } catch(std::runtime_error &)
    {
    }
    // If more than one new arena was allocated for the above tests, something is wrong
    BOOST_CHECK(pool.stats().total <= (initial.total + LockedPool::ARENA_SIZE));
    // Usage must be back to where it started
    BOOST_CHECK(pool.stats().used == initial.used);
}


BOOST_AUTO_TEST_SUITE_END()
