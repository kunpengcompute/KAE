#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <zlib.h>

extern "C" {
#include <lz4_accelerater.h>
#include "kaelz4.h"
#include "kaelz4_comp.h"
#include <lz4.h>
#include <lz4frame.h>

extern void kaelz4_ctx_clear(struct kaelz4_async_ctrl *ctrl);
extern int kaelz4_compress_async(struct kaelz4_async_ctrl *ctrl, const struct kaelz4_buffer_list *src,
    struct kaelz4_buffer_list *dst, lz4_async_callback callback, struct kaelz4_result *result,
    enum kae_lz4_async_data_format data_format, const LZ4F_preferences_t *ptr);
}

extern __thread struct kaelz4_async_ctrl g_async_ctrl;

enum class MallocFailPoint {
    kNone,
    kAsyncReqAlloc,
};

static thread_local MallocFailPoint g_thread_malloc_fail_point = MallocFailPoint::kNone;
static thread_local size_t g_thread_malloc_fail_size = 0;
static thread_local int g_thread_malloc_fail_count = 0;
static thread_local int g_thread_malloc_fail_skip = 0;

extern "C" void *__real_malloc(size_t size);

extern "C" void *__wrap_malloc(size_t size)
{
    if (g_thread_malloc_fail_point == MallocFailPoint::kAsyncReqAlloc && g_thread_malloc_fail_count > 0 &&
        size == g_thread_malloc_fail_size) {
        if (g_thread_malloc_fail_skip > 0) {
            --g_thread_malloc_fail_skip;
        } else {
            --g_thread_malloc_fail_count;
            return nullptr;
        }
    }

    return __real_malloc(size);
}

#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif

#ifndef MAP_HUGE_512MB
#define MAP_HUGE_512MB (29 << MAP_HUGE_SHIFT)
#endif

#ifndef MAP_HUGE_32MB
#define MAP_HUGE_32MB (25 << MAP_HUGE_SHIFT)
#endif

#ifndef MAP_HUGE_2MB
#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#endif

#ifndef MAP_HUGE_1GB
#define MAP_HUGE_1GB (30 << MAP_HUGE_SHIFT)
#endif

namespace
{

const size_t kSmallSize = 32 * 1024;
const size_t kLargeSize = 160 * 1024;
const size_t kFrameSize = 192 * 1024;
const size_t kLz4BlockSize = 64 * 1024;
const size_t kPartialTupleSourceSize = 4 * 1024;
const size_t kPartialTupleBufferSize = 2 * kPartialTupleSourceSize;
const size_t kLiteralOnlyLz77Size = 11;
const int kInflightTasks = 16;
const int kBackpressureTasks = 72;
const int kPollBudget = 16;
const int kTimeoutMs = 30000;
const uint64_t kPagemapPresent = 1ULL << 63;
const uint64_t kPagemapPfnMask = (1ULL << 55) - 1;

class ScopedAsyncReqMallocFailure
{
  public:
    explicit ScopedAsyncReqMallocFailure(int fail_count)
    {
        g_thread_malloc_fail_point = MallocFailPoint::kAsyncReqAlloc;
        g_thread_malloc_fail_size = sizeof(struct kaelz4_async_req);
        g_thread_malloc_fail_count = fail_count;
        g_thread_malloc_fail_skip = (sizeof(struct kaelz4_async_req) == sizeof(struct kaelz4_compress_ctx)) ? 1 : 0;
    }

    ~ScopedAsyncReqMallocFailure()
    {
        g_thread_malloc_fail_point = MallocFailPoint::kNone;
        g_thread_malloc_fail_size = 0;
        g_thread_malloc_fail_count = 0;
        g_thread_malloc_fail_skip = 0;
    }

    ScopedAsyncReqMallocFailure(const ScopedAsyncReqMallocFailure &) = delete;
    ScopedAsyncReqMallocFailure &operator=(const ScopedAsyncReqMallocFailure &) = delete;
};

enum class MemoryMode {
    kNonZeroCopy,
    kZeroCopy,
};

enum class TaskFormat {
    kBlock,
    kFrame,
    kLz77ToBlock,
    kLz77ToFrame,
};

struct HugePageChoice {
    size_t map_size;
    size_t page_size;
    int flag;
    const char *path;
    const char *name;
};

bool FileExists(const char *path)
{
    return access(path, F_OK) == 0;
}

// Set this to 1 in CI or on 920B so missing zero-copy hugepages fail the test;
// leave it unset in ordinary local environments so zero-copy cases can skip.
bool RequireHugePage()
{
    const char *value = getenv("KAELZ4_REQUIRE_HUGEPAGE");
    return value != nullptr && strcmp(value, "1") == 0;
}

std::string HugePageSetupHint(const std::string &error)
{
    return "零拷贝hugetlb大页不可用: " + error +
           ". 请确认环境已申请 hugetlb 大页，并使用 sudo 运行测试以读取 /proc/self/pagemap。"
           " 大页申请命令请参考 KAELz4/test/gtest/README.md。";
}

std::vector<uint8_t> GenerateInput(size_t size, uint32_t seed)
{
    std::vector<uint8_t> data(size);
    for (size_t i = 0; i < size; ++i) {
        uint32_t group = static_cast<uint32_t>((i / 97) + seed);
        uint8_t repeated = static_cast<uint8_t>('A' + (group % 23));
        uint8_t noise = static_cast<uint8_t>((i * 131u + seed * 17u) & 0xffu);
        data[i] = (i % 31 == 0) ? noise : repeated;
    }
    return data;
}

uint32_t Crc32cSoftware(uint32_t crc, const uint8_t *data, size_t len)
{
    crc ^= 0xffffffffU;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit) {
            uint32_t mask = 0U - (crc & 1U);
            crc = (crc >> 1) ^ (0x82f63b78U & mask);
        }
    }
    return crc ^ 0xffffffffU;
}

::testing::AssertionResult ExpectCrcMatchesEither(uint32_t observed, const uint8_t *data, size_t len)
{
    uint32_t crc32_value = static_cast<uint32_t>(crc32(0, data, static_cast<uInt>(len)));
    uint32_t crc32c_value = Crc32cSoftware(0, data, len);
    if (observed == crc32_value || observed == crc32c_value) {
        return ::testing::AssertionSuccess();
    }

    return ::testing::AssertionFailure() << "CRC mismatch, observed=0x" << std::hex << observed << " crc32=0x"
                                         << crc32_value << " crc32c=0x" << crc32c_value << std::dec;
}

size_t OutputCapacity(size_t src_size, bool frame)
{
    size_t lz4_bound = static_cast<size_t>(LZ4_compressBound(static_cast<int>(src_size)));
    size_t frame_bound = frame ? LZ4F_compressFrameBound(src_size, nullptr) : 0;
    size_t bound = std::max(lz4_bound, frame_bound);
    return std::max(bound + 64 * 1024, src_size * 2 + 64 * 1024);
}

// Cache /proc/self/pagemap entries for the hugetlb arena and provide VA -> PA
// translation to KAELz4's iova_map_fn. For hugetlb mappings, using the first
// base-page PFN of each hugepage plus the in-hugepage offset matches kzip's
// hugepage zero-copy model and avoids depending on the UADK user allocator.
class PageMap
{
  public:
    PageMap() : fd_(-1), page_size_(0), huge_page_size_(0), base_(nullptr), total_size_(0)
    {
    }
    ~PageMap()
    {
        if (fd_ >= 0) {
            close(fd_);
        }
    }

    bool Init(void *base, size_t total_size, size_t huge_page_size, std::string *error)
    {
        long page_size = sysconf(_SC_PAGESIZE);
        if (page_size <= 0) {
            *error = "sysconf(_SC_PAGESIZE) failed";
            return false;
        }

        fd_ = open("/proc/self/pagemap", O_RDONLY);
        if (fd_ < 0) {
            *error = std::string("open(/proc/self/pagemap) failed: ") + strerror(errno);
            return false;
        }

        page_size_ = static_cast<size_t>(page_size);
        huge_page_size_ = huge_page_size;
        base_ = static_cast<uint8_t *>(base);
        total_size_ = total_size;
        size_t pages = (total_size_ + page_size_ - 1) / page_size_;
        entries_.assign(pages, 0);
        valid_.assign(pages, 0);
        return true;
    }

    void *Map(void *vaddr, size_t len)
    {
        uintptr_t addr = reinterpret_cast<uintptr_t>(vaddr);
        uintptr_t base = reinterpret_cast<uintptr_t>(base_);
        if (addr < base || addr + len > base + total_size_ || len == 0) {
            return nullptr;
        }

        size_t relative = addr - base;
        size_t huge_index = relative / huge_page_size_;
        size_t huge_offset = relative % huge_page_size_;
        size_t index = (huge_index * huge_page_size_) / page_size_;
        uint64_t entry = 0;
        if (!ReadEntry(index, &entry)) {
            return nullptr;
        }

        if ((entry & kPagemapPresent) == 0) {
            return nullptr;
        }
        uint64_t pfn = entry & kPagemapPfnMask;
        if (pfn == 0) {
            return nullptr;
        }

        uintptr_t phys = static_cast<uintptr_t>((pfn * page_size_) + huge_offset);
        return reinterpret_cast<void *>(phys);
    }

  private:
    bool ReadEntry(size_t index, uint64_t *entry)
    {
        if (index >= entries_.size()) {
            return false;
        }
        if (!valid_[index]) {
            uintptr_t vaddr = reinterpret_cast<uintptr_t>(base_) + index * page_size_;
            off_t offset = static_cast<off_t>((vaddr / page_size_) * sizeof(uint64_t));
            ssize_t got = pread(fd_, &entries_[index], sizeof(uint64_t), offset);
            if (got != static_cast<ssize_t>(sizeof(uint64_t))) {
                return false;
            }
            valid_[index] = 1;
        }

        *entry = entries_[index];
        return true;
    }

    int fd_;
    size_t page_size_;
    size_t huge_page_size_;
    uint8_t *base_;
    size_t total_size_;
    std::vector<uint64_t> entries_;
    std::vector<uint8_t> valid_;
};

// Process-wide hugetlb arena used by zero-copy cases for both input buffers and
// LZ77 tuple buffers. Keeping the arena alive for the whole test process ensures
// submitted async tasks never access freed source or tuple memory before their
// callbacks run.
class HugeArena
{
  public:
    static HugeArena &Instance()
    {
        static HugeArena arena;
        return arena;
    }

    ~HugeArena()
    {
        if (base_ != MAP_FAILED && base_ != nullptr) {
            munmap(base_, total_size_);
        }
    }

    bool Available() const
    {
        return available_;
    }

    const std::string &Error() const
    {
        return error_;
    }

    void *Alloc(size_t size, size_t align)
    {
        if (!available_) {
            return nullptr;
        }
        if (size > huge_page_size_) {
            return nullptr;
        }

        // Do not let one allocation cross a hugepage boundary; the simple
        // PageMap path maps each segment from one hugepage base PFN.
        size_t aligned = (offset_ + align - 1) & ~(align - 1);
        size_t page_offset = aligned % huge_page_size_;
        if (page_offset + size > huge_page_size_) {
            aligned += huge_page_size_ - page_offset;
            aligned = (aligned + align - 1) & ~(align - 1);
        }
        if (aligned + size > total_size_) {
            return nullptr;
        }

        uint8_t *ptr = static_cast<uint8_t *>(base_) + aligned;
        offset_ = aligned + size;
        memset(ptr, 0, size);
        return ptr;
    }

    PageMap *page_map()
    {
        return &page_map_;
    }

  private:
    HugeArena() : base_(MAP_FAILED), total_size_(0), huge_page_size_(0), offset_(0), available_(false)
    {
        // Prefer the 1GB/512MB hugepage sizes used by the kzip-style path. Fall
        // back to smaller hugetlb sizes only when the platform exposes them,
        // while still keeping the test on hugepages rather than UADK memory.
        std::vector<HugePageChoice> choices;
        if (FileExists("/sys/devices/system/node/node0/hugepages/hugepages-1048576kB")) {
            choices.push_back(
                {1024UL * 1024UL * 1024UL, 1024UL * 1024UL * 1024UL, MAP_HUGE_1GB, "hugepages-1048576kB", "1GB"});
        }
        if (FileExists("/sys/devices/system/node/node0/hugepages/hugepages-524288kB")) {
            choices.push_back(
                {512UL * 1024UL * 1024UL, 512UL * 1024UL * 1024UL, MAP_HUGE_512MB, "hugepages-524288kB", "512MB"});
        }
        if (FileExists("/sys/devices/system/node/node0/hugepages/hugepages-32768kB")) {
            choices.push_back(
                {512UL * 1024UL * 1024UL, 32UL * 1024UL * 1024UL, MAP_HUGE_32MB, "hugepages-32768kB", "32MB"});
        }
        if (FileExists("/sys/devices/system/node/node0/hugepages/hugepages-2048kB")) {
            choices.push_back(
                {512UL * 1024UL * 1024UL, 2UL * 1024UL * 1024UL, MAP_HUGE_2MB, "hugepages-2048kB", "2MB"});
        }

        if (choices.empty()) {
            error_ = "no supported hugepage directory found on node0";
            return;
        }

        std::string last_error;
        for (size_t i = 0; i < choices.size(); ++i) {
            base_ = mmap(nullptr, choices[i].map_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | choices[i].flag, -1, 0);
            if (base_ != MAP_FAILED) {
                total_size_ = choices[i].map_size;
                huge_page_size_ = choices[i].page_size;
                huge_name_ = choices[i].name;
                break;
            }
            last_error = std::string(choices[i].name) + " mmap failed: " + strerror(errno);
        }

        if (base_ == MAP_FAILED) {
            error_ = last_error.empty() ? std::string("mmap hugepage failed: ") + strerror(errno) : last_error;
            return;
        }

        if (!page_map_.Init(base_, total_size_, huge_page_size_, &error_)) {
            munmap(base_, total_size_);
            base_ = MAP_FAILED;
            return;
        }

        uint8_t *probe = static_cast<uint8_t *>(base_);
        probe[0] = 0xa5;
        if (page_map_.Map(probe, 1) == nullptr) {
            error_ = "pagemap did not expose a valid PFN for the hugepage";
            munmap(base_, total_size_);
            base_ = MAP_FAILED;
            return;
        }

        offset_ = 4096;
        available_ = true;
    }

    void *base_;
    size_t total_size_;
    size_t huge_page_size_;
    size_t offset_;
    bool available_;
    std::string huge_name_;
    std::string error_;
    PageMap page_map_;
};

void *HugeIovaMap(void *usr, void *vaddr, size_t sz)
{
    // KAELz4 passes kaelz4_buffer_list::usr_data back here for every SGL entry.
    PageMap *page_map = static_cast<PageMap *>(usr);
    if (page_map == nullptr) {
        return nullptr;
    }
    return page_map->Map(vaddr, sz);
}

#define KAELZ4_REQUIRE_ZERO_COPY()                                                                                     \
    do {                                                                                                               \
        HugeArena &arena = HugeArena::Instance();                                                                      \
        if (!arena.Available()) {                                                                                      \
            if (RequireHugePage()) {                                                                                   \
                FAIL() << HugePageSetupHint(arena.Error());                                                            \
            }                                                                                                          \
            GTEST_SKIP() << HugePageSetupHint(arena.Error());                                                          \
        }                                                                                                              \
    } while (0)

class PollingSession
{
  public:
    explicit PollingSession(MemoryMode mode)
        : sess_(KAELZ4_create_async_compress_session(mode == MemoryMode::kZeroCopy ? HugeIovaMap : nullptr, nullptr))
    {
    }

    ~PollingSession()
    {
        if (sess_ != nullptr) {
            KAELZ4_destroy_async_compress_session(sess_);
        }
    }

    void *get() const
    {
        return sess_;
    }

    void Reset()
    {
        KAELZ4_reset_session(sess_);
    }

  private:
    void *sess_;
};

class GuardedInput
{
  public:
    static std::unique_ptr<GuardedInput> Create(const uint8_t *src, size_t len)
    {
        long page_size = sysconf(_SC_PAGESIZE);
        if (page_size <= 0 || len == 0) {
            return nullptr;
        }

        size_t page = static_cast<size_t>(page_size);
        size_t accessible = ((len + page - 1) / page) * page;
        size_t total = accessible + page;
        void *base = mmap(nullptr, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED) {
            return nullptr;
        }

        uint8_t *guard = static_cast<uint8_t *>(base) + accessible;
        if (mprotect(guard, page, PROT_NONE) != 0) {
            munmap(base, total);
            return nullptr;
        }

        std::unique_ptr<GuardedInput> input(new GuardedInput(base, total, guard - len, len));
        memcpy(input->data_, src, len);
        return input;
    }

    ~GuardedInput()
    {
        if (base_ != MAP_FAILED && base_ != nullptr) {
            munmap(base_, total_);
        }
    }

    uint8_t *data() const
    {
        return data_;
    }

    size_t size() const
    {
        return size_;
    }

    GuardedInput(const GuardedInput &) = delete;
    GuardedInput &operator=(const GuardedInput &) = delete;

  private:
    GuardedInput(void *base, size_t total, uint8_t *data, size_t size)
        : base_(base), total_(total), data_(data), size_(size)
    {
    }

    void *base_;
    size_t total_;
    uint8_t *data_;
    size_t size_;
};

struct AsyncTask {
    explicit AsyncTask(TaskFormat fmt) : format(fmt)
    {
    }

    TaskFormat format;
    std::vector<uint8_t> expected;
    std::vector<uint8_t> heap_src;
    std::vector<std::unique_ptr<GuardedInput>> guarded_src;
    void *zero_src = nullptr;

    std::vector<uint8_t> direct_dst_storage;
    std::vector<uint8_t> final_dst_storage;
    std::vector<uint8_t> tuple_heap_storage;
    void *tuple_zero_storage = nullptr;

    std::vector<kaelz4_buffer> src_bufs;
    std::vector<kaelz4_buffer> direct_dst_bufs;
    std::vector<kaelz4_buffer> final_dst_bufs;
    std::vector<kaelz4_buffer> tuple_bufs;

    kaelz4_buffer_list src = {};
    kaelz4_buffer_list direct_dst = {};
    kaelz4_buffer_list final_dst = {};
    kaelz4_buffer_list tuple = {};

    kaelz4_result result = {};
    LZ4F_preferences_t preferences = {};
    uint32_t ibuf_crc = 0;
    uint32_t obuf_crc = 0;
    bool crc_enabled = false;
    int callback_status = -1;
    int rebuild_status = KAE_LZ4_SUCC;
    std::atomic<bool> done;

    bool IsLz77() const
    {
        return format == TaskFormat::kLz77ToBlock || format == TaskFormat::kLz77ToFrame;
    }

    bool OutputIsFrame() const
    {
        return format == TaskFormat::kFrame || format == TaskFormat::kLz77ToFrame;
    }

    uint8_t *CompressedData()
    {
        if (IsLz77()) {
            return final_dst_storage.data();
        }
        return direct_dst_storage.data();
    }

    AsyncTask(const AsyncTask &) = delete;
    AsyncTask &operator=(const AsyncTask &) = delete;
};

void BuildBufferList(
    void *base, size_t size, int segments, std::vector<kaelz4_buffer> *bufs, kaelz4_buffer_list *list, void *usr_data)
{
    bufs->clear();
    int real_segments = std::max(1, std::min<int>(segments, static_cast<int>(size)));
    uint8_t *ptr = static_cast<uint8_t *>(base);
    size_t offset = 0;
    for (int i = 0; i < real_segments; ++i) {
        size_t remaining = size - offset;
        size_t parts_left = static_cast<size_t>(real_segments - i);
        size_t len = remaining / parts_left;
        if (remaining % parts_left != 0) {
            ++len;
        }
        bufs->push_back({len, ptr + offset});
        offset += len;
    }

    list->buf_num = static_cast<unsigned int>(bufs->size());
    list->rsvd = 0;
    list->buf = bufs->data();
    list->usr_data = usr_data;
}

void InitFramePreferences(AsyncTask *task, bool full_checksums)
{
    memset(&task->preferences, 0, sizeof(task->preferences));
    task->preferences.frameInfo.blockSizeID = LZ4F_max64KB;
    task->preferences.frameInfo.blockMode = LZ4F_blockIndependent;
    task->preferences.frameInfo.contentSize = task->expected.size();
    task->preferences.frameInfo.blockChecksumFlag = full_checksums ? LZ4F_blockChecksumEnabled : LZ4F_noBlockChecksum;
    task->preferences.frameInfo.contentChecksumFlag =
        full_checksums ? LZ4F_contentChecksumEnabled : LZ4F_noContentChecksum;
}

std::unique_ptr<AsyncTask> PrepareTask(MemoryMode mode, TaskFormat format, size_t size, int src_segments, bool with_crc,
    uint32_t seed, bool frame_full_checksums, size_t lz77_tuple_capacity = 0)
{
    std::unique_ptr<AsyncTask> task(new AsyncTask(format));
    task->done.store(false, std::memory_order_relaxed);
    task->expected = GenerateInput(size, seed);
    task->crc_enabled = with_crc;

    PageMap *zero_copy_page_map = nullptr;
    void *src_base = nullptr;
    if (mode == MemoryMode::kZeroCopy) {
        // Zero-copy path: source data is hugetlb-backed, and usr_data carries
        // the PageMap used by HugeIovaMap during KAELz4's wd_build_sgl() flow.
        HugeArena &huge_arena = HugeArena::Instance();
        zero_copy_page_map = huge_arena.page_map();
        task->zero_src = huge_arena.Alloc(size + 64, 64);
        if (task->zero_src == nullptr) {
            return nullptr;
        }
        memcpy(task->zero_src, task->expected.data(), size);
        src_base = task->zero_src;
    } else {
        // Non-zero-copy path: the session is created with usr_map == NULL, so
        // KAELz4 copies multi-segment input into an internal flat buffer before
        // submitting it to hardware.
        task->heap_src.assign(size + 64, 0);
        memcpy(task->heap_src.data(), task->expected.data(), size);
        src_base = task->heap_src.data();
    }
    BuildBufferList(src_base, size, src_segments, &task->src_bufs, &task->src,
        mode == MemoryMode::kZeroCopy ? zero_copy_page_map : nullptr);

    bool frame_output = task->OutputIsFrame();
    size_t dst_capacity = OutputCapacity(size, frame_output);
    task->direct_dst_storage.assign(dst_capacity, 0);
    task->direct_dst_bufs.push_back({dst_capacity, task->direct_dst_storage.data()});
    task->direct_dst.buf_num = 1;
    task->direct_dst.buf = task->direct_dst_bufs.data();
    task->direct_dst.usr_data = nullptr;

    task->final_dst_storage.assign(dst_capacity, 0);
    task->final_dst_bufs.push_back({dst_capacity, task->final_dst_storage.data()});
    task->final_dst.buf_num = 1;
    task->final_dst.buf = task->final_dst_bufs.data();
    task->final_dst.usr_data = nullptr;

    if (task->IsLz77()) {
        size_t tuple_len = lz77_tuple_capacity != 0 ? lz77_tuple_capacity : KAELZ4_compress_get_tuple_buf_len(size);
        if (mode == MemoryMode::kZeroCopy) {
            // Zero-copy LZ77 raw tuple output is also an SGL destination, so the
            // tuple buffer must be hugetlb-backed and mappable by HugeIovaMap.
            HugeArena &huge_arena = HugeArena::Instance();
            task->tuple_zero_storage = huge_arena.Alloc(tuple_len, 64);
            if (task->tuple_zero_storage == nullptr) {
                return nullptr;
            }
            task->tuple_bufs.push_back({tuple_len, task->tuple_zero_storage});
            task->tuple.usr_data = zero_copy_page_map;
        } else {
            task->tuple_heap_storage.assign(tuple_len, 0);
            task->tuple_bufs.push_back({tuple_len, task->tuple_heap_storage.data()});
            task->tuple.usr_data = nullptr;
        }
        task->tuple.buf_num = 1;
        task->tuple.buf = task->tuple_bufs.data();
    }

    if (frame_output) {
        InitFramePreferences(task.get(), frame_full_checksums);
    }

    memset(&task->result, 0, sizeof(task->result));
    task->result.user_data = task.get();
    if (with_crc) {
        task->result.ibuf_crc = &task->ibuf_crc;
        task->result.obuf_crc = &task->obuf_crc;
    }

    return task;
}

std::unique_ptr<AsyncTask> PrepareGuardedNonZeroCopyTask(TaskFormat format, const std::vector<size_t> &segment_sizes,
    bool with_crc, uint32_t seed, bool frame_full_checksums)
{
    size_t total_size = 0;
    for (size_t len : segment_sizes) {
        if (len == 0 || total_size > SIZE_MAX - len) {
            return nullptr;
        }
        total_size += len;
    }

    std::unique_ptr<AsyncTask> task(new AsyncTask(format));
    task->done.store(false, std::memory_order_relaxed);
    task->expected = GenerateInput(total_size, seed);
    task->crc_enabled = with_crc;

    size_t offset = 0;
    for (size_t len : segment_sizes) {
        std::unique_ptr<GuardedInput> guarded = GuardedInput::Create(task->expected.data() + offset, len);
        if (guarded == nullptr) {
            return nullptr;
        }
        task->src_bufs.push_back({guarded->size(), guarded->data()});
        task->guarded_src.push_back(std::move(guarded));
        offset += len;
    }

    task->src.buf_num = static_cast<unsigned int>(task->src_bufs.size());
    task->src.rsvd = 0;
    task->src.buf = task->src_bufs.data();
    task->src.usr_data = nullptr;

    bool frame_output = task->OutputIsFrame();
    size_t dst_capacity = OutputCapacity(total_size, frame_output);
    task->direct_dst_storage.assign(dst_capacity, 0);
    task->direct_dst_bufs.push_back({dst_capacity, task->direct_dst_storage.data()});
    task->direct_dst.buf_num = 1;
    task->direct_dst.buf = task->direct_dst_bufs.data();
    task->direct_dst.usr_data = nullptr;

    task->final_dst_storage.assign(dst_capacity, 0);
    task->final_dst_bufs.push_back({dst_capacity, task->final_dst_storage.data()});
    task->final_dst.buf_num = 1;
    task->final_dst.buf = task->final_dst_bufs.data();
    task->final_dst.usr_data = nullptr;

    if (task->IsLz77()) {
        size_t tuple_len = KAELZ4_compress_get_tuple_buf_len(total_size);
        task->tuple_heap_storage.assign(tuple_len, 0);
        task->tuple_bufs.push_back({tuple_len, task->tuple_heap_storage.data()});
        task->tuple.buf_num = 1;
        task->tuple.buf = task->tuple_bufs.data();
        task->tuple.usr_data = nullptr;
    }

    if (frame_output) {
        InitFramePreferences(task.get(), frame_full_checksums);
    }

    memset(&task->result, 0, sizeof(task->result));
    task->result.user_data = task.get();
    if (with_crc) {
        task->result.ibuf_crc = &task->ibuf_crc;
        task->result.obuf_crc = &task->obuf_crc;
    }

    return task;
}

void AsyncCallback(kaelz4_result *result)
{
    AsyncTask *task = static_cast<AsyncTask *>(result->user_data);
    task->callback_status = result->status;
    task->rebuild_status = KAE_LZ4_SUCC;

    if (result->status == KAE_LZ4_SUCC && task->format == TaskFormat::kLz77ToBlock) {
        task->rebuild_status = KAELZ4_rebuild_lz77_to_block(&task->src, &task->tuple, &task->final_dst, result);
    } else if (result->status == KAE_LZ4_SUCC && task->format == TaskFormat::kLz77ToFrame) {
        task->rebuild_status =
            KAELZ4_rebuild_lz77_to_frame(&task->src, &task->tuple, &task->final_dst, result, &task->preferences);
    }

    task->done.store(true, std::memory_order_release);
}

int SubmitTask(void *session, AsyncTask *task)
{
    if (task->format == TaskFormat::kBlock) {
        return KAELZ4_compress_async_in_session(session, &task->src, &task->direct_dst, AsyncCallback, &task->result);
    }
    if (task->format == TaskFormat::kFrame) {
        return KAELZ4_compress_frame_async_in_session(
            session, &task->src, &task->direct_dst, AsyncCallback, &task->result, &task->preferences);
    }
    return KAELZ4_compress_lz77_async_in_session(session, &task->src, &task->tuple, AsyncCallback, &task->result);
}

::testing::AssertionResult WaitForTasks(void *session, const std::vector<AsyncTask *> &tasks)
{
    auto start = std::chrono::steady_clock::now();
    while (true) {
        KAELZ4_async_polling_in_session(session, kPollBudget);

        bool all_done = true;
        size_t done_count = 0;
        for (size_t i = 0; i < tasks.size(); ++i) {
            if (tasks[i]->done.load(std::memory_order_acquire)) {
                ++done_count;
            } else {
                all_done = false;
            }
        }

        if (all_done) {
            return ::testing::AssertionSuccess();
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
        if (elapsed.count() > kTimeoutMs) {
            return ::testing::AssertionFailure()
                   << "timeout waiting for polling tasks, done=" << done_count << "/" << tasks.size();
        }
        usleep(1000);
    }
}

::testing::AssertionResult DecompressBlock(
    const uint8_t *compressed, size_t compressed_len, const std::vector<uint8_t> &expected)
{
    std::vector<uint8_t> decoded(expected.size());
    int decoded_len = LZ4_decompress_safe(reinterpret_cast<const char *>(compressed),
        reinterpret_cast<char *>(decoded.data()), static_cast<int>(compressed_len), static_cast<int>(decoded.size()));
    if (decoded_len != static_cast<int>(expected.size())) {
        return ::testing::AssertionFailure()
               << "LZ4_decompress_safe returned " << decoded_len << ", expected " << expected.size();
    }
    if (decoded != expected) {
        return ::testing::AssertionFailure() << "block decoded bytes differ from original input";
    }
    return ::testing::AssertionSuccess();
}

::testing::AssertionResult DecompressFrame(
    const uint8_t *compressed, size_t compressed_len, const std::vector<uint8_t> &expected)
{
    LZ4F_dctx *dctx = nullptr;
    size_t ret = LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);
    if (LZ4F_isError(ret)) {
        return ::testing::AssertionFailure() << "LZ4F_createDecompressionContext failed: " << LZ4F_getErrorName(ret);
    }

    std::vector<uint8_t> decoded(expected.size());
    size_t src_pos = 0;
    size_t dst_pos = 0;
    while (src_pos < compressed_len) {
        size_t src_size = compressed_len - src_pos;
        size_t dst_size = decoded.size() - dst_pos;
        ret = LZ4F_decompress(dctx, decoded.data() + dst_pos, &dst_size, compressed + src_pos, &src_size, nullptr);
        if (LZ4F_isError(ret)) {
            const char *name = LZ4F_getErrorName(ret);
            LZ4F_freeDecompressionContext(dctx);
            return ::testing::AssertionFailure() << "LZ4F_decompress failed: " << name;
        }
        src_pos += src_size;
        dst_pos += dst_size;
        if (ret == 0 && src_pos == compressed_len) {
            break;
        }
        if (src_size == 0 && dst_size == 0) {
            LZ4F_freeDecompressionContext(dctx);
            return ::testing::AssertionFailure() << "LZ4F_decompress made no progress";
        }
    }

    LZ4F_freeDecompressionContext(dctx);
    if (dst_pos != expected.size()) {
        return ::testing::AssertionFailure() << "frame decoded length " << dst_pos << ", expected " << expected.size();
    }
    if (decoded != expected) {
        return ::testing::AssertionFailure() << "frame decoded bytes differ from original input";
    }
    return ::testing::AssertionSuccess();
}

::testing::AssertionResult VerifyTask(AsyncTask *task)
{
    if (!task->done.load(std::memory_order_acquire)) {
        return ::testing::AssertionFailure() << "task callback was not invoked";
    }
    if (task->callback_status != KAE_LZ4_SUCC) {
        return ::testing::AssertionFailure() << "callback status=" << task->callback_status;
    }
    if (task->rebuild_status != KAE_LZ4_SUCC) {
        return ::testing::AssertionFailure()
               << "rebuild status=" << task->rebuild_status << " result status=" << task->result.status;
    }
    if (task->result.status != KAE_LZ4_SUCC) {
        return ::testing::AssertionFailure() << "final result status=" << task->result.status;
    }
    if (task->result.dst_len == 0) {
        return ::testing::AssertionFailure() << "compressed output length is zero";
    }

    uint8_t *compressed = task->CompressedData();
    if (task->OutputIsFrame()) {
        auto frame_result = DecompressFrame(compressed, task->result.dst_len, task->expected);
        if (!frame_result) {
            return frame_result;
        }
    } else {
        auto block_result = DecompressBlock(compressed, task->result.dst_len, task->expected);
        if (!block_result) {
            return block_result;
        }
    }

    if (task->crc_enabled) {
        auto input_crc = ExpectCrcMatchesEither(task->ibuf_crc, task->expected.data(), task->expected.size());
        if (!input_crc) {
            return input_crc;
        }
        auto output_crc = ExpectCrcMatchesEither(task->obuf_crc, compressed, task->result.dst_len);
        if (!output_crc) {
            return output_crc;
        }
    }

    return ::testing::AssertionSuccess();
}

void RunSingleCase(MemoryMode mode, TaskFormat format, size_t size, int segments, bool with_crc,
    bool frame_full_checksums, uint32_t seed, size_t lz77_tuple_capacity = 0)
{
    PollingSession session(mode);
    ASSERT_NE(session.get(), nullptr);

    std::unique_ptr<AsyncTask> task =
        PrepareTask(mode, format, size, segments, with_crc, seed, frame_full_checksums, lz77_tuple_capacity);
    ASSERT_NE(task, nullptr);

    ASSERT_EQ(SubmitTask(session.get(), task.get()), KAE_LZ4_SUCC);
    std::vector<AsyncTask *> tasks;
    tasks.push_back(task.get());
    ASSERT_TRUE(WaitForTasks(session.get(), tasks));
    ASSERT_TRUE(VerifyTask(task.get()));
}

void RunGuardedNonZeroCopyCase(TaskFormat format, const std::vector<size_t> &segment_sizes, bool with_crc,
    bool frame_full_checksums, uint32_t seed)
{
    PollingSession session(MemoryMode::kNonZeroCopy);
    ASSERT_NE(session.get(), nullptr);

    std::unique_ptr<AsyncTask> task =
        PrepareGuardedNonZeroCopyTask(format, segment_sizes, with_crc, seed, frame_full_checksums);
    ASSERT_NE(task, nullptr);

    ASSERT_EQ(SubmitTask(session.get(), task.get()), KAE_LZ4_SUCC);
    std::vector<AsyncTask *> tasks;
    tasks.push_back(task.get());
    ASSERT_TRUE(WaitForTasks(session.get(), tasks));
    ASSERT_TRUE(VerifyTask(task.get()));
}

void RunInflightCase(MemoryMode mode, TaskFormat format, int task_count, size_t base_size, int segments, bool with_crc,
    bool frame_full_checksums)
{
    PollingSession session(mode);
    ASSERT_NE(session.get(), nullptr);

    std::vector<std::unique_ptr<AsyncTask>> owned;
    std::vector<AsyncTask *> tasks;
    for (int i = 0; i < task_count; ++i) {
        TaskFormat actual_format = format;
        if (format == TaskFormat::kLz77ToBlock && (i % 2) != 0) {
            actual_format = TaskFormat::kLz77ToFrame;
        }

        size_t size = base_size + static_cast<size_t>((i % 5) * 4096);
        if (mode == MemoryMode::kNonZeroCopy &&
            (actual_format == TaskFormat::kLz77ToBlock || actual_format == TaskFormat::kLz77ToFrame)) {
            // The full LZ77 raw path is SGL-oriented. The non-zero-copy path only
            // covers the currently supported literal-only branch for usr_map == NULL.
            size = kLiteralOnlyLz77Size;
        }

        std::unique_ptr<AsyncTask> task = PrepareTask(
            mode, actual_format, size, segments, with_crc, static_cast<uint32_t>(0x1000 + i), frame_full_checksums);
        ASSERT_NE(task, nullptr);
        tasks.push_back(task.get());
        owned.push_back(std::move(task));
    }

    for (size_t i = 0; i < tasks.size(); ++i) {
        ASSERT_EQ(SubmitTask(session.get(), tasks[i]), KAE_LZ4_SUCC) << "submit index " << i;
    }

    ASSERT_TRUE(WaitForTasks(session.get(), tasks));
    for (size_t i = 0; i < tasks.size(); ++i) {
        ASSERT_TRUE(VerifyTask(tasks[i])) << "verify index " << i;
    }
}

void RunMixedInflightCase(MemoryMode mode)
{
    PollingSession session(mode);
    ASSERT_NE(session.get(), nullptr);

    std::vector<TaskFormat> formats;
    formats.push_back(TaskFormat::kBlock);
    formats.push_back(TaskFormat::kFrame);
    formats.push_back(TaskFormat::kLz77ToBlock);
    formats.push_back(TaskFormat::kLz77ToFrame);

    std::vector<std::unique_ptr<AsyncTask>> owned;
    std::vector<AsyncTask *> tasks;
    for (int i = 0; i < kInflightTasks; ++i) {
        TaskFormat format = formats[static_cast<size_t>(i) % formats.size()];
        size_t size = kSmallSize + static_cast<size_t>((i % 4) * 2048);
        if (mode == MemoryMode::kNonZeroCopy &&
            (format == TaskFormat::kLz77ToBlock || format == TaskFormat::kLz77ToFrame)) {
            size = kLiteralOnlyLz77Size;
        }

        std::unique_ptr<AsyncTask> task = PrepareTask(
            mode, format, size, (i % 3) + 1, true, static_cast<uint32_t>(0x2000 + i), format == TaskFormat::kFrame);
        ASSERT_NE(task, nullptr);
        tasks.push_back(task.get());
        owned.push_back(std::move(task));
    }

    for (size_t i = 0; i < tasks.size(); ++i) {
        ASSERT_EQ(SubmitTask(session.get(), tasks[i]), KAE_LZ4_SUCC) << "submit index " << i;
    }

    ASSERT_TRUE(WaitForTasks(session.get(), tasks));
    for (size_t i = 0; i < tasks.size(); ++i) {
        ASSERT_TRUE(VerifyTask(tasks[i])) << "verify index " << i;
    }
}

void RunQueueBackpressureCase(MemoryMode mode)
{
    PollingSession session(mode);
    ASSERT_NE(session.get(), nullptr);

    std::vector<std::unique_ptr<AsyncTask>> owned;
    std::vector<AsyncTask *> tasks;
    for (int i = 0; i < kBackpressureTasks; ++i) {
        std::unique_ptr<AsyncTask> task = PrepareTask(
            mode, TaskFormat::kBlock, 16 * 1024 + (i % 7) * 1024, 2, true, static_cast<uint32_t>(0x3000 + i), false);
        ASSERT_NE(task, nullptr);
        tasks.push_back(task.get());
        owned.push_back(std::move(task));
    }

    for (size_t i = 0; i < tasks.size(); ++i) {
        ASSERT_EQ(SubmitTask(session.get(), tasks[i]), KAE_LZ4_SUCC) << "submit index " << i;
    }

    ASSERT_TRUE(WaitForTasks(session.get(), tasks));
    for (size_t i = 0; i < tasks.size(); ++i) {
        ASSERT_TRUE(VerifyTask(tasks[i])) << "verify index " << i;
    }
}

void RunResetPendingCase(MemoryMode mode)
{
    {
        PollingSession session(mode);
        ASSERT_NE(session.get(), nullptr);

        std::vector<std::unique_ptr<AsyncTask>> owned;
        std::vector<AsyncTask *> tasks;
        for (int i = 0; i < kInflightTasks; ++i) {
            std::unique_ptr<AsyncTask> task =
                PrepareTask(mode, TaskFormat::kBlock, kLargeSize, 3, true, static_cast<uint32_t>(0x4000 + i), false);
            ASSERT_NE(task, nullptr);
            tasks.push_back(task.get());
            owned.push_back(std::move(task));
        }

        for (size_t i = 0; i < tasks.size(); ++i) {
            ASSERT_EQ(SubmitTask(session.get(), tasks[i]), KAE_LZ4_SUCC) << "submit index " << i;
        }

        session.Reset();
        for (size_t i = 0; i < tasks.size(); ++i) {
            ASSERT_TRUE(tasks[i]->done.load(std::memory_order_acquire)) << "reset did not finish task " << i;
            ASSERT_NE(tasks[i]->callback_status, KAE_LZ4_SUCC) << "reset task unexpectedly succeeded at " << i;
        }
    }

    RunSingleCase(mode, TaskFormat::kBlock, kSmallSize, 1, true, false, 0x5000);
}

struct RebuildCase {
    RebuildCase(size_t src_size, size_t tuple_len, int src_segments = 1)
    {
        expected = GenerateInput(src_size, 0x9000);
        src_storage.assign(src_size + 64, 0);
        memcpy(src_storage.data(), expected.data(), src_size);
        BuildBufferList(src_storage.data(), src_size, src_segments, &src_bufs, &src, nullptr);

        tuple_storage.assign(tuple_len, 0);
        tuple_bufs.push_back({tuple_len, tuple_storage.data()});
        tuple.buf_num = 1;
        tuple.buf = tuple_bufs.data();
        tuple.usr_data = nullptr;

        dst_storage.assign(OutputCapacity(src_size, true), 0);
        dst_bufs.push_back({dst_storage.size(), dst_storage.data()});
        dst.buf_num = 1;
        dst.buf = dst_bufs.data();
        dst.usr_data = nullptr;

        memset(&result, 0, sizeof(result));
        result.status = KAE_LZ4_SUCC;
        result.src_size = src_size;
        InitFramePreferencesForRebuild();
    }

    void InitFramePreferencesForRebuild()
    {
        memset(&preferences, 0, sizeof(preferences));
        preferences.frameInfo.blockSizeID = LZ4F_max64KB;
        preferences.frameInfo.blockMode = LZ4F_blockIndependent;
        preferences.frameInfo.contentSize = expected.size();
        preferences.frameInfo.blockChecksumFlag = LZ4F_noBlockChecksum;
        preferences.frameInfo.contentChecksumFlag = LZ4F_noContentChecksum;
    }

    uint32_t *SeqNum()
    {
        return reinterpret_cast<uint32_t *>(tuple_storage.data());
    }

    seqDef *FirstSeq()
    {
        return reinterpret_cast<seqDef *>(tuple_storage.data() + sizeof(uint32_t));
    }

    std::vector<uint8_t> expected;
    std::vector<uint8_t> src_storage;
    std::vector<uint8_t> tuple_storage;
    std::vector<uint8_t> dst_storage;
    std::vector<kaelz4_buffer> src_bufs;
    std::vector<kaelz4_buffer> tuple_bufs;
    std::vector<kaelz4_buffer> dst_bufs;
    kaelz4_buffer_list src = {};
    kaelz4_buffer_list tuple = {};
    kaelz4_buffer_list dst = {};
    kaelz4_result result = {};
    LZ4F_preferences_t preferences = {};
};

struct GuardedRebuildCase {
    GuardedRebuildCase(const std::vector<uint8_t> &input, const std::vector<size_t> &segment_sizes)
    {
        expected = input;
        size_t offset = 0;
        for (size_t len : segment_sizes) {
            if (len == 0 || offset > expected.size() || len > expected.size() - offset) {
                valid = false;
                return;
            }
            std::unique_ptr<GuardedInput> guarded = GuardedInput::Create(expected.data() + offset, len);
            if (guarded == nullptr) {
                valid = false;
                return;
            }
            src_bufs.push_back({guarded->size(), guarded->data()});
            guarded_src.push_back(std::move(guarded));
            offset += len;
        }
        if (offset != expected.size()) {
            valid = false;
            return;
        }

        src.buf_num = static_cast<unsigned int>(src_bufs.size());
        src.buf = src_bufs.data();
        src.usr_data = nullptr;

        tuple_storage.assign(KAELZ4_compress_get_tuple_buf_len(expected.size()), 0);
        tuple_bufs.push_back({tuple_storage.size(), tuple_storage.data()});
        tuple.buf_num = 1;
        tuple.buf = tuple_bufs.data();
        tuple.usr_data = nullptr;

        dst_storage.assign(OutputCapacity(expected.size(), false), 0);
        dst_bufs.push_back({dst_storage.size(), dst_storage.data()});
        dst.buf_num = 1;
        dst.buf = dst_bufs.data();
        dst.usr_data = nullptr;

        memset(&result, 0, sizeof(result));
        result.status = KAE_LZ4_SUCC;
        result.src_size = expected.size();
    }

    uint32_t *SeqNum()
    {
        return reinterpret_cast<uint32_t *>(tuple_storage.data());
    }

    seqDef *FirstSeq()
    {
        return reinterpret_cast<seqDef *>(tuple_storage.data() + sizeof(uint32_t));
    }

    bool valid = true;
    std::vector<uint8_t> expected;
    std::vector<std::unique_ptr<GuardedInput>> guarded_src;
    std::vector<uint8_t> tuple_storage;
    std::vector<uint8_t> dst_storage;
    std::vector<kaelz4_buffer> src_bufs;
    std::vector<kaelz4_buffer> tuple_bufs;
    std::vector<kaelz4_buffer> dst_bufs;
    kaelz4_buffer_list src = {};
    kaelz4_buffer_list tuple = {};
    kaelz4_buffer_list dst = {};
    kaelz4_result result = {};
};

std::vector<uint8_t> BuildSingleSequenceSource(size_t final_literal_len)
{
    std::vector<uint8_t> input;
    input.reserve(17 + 4 + final_literal_len);
    for (int i = 0; i < 16; ++i) {
        input.push_back(static_cast<uint8_t>('a' + i));
    }
    input.push_back('Q');
    input.insert(input.end(), 4, 'Q');
    for (size_t i = 0; i < final_literal_len; ++i) {
        input.push_back(static_cast<uint8_t>('Z' - (i % 13)));
    }
    return input;
}

void UnexpectedQueueRollbackCallback(kaelz4_result *result)
{
    (void)result;
    ADD_FAILURE() << "allocation rollback test should not invoke callback in polling mode";
}

} // namespace

// Purpose: LZ77 tuple-buffer sizing API smoke test. Verifies the source-length
// full-stride estimate and its overflow sentinel.
TEST(KAELz4AsyncPolling, LZ77TupleBufferLengthRoundsBy64KB)
{
    EXPECT_EQ(KAELZ4_compress_get_tuple_buf_len(0), 0U);
    EXPECT_EQ(KAELZ4_compress_get_tuple_buf_len(1), KAE_LZ77_SEQ_DATA_SIZE_PER_64K);
    EXPECT_EQ(KAELZ4_compress_get_tuple_buf_len(kLz4BlockSize), KAE_LZ77_SEQ_DATA_SIZE_PER_64K);
    EXPECT_EQ(KAELZ4_compress_get_tuple_buf_len(kLz4BlockSize + 1), 2 * KAE_LZ77_SEQ_DATA_SIZE_PER_64K);

    const size_t max_chunks = SIZE_MAX / KAE_LZ77_SEQ_DATA_SIZE_PER_64K;
    const size_t max_src_len = max_chunks * kLz4BlockSize;
    EXPECT_EQ(KAELZ4_compress_get_tuple_buf_len(max_src_len), max_chunks * KAE_LZ77_SEQ_DATA_SIZE_PER_64K);
    EXPECT_EQ(KAELZ4_compress_get_tuple_buf_len(max_src_len + 1), 0U);
    EXPECT_EQ(KAELZ4_compress_get_tuple_buf_len(SIZE_MAX), 0U);
}

// Purpose: async compression entry-point validation. A source list with more
// than 255 SGEs must be rejected before any hardware request is submitted.
TEST(KAELz4AsyncPolling, LZ77CompressionRejectsTooManySourceSges)
{
    PollingSession session(MemoryMode::kNonZeroCopy);
    ASSERT_NE(session.get(), nullptr);

    std::unique_ptr<AsyncTask> task =
        PrepareTask(MemoryMode::kNonZeroCopy, TaskFormat::kLz77ToBlock, 256, 256, false, 0x08, false);
    ASSERT_NE(task, nullptr);

    EXPECT_EQ(SubmitTask(session.get(), task.get()), KAE_LZ4_INVAL_PARA);
    EXPECT_FALSE(task->done.load(std::memory_order_acquire));
}

// Purpose: keep the SGE-count limit specific to raw LZ77. Regular block
// compression accepts more than 255 source SGEs and splits them across
// multiple hardware requests internally.
TEST(KAELz4AsyncPolling, BlockCompressionAcceptsMoreThan255SourceSges)
{
    RunSingleCase(MemoryMode::kNonZeroCopy, TaskFormat::kBlock, kLz4BlockSize, 256, true, false, 0x09);
}

// Purpose: async control cleanup validation. Verifies that clearing an empty
// control object is safe and nulls the context slots it is asked to inspect.
TEST(KAELz4AsyncPolling, CtxClearEmptyCtrlIsSafe)
{
    memset(&g_async_ctrl, 0, sizeof(g_async_ctrl));
    g_async_ctrl.ctx_num = 2;

    kaelz4_ctx_clear(&g_async_ctrl);

    for (int i = 0; i < 2; i++) {
        ASSERT_EQ(g_async_ctrl.kz_ctx[i], nullptr);
    }
}

// Purpose: async queue rollback on request allocation failure. Builds an
// existing ctx queue, injects one kaelz4_async_req malloc failure, then verifies
// that the newly appended ctx is removed without dropping the old queue head.
TEST(KAELz4AsyncPolling, AsyncReqAllocFailurePreservesExistingQueue)
{
    struct kaelz4_async_ctrl ctrl = {};
    struct kaelz4_compress_ctx existing_ctx = {};
    ctrl.ctx_head = &existing_ctx;
    ctrl.tail = &existing_ctx;
    ctrl.is_polling = 1;

    std::vector<uint8_t> input = GenerateInput(128, 0x7100);
    std::vector<uint8_t> output(OutputCapacity(input.size(), false), 0);
    std::vector<kaelz4_buffer> src_bufs;
    kaelz4_buffer_list src = {};
    BuildBufferList(input.data(), input.size(), 1, &src_bufs, &src, nullptr);

    kaelz4_buffer dst_buf = {output.size(), output.data()};
    kaelz4_buffer_list dst = {};
    dst.buf_num = 1;
    dst.buf = &dst_buf;
    dst.usr_data = nullptr;

    kaelz4_result result = {};
    result.src_size = input.size();
    result.dst_len = output.size();
    LZ4F_preferences_t preferences = {};

    {
        ScopedAsyncReqMallocFailure fail_once(1);
        EXPECT_EQ(kaelz4_compress_async(
                      &ctrl, &src, &dst, UnexpectedQueueRollbackCallback, &result, KAELZ4_ASYNC_BLOCK, &preferences),
            KAE_LZ4_ALLOC_FAIL);
    }

    EXPECT_EQ(ctrl.ctx_head, &existing_ctx);
    EXPECT_EQ(ctrl.tail, &existing_ctx);
    EXPECT_EQ(existing_ctx.next, nullptr);
}

// Purpose: partial final tuple-slot compatibility. A 4KB request historically
// advertises an 8KB tuple buffer; rebuild must accept it when seq_num fits the
// bytes that are actually present instead of requiring a nominal 128KB slot.
TEST(KAELz4AsyncPolling, RebuildAcceptsPartialTupleSlot)
{
    RebuildCase block_tc(kPartialTupleSourceSize, kPartialTupleBufferSize);
    *block_tc.SeqNum() = 0;

    ASSERT_EQ(
        KAELZ4_rebuild_lz77_to_block(&block_tc.src, &block_tc.tuple, &block_tc.dst, &block_tc.result), KAE_LZ4_SUCC);
    ASSERT_TRUE(DecompressBlock(block_tc.dst_storage.data(), block_tc.result.dst_len, block_tc.expected));

    RebuildCase frame_tc(kPartialTupleSourceSize, kPartialTupleBufferSize);
    *frame_tc.SeqNum() = 0;

    ASSERT_EQ(KAELZ4_rebuild_lz77_to_frame(
                  &frame_tc.src, &frame_tc.tuple, &frame_tc.dst, &frame_tc.result, &frame_tc.preferences),
        KAE_LZ4_SUCC);
    ASSERT_TRUE(DecompressFrame(frame_tc.dst_storage.data(), frame_tc.result.dst_len, frame_tc.expected));
}

// Purpose: fixed-stride layout with a partial final slot. Complete 64KB
// requests retain 128KB strides, while only the final 32KB request uses its
// shorter 64KB capacity.
TEST(KAELz4AsyncPolling, RebuildAcceptsPartialFinalTupleSlot)
{
    RebuildCase tc(kLargeSize, 2 * kLargeSize, 3);
    *reinterpret_cast<uint32_t *>(tc.tuple_storage.data()) = 0;
    *reinterpret_cast<uint32_t *>(tc.tuple_storage.data() + KAE_LZ77_SEQ_DATA_SIZE_PER_64K) = 0;
    *reinterpret_cast<uint32_t *>(tc.tuple_storage.data() + 2 * KAE_LZ77_SEQ_DATA_SIZE_PER_64K) = 0;

    ASSERT_EQ(KAELZ4_rebuild_lz77_to_block(&tc.src, &tc.tuple, &tc.dst, &tc.result), KAE_LZ4_SUCC);
    ASSERT_TRUE(DecompressBlock(tc.dst_storage.data(), tc.result.dst_len, tc.expected));
}

// Purpose: request-count compatibility around MFLIMIT. Inputs up to
// 64KB+MFLIMIT remain one hardware request because the final 12 bytes are kept
// as literals, so a simple ceil(src/64KB) calculation must not demand slot 2.
TEST(KAELz4AsyncPolling, RebuildUsesHardwareRequestSplitAtMflimitBoundary)
{
    RebuildCase tc(kLz4BlockSize + 1, KAE_LZ77_SEQ_DATA_SIZE_PER_64K, 2);
    *tc.SeqNum() = 0;

    ASSERT_EQ(KAELZ4_rebuild_lz77_to_block(&tc.src, &tc.tuple, &tc.dst, &tc.result), KAE_LZ4_SUCC);
    ASSERT_TRUE(DecompressBlock(tc.dst_storage.data(), tc.result.dst_len, tc.expected));
}

// Purpose: rebuild literal copying from a guarded source segment. Verifies that
// a hardware-format tuple with a non-16-byte literal does not read into the
// guard page while copying within the current segment.
TEST(KAELz4AsyncPolling, RebuildCopiesGuardedUnalignedDirectLiteral)
{
    std::vector<uint8_t> input = BuildSingleSequenceSource(1);
    GuardedRebuildCase tc(input, {input.size()});
    ASSERT_TRUE(tc.valid);
    ASSERT_GE(tc.tuple_storage.size(), sizeof(uint32_t) + sizeof(seqDef));

    *tc.SeqNum() = 1;
    seqDef *seq = tc.FirstSeq();
    seq->litLength = 17;
    seq->offBase = 0;
    seq->mlBase = 1;

    ASSERT_EQ(KAELZ4_rebuild_lz77_to_block(&tc.src, &tc.tuple, &tc.dst, &tc.result), KAE_LZ4_SUCC);
    ASSERT_GT(tc.result.dst_len, 0U);
}

// Purpose: the sequence fits in the current SGE, but its 16-byte rounded
// literal load would cross that SGE's guard page. The request still has the
// required 12-byte logical tail, split as one byte here and eleven in the next
// SGE, so the bounded wild-copy implementation must select its exact fallback.
TEST(KAELz4AsyncPolling, RebuildCopiesGuardedDirectLiteralBeforeSegmentTail)
{
    std::vector<uint8_t> input = BuildSingleSequenceSource(12);
    GuardedRebuildCase tc(input, {22, input.size() - 22});
    ASSERT_TRUE(tc.valid);
    ASSERT_GE(tc.tuple_storage.size(), sizeof(uint32_t) + sizeof(seqDef));

    *tc.SeqNum() = 1;
    seqDef *seq = tc.FirstSeq();
    seq->litLength = 17;
    seq->offBase = 0;
    seq->mlBase = 1;

    ASSERT_EQ(KAELZ4_rebuild_lz77_to_block(&tc.src, &tc.tuple, &tc.dst, &tc.result), KAE_LZ4_SUCC);
    ASSERT_TRUE(DecompressBlock(tc.dst_storage.data(), tc.result.dst_len, tc.expected));
}

// Purpose: rebuild literal copying across guarded source segments. Verifies that
// the buffer-list copy helper handles a segment tail shorter than 16 bytes
// without reading into the guard page.
TEST(KAELz4AsyncPolling, RebuildCopiesGuardedUnalignedSegmentedLiteral)
{
    std::vector<uint8_t> input = BuildSingleSequenceSource(12);
    GuardedRebuildCase tc(input, {17, input.size() - 17});
    ASSERT_TRUE(tc.valid);
    ASSERT_GE(tc.tuple_storage.size(), sizeof(uint32_t) + sizeof(seqDef));

    *tc.SeqNum() = 1;
    seqDef *seq = tc.FirstSeq();
    seq->litLength = 17;
    seq->offBase = 0;
    seq->mlBase = 1;

    ASSERT_EQ(KAELZ4_rebuild_lz77_to_block(&tc.src, &tc.tuple, &tc.dst, &tc.result), KAE_LZ4_SUCC);
    ASSERT_TRUE(DecompressBlock(tc.dst_storage.data(), tc.result.dst_len, tc.expected));
}

// Purpose: zero-copy block output with a single small input segment. Verifies
// hugepage-backed SGL input, direct submission through the polling session,
// callback completion, block decompression, and input/output CRC.
TEST(KAELz4AsyncPolling, ZeroCopy_BlockSmall_WithCRC)
{
    KAELZ4_REQUIRE_ZERO_COPY();
    RunSingleCase(MemoryMode::kZeroCopy, TaskFormat::kBlock, kSmallSize, 1, true, false, 0x01);
}

// Purpose: zero-copy block output with multi-segment SGL input larger than
// 64KB. Verifies input spanning multiple kaelz4_buffer entries, hardware 64KB
// chunking, block stitching after chunking, decompression, and CRC.
TEST(KAELz4AsyncPolling, ZeroCopy_BlockLargeSglInput_WithCRC)
{
    KAELZ4_REQUIRE_ZERO_COPY();
    RunSingleCase(MemoryMode::kZeroCopy, TaskFormat::kBlock, kLargeSize, 4, true, false, 0x02);
}

// Purpose: zero-copy frame output with full frame preferences. Verifies content
// size, block checksum, content checksum, frame header/footer, decompression,
// and CRC.
TEST(KAELz4AsyncPolling, ZeroCopy_Frame_WithPreferencesAndCRC)
{
    KAELZ4_REQUIRE_ZERO_COPY();
    RunSingleCase(MemoryMode::kZeroCopy, TaskFormat::kFrame, kFrameSize, 1, true, true, 0x03);
}

// Purpose: zero-copy frame output with multi-segment SGL input. Verifies that
// frame wrapping can consume segmented input and produce LZ4F-decodable data.
TEST(KAELz4AsyncPolling, ZeroCopy_FrameSglInput_MultiSegment)
{
    KAELZ4_REQUIRE_ZERO_COPY();
    RunSingleCase(MemoryMode::kZeroCopy, TaskFormat::kFrame, kFrameSize, 5, true, false, 0x04);
}

// Purpose: zero-copy LZ77 raw output rebuilt to block format. Verifies that the
// tuple destination is also hugepage-backed SGL memory, then rebuilds with
// KAELZ4_rebuild_lz77_to_block after the callback and checks CRC.
TEST(KAELz4AsyncPolling, ZeroCopy_LZ77RawToBlock_WithCRC)
{
    KAELZ4_REQUIRE_ZERO_COPY();
    RunSingleCase(MemoryMode::kZeroCopy, TaskFormat::kLz77ToBlock, kLargeSize, 4, true, false, 0x05);
}

// Purpose: end-to-end compatibility with kzip's historical partial tuple
// allocation. Sends a 4KB source to hardware with an actual 8KB raw tuple
// buffer, then rebuilds, decompresses, compares bytes, and verifies CRC.
TEST(KAELz4AsyncPolling, ZeroCopy_LZ77Raw4KBToBlock_With8KBTuple)
{
    KAELZ4_REQUIRE_ZERO_COPY();
    RunSingleCase(MemoryMode::kZeroCopy, TaskFormat::kLz77ToBlock, kPartialTupleSourceSize, 1, true, false, 0x07,
        kPartialTupleBufferSize);
}

// Purpose: zero-copy LZ77 raw output rebuilt to frame format. Verifies tuple to
// frame conversion, frame preferences, header/footer/checksum padding, and final
// frame decompression.
TEST(KAELz4AsyncPolling, ZeroCopy_LZ77RawToFrame_WithCRC)
{
    KAELZ4_REQUIRE_ZERO_COPY();
    RunSingleCase(MemoryMode::kZeroCopy, TaskFormat::kLz77ToFrame, kLargeSize, 4, true, true, 0x06);
}

// Purpose: zero-copy block output with 16 tasks submitted before polling.
// Verifies direct in-flight submission, completion reclamation, CRC, and
// order-independent result validation in polling mode.
TEST(KAELz4AsyncPolling, ZeroCopy_InflightBlockTasks_WithCRC)
{
    KAELZ4_REQUIRE_ZERO_COPY();
    RunInflightCase(MemoryMode::kZeroCopy, TaskFormat::kBlock, kInflightTasks, kSmallSize, 2, true, false);
}

// Purpose: zero-copy frame output with 16 tasks submitted before polling.
// Verifies frame post-processing, independent frame generation, and CRC under
// multiple in-flight tasks.
TEST(KAELz4AsyncPolling, ZeroCopy_InflightFrameTasks_WithCRC)
{
    KAELZ4_REQUIRE_ZERO_COPY();
    RunInflightCase(MemoryMode::kZeroCopy, TaskFormat::kFrame, kInflightTasks, kSmallSize, 2, true, true);
}

// Purpose: zero-copy LZ77 raw multi-task flow. Submits 16 raw tasks and rebuilds
// alternating results to block/frame, covering tuple SGL output, polling
// completion, and CRC after rebuild.
TEST(KAELz4AsyncPolling, ZeroCopy_InflightLZ77RawTasks_ToBlockAndFrame)
{
    KAELZ4_REQUIRE_ZERO_COPY();
    RunInflightCase(MemoryMode::kZeroCopy, TaskFormat::kLz77ToBlock, kInflightTasks, kSmallSize, 3, true, true);
}

// Purpose: zero-copy mixed-format multi-task flow. Mixes block, frame,
// LZ77-to-block, and LZ77-to-frame in one session to verify that queue/context
// reuse does not cross-contaminate post-processing paths.
TEST(KAELz4AsyncPolling, ZeroCopy_InflightMixedFormats_WithCRC)
{
    KAELZ4_REQUIRE_ZERO_COPY();
    RunMixedInflightCase(MemoryMode::kZeroCopy);
}

// Purpose: zero-copy queue backpressure. Submits 72 block tasks to fill the
// current 64 direct contexts, exercise enqueueing, then verify polling drains
// and resubmits queued work until all tasks complete.
TEST(KAELz4AsyncPolling, ZeroCopy_QueueBackpressure_ThenPollingDrains)
{
    KAELZ4_REQUIRE_ZERO_COPY();
    RunQueueBackpressureCase(MemoryMode::kZeroCopy);
}

// Purpose: zero-copy reset handling. Resets immediately after submitting
// multiple tasks, verifies pending tasks finish with failure callbacks and
// resources are cleaned, then verifies a new task still succeeds in the mode.
TEST(KAELz4AsyncPolling, ZeroCopy_ResetPendingTasks)
{
    KAELZ4_REQUIRE_ZERO_COPY();
    RunResetPendingCase(MemoryMode::kZeroCopy);
}

// Purpose: non-zero-copy block output with a single small input segment.
// Verifies the internal flat-buffer copy path used when usr_map is NULL,
// callback completion, block decompression, and CRC.
TEST(KAELz4AsyncPolling, NonZeroCopy_BlockSmall_WithCRC)
{
    RunSingleCase(MemoryMode::kNonZeroCopy, TaskFormat::kBlock, kSmallSize, 1, true, false, 0x11);
}

// Purpose: non-zero-copy flat-buffer copy from a guarded single segment.
// Verifies that an unaligned segment tail is copied exactly and does not read
// past the user buffer before hardware submission.
TEST(KAELz4AsyncPolling, NonZeroCopy_BlockGuardedUnalignedSingleSegment)
{
    RunGuardedNonZeroCopyCase(TaskFormat::kBlock, {4093}, true, false, 0x61);
}

// Purpose: non-zero-copy flat-buffer copy from guarded multi-segment input.
// Verifies that every user segment tail is copied exactly before concatenation
// into the internal flat staging buffer.
TEST(KAELz4AsyncPolling, NonZeroCopy_BlockGuardedUnalignedMultiSegment)
{
    RunGuardedNonZeroCopyCase(TaskFormat::kBlock, {31, 47, 4093}, true, false, 0x62);
}

// Purpose: non-zero-copy block output with multi-segment heap input larger than
// 64KB. Verifies internal flat-buffer concatenation, 64KB chunking, block
// stitching, and CRC.
TEST(KAELz4AsyncPolling, NonZeroCopy_BlockLargeMultiSegmentInput_WithCRC)
{
    RunSingleCase(MemoryMode::kNonZeroCopy, TaskFormat::kBlock, kLargeSize, 4, true, false, 0x12);
}

// Purpose: non-zero-copy frame output with full frame preferences. Verifies
// content size, block/content checksum, frame header/footer, and CRC on the flat
// buffer path.
TEST(KAELz4AsyncPolling, NonZeroCopy_Frame_WithPreferencesAndCRC)
{
    RunSingleCase(MemoryMode::kNonZeroCopy, TaskFormat::kFrame, kFrameSize, 1, true, true, 0x13);
}

// Purpose: non-zero-copy frame output with multi-segment heap input. Verifies
// segmented input concatenation, frame post-processing, CRC, and decodability.
TEST(KAELz4AsyncPolling, NonZeroCopy_FrameMultiSegmentInput_WithCRC)
{
    RunSingleCase(MemoryMode::kNonZeroCopy, TaskFormat::kFrame, kFrameSize, 5, true, false, 0x14);
}

// Purpose: non-zero-copy LZ77 raw literal-only special case rebuilt to block.
// The full LZ77 raw path is SGL-oriented; this covers the currently supported
// usr_map == NULL literal-only branch and CRC.
TEST(KAELz4AsyncPolling, NonZeroCopy_LZ77RawToBlock_WithCRC)
{
    RunSingleCase(MemoryMode::kNonZeroCopy, TaskFormat::kLz77ToBlock, kLiteralOnlyLz77Size, 1, true, false, 0x15);
}

// Purpose: non-zero-copy LZ77 raw literal-only special case rebuilt to frame.
// Verifies literal-only tuple rebuild, frame checksum, and frame decompression.
TEST(KAELz4AsyncPolling, NonZeroCopy_LZ77RawToFrame_WithCRC)
{
    RunSingleCase(MemoryMode::kNonZeroCopy, TaskFormat::kLz77ToFrame, kLiteralOnlyLz77Size, 1, true, true, 0x16);
}

// Purpose: non-zero-copy block output with 16 tasks submitted before polling.
// Verifies multiple in-flight tasks, completion reclamation, CRC, and
// decompression on the flat-buffer path.
TEST(KAELz4AsyncPolling, NonZeroCopy_InflightBlockTasks_WithCRC)
{
    RunInflightCase(MemoryMode::kNonZeroCopy, TaskFormat::kBlock, kInflightTasks, kSmallSize, 2, true, false);
}

// Purpose: non-zero-copy frame output with 16 tasks submitted before polling.
// Verifies that frame post-processing keeps header/footer/checksum data intact
// under flat-buffer multi-task execution.
TEST(KAELz4AsyncPolling, NonZeroCopy_InflightFrameTasks_WithCRC)
{
    RunInflightCase(MemoryMode::kNonZeroCopy, TaskFormat::kFrame, kInflightTasks, kSmallSize, 2, true, true);
}

// Purpose: non-zero-copy LZ77 raw literal-only multi-task flow. Submits 16 raw
// tasks and rebuilds alternating results to block/frame, covering rebuild and
// CRC on the flat-buffer path.
TEST(KAELz4AsyncPolling, NonZeroCopy_InflightLZ77RawTasks_ToBlockAndFrame)
{
    RunInflightCase(
        MemoryMode::kNonZeroCopy, TaskFormat::kLz77ToBlock, kInflightTasks, kLiteralOnlyLz77Size, 1, true, true);
}

// Purpose: non-zero-copy mixed-format multi-task flow. Mixes block, frame, and
// literal-only LZ77-to-block/frame work in one session to verify flat-buffer
// context reuse and post-processing isolation.
TEST(KAELz4AsyncPolling, NonZeroCopy_InflightMixedFormats_WithCRC)
{
    RunMixedInflightCase(MemoryMode::kNonZeroCopy);
}

// Purpose: non-zero-copy queue backpressure. Submits 72 block tasks to verify
// that the flat-buffer path can enqueue when direct contexts are exhausted and
// polling can keep resubmitting queued work until all tasks complete.
TEST(KAELz4AsyncPolling, NonZeroCopy_QueueBackpressure_ThenPollingDrains)
{
    RunQueueBackpressureCase(MemoryMode::kNonZeroCopy);
}

// Purpose: non-zero-copy reset handling. Resets immediately after submitting
// multiple tasks, verifies failure callbacks and flat-buffer resource cleanup,
// then verifies a new block task still succeeds after reset.
TEST(KAELz4AsyncPolling, NonZeroCopy_ResetPendingTasks)
{
    RunResetPendingCase(MemoryMode::kNonZeroCopy);
}
