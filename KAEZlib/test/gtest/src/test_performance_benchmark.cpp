/*
 * 性能基准测试 - 压缩/解压吞吐量与流式处理
 *
 * 测试维度：
 *   - 各压缩等级的压缩吞吐量
 *   - 各压缩等级的解压吞吐量
 *   - 不同数据类型的压缩吞吐量(零/文本/随机)
 *   - 不同压缩模式的吞吐量(DEFLATE/ZLIB/GZIP)
 *   - 流式压缩(Z_SYNC_FLUSH)性能
 *   - 多线程并发压缩性能
 */

#include "zlib_test_common.h"
#include <pthread.h>

/*
 * 测试目的: 测量各压缩等级的压缩吞吐量
 *          建立KAE zlib实现的性能基线
 * 预期结果: 所有等级压缩成功; 吞吐量随等级增加而下降
 * 测试数据: 1MB文本数据
 * 验证方法: 所有等级产生正确输出; 记录计时数据
 */
TEST(PerformanceBenchmarkTest, CompressionThroughput_ByLevel)
{
    const uLong data_length = 1024UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    for (int level = 1; level <= 9; ++level) {
        uLong compressed_size = compressBound(data_length);
        Bytef* compressed_data = new Bytef[compressed_size];

        struct timeval start, end;
        gettimeofday(&start, NULL);
        common_compress(15, level, data, data_length, compressed_data, compressed_size);
        gettimeofday(&end, NULL);

        double elapsed_us = get_time_diff_us(start, end);
        double throughput_gbps = (data_length * 1.0 / 1e9) / (elapsed_us / 1e6);

        fprintf(stdout, "[PERF] Level %d: compressed %lu -> %lu bytes, "
                "ratio=%.1f%%, time=%.0f us, throughput=%.3f GB/s\n",
                level, data_length, compressed_size,
                100.0 * compressed_size / data_length,
                elapsed_us, throughput_gbps);

        uLong decompressed_size = data_length + 1024;
        Bytef* decompressed_data = new Bytef[decompressed_size];
        common_uncompress(15, compressed_data, compressed_size, decompressed_data, decompressed_size);
        EXPECT_EQ(data_length, decompressed_size);
        EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

        delete[] compressed_data;
        delete[] decompressed_data;
    }
    delete[] data;
}

/*
 * 测试目的: 测量各压缩等级的解压吞吐量
 *          解压速度通常更快且随等级变化较小
 * 预期结果: 所有等级解压成功; 吞吐量通常高于压缩吞吐量
 * 测试数据: 1MB文本数据, 各等级压缩后解压
 * 验证方法: 所有解压产生正确输出; 记录计时数据
 */
TEST(PerformanceBenchmarkTest, DecompressionThroughput_ByLevel)
{
    const uLong data_length = 1024UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    for (int level = 1; level <= 9; ++level) {
        uLong compressed_size = compressBound(data_length);
        Bytef* compressed_data = new Bytef[compressed_size];
        common_compress(15, level, data, data_length, compressed_data, compressed_size);

        uLong decompressed_size = data_length + 1024;
        Bytef* decompressed_data = new Bytef[decompressed_size];

        struct timeval start, end;
        gettimeofday(&start, NULL);
        common_uncompress(15, compressed_data, compressed_size, decompressed_data, decompressed_size);
        gettimeofday(&end, NULL);

        double elapsed_us = get_time_diff_us(start, end);
        double throughput_gbps = (decompressed_size * 1.0 / 1e9) / (elapsed_us / 1e6);

        fprintf(stdout, "[PERF] Decompress level %d: %lu -> %lu bytes, "
                "time=%.0f us, throughput=%.3f GB/s\n",
                level, compressed_size, decompressed_size,
                elapsed_us, throughput_gbps);

        EXPECT_EQ(data_length, decompressed_size);
        EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

        delete[] compressed_data;
        delete[] decompressed_data;
    }
    delete[] data;
}

/*
 * 测试目的: 测量不同数据类型的压缩吞吐量
 *          展示数据可压缩性对吞吐量的影响
 * 预期结果: 高可压缩数据(零)有效吞吐量最高; 随机数据最低
 * 测试数据: 1MB的零/文本/随机数据
 * 验证方法: 所有压缩产生正确输出; 记录计时数据
 */
TEST(PerformanceBenchmarkTest, CompressionThroughput_ByDataType)
{
    const uLong data_length = 1024UL * 1024;

    struct DataSample {
        Bytef* data;
        const char* name;
        void (*gen)(Bytef*, unsigned long long);
    };

    DataSample samples[] = {
        {nullptr, "zeros", nullptr},
        {nullptr, "text", generate_text_data},
        {nullptr, "random", generate_random_data},
    };

    for (auto& sample : samples) {
        sample.data = new Bytef[data_length];
        if (sample.gen == nullptr) {
            generate_repeated_data(sample.data, data_length, 0x00);
        } else {
            sample.gen(sample.data, data_length);
        }

        uLong compressed_size = compressBound(data_length);
        Bytef* compressed_data = new Bytef[compressed_size];

        struct timeval start, end;
        gettimeofday(&start, NULL);
        common_compress(15, Z_BEST_COMPRESSION, sample.data, data_length,
                        compressed_data, compressed_size);
        gettimeofday(&end, NULL);

        double elapsed_us = get_time_diff_us(start, end);
        double throughput_gbps = (data_length * 1.0 / 1e9) / (elapsed_us / 1e6);
        double ratio = 100.0 * compressed_size / data_length;

        fprintf(stdout, "[PERF] Data=%s: compressed %lu -> %lu bytes, "
                "ratio=%.1f%%, time=%.0f us, throughput=%.3f GB/s\n",
                sample.name, data_length, compressed_size,
                ratio, elapsed_us, throughput_gbps);

        uLong decompressed_size = data_length + 1024;
        Bytef* decompressed_data = new Bytef[decompressed_size];
        common_uncompress(15, compressed_data, compressed_size, decompressed_data, decompressed_size);
        EXPECT_EQ(data_length, decompressed_size);
        EXPECT_EQ(memcmp(sample.data, decompressed_data, data_length), 0);

        delete[] sample.data;
        delete[] compressed_data;
        delete[] decompressed_data;
    }
}

/*
 * 测试目的: 测量不同压缩模式的吞吐量
 *          DEFLATE/ZLIB/GZIP模式的原始压缩速度应相近,
 *          差异仅来自头部/尾部处理开销
 * 预期结果: 三种模式均产生正确输出; 吞吐量可比
 * 测试数据: 1MB文本数据
 * 验证方法: 所有模式产生正确往返; 记录计时数据
 */
TEST(PerformanceBenchmarkTest, CompressionThroughput_ByMode)
{
    const uLong data_length = 1024UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    struct ModeInfo {
        int windowBits;
        const char* name;
    };

    ModeInfo modes[] = {
        {-15, "DEFLATE"},
        {15, "ZLIB"},
        {31, "GZIP"},
    };

    for (const auto& mode : modes) {
        uLong compressed_size = compressBound(data_length) + 24;
        Bytef* compressed_data = new Bytef[compressed_size];

        struct timeval start, end;
        gettimeofday(&start, NULL);
        common_compress(mode.windowBits, Z_DEFAULT_COMPRESSION, data, data_length,
                        compressed_data, compressed_size);
        gettimeofday(&end, NULL);

        double elapsed_us = get_time_diff_us(start, end);
        double throughput_gbps = (data_length * 1.0 / 1e9) / (elapsed_us / 1e6);

        fprintf(stdout, "[PERF] Mode=%s: compressed %lu -> %lu bytes, "
                "time=%.0f us, throughput=%.3f GB/s\n",
                mode.name, data_length, compressed_size,
                elapsed_us, throughput_gbps);

        uLong decompressed_size = data_length + 1024;
        Bytef* decompressed_data = new Bytef[decompressed_size];
        common_uncompress(mode.windowBits, compressed_data, compressed_size,
                          decompressed_data, decompressed_size);
        EXPECT_EQ(data_length, decompressed_size);
        EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

        delete[] compressed_data;
        delete[] decompressed_data;
    }
    delete[] data;
}

/*
 * 测试目的: 测量流式压缩(Z_SYNC_FLUSH)的性能
 *          流式压缩以分块方式处理数据, 常见于网络协议和实时应用
 * 预期结果: 流式压缩产生与一次性压缩相同的解压输出
 * 测试数据: 64KB文本数据, 4KB分块处理
 * 验证方法: 解压数据与原始匹配; 记录计时数据
 */
TEST(PerformanceBenchmarkTest, StreamingCompression_SyncFlush)
{
    const uLong data_length = 64UL * 1024;
    const uLong chunk_size = 4UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    uLong compressed_bound = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_bound];
    uLong total_compressed = 0;

    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    ASSERT_EQ(deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY), Z_OK);

    struct timeval start, end;
    gettimeofday(&start, NULL);

    uLong offset = 0;
    while (offset < data_length) {
        uLong remaining = data_length - offset;
        uLong this_chunk = (remaining > chunk_size) ? chunk_size : remaining;

        stream.next_in = data + offset;
        stream.avail_in = this_chunk;
        stream.next_out = compressed_data + stream.total_out;
        stream.avail_out = compressed_bound - stream.total_out;

        int flush = (offset + this_chunk >= data_length) ? Z_FINISH : Z_SYNC_FLUSH;
        int ret = deflate(&stream, flush);
        if (flush == Z_FINISH) {
            EXPECT_EQ(ret, Z_STREAM_END);
        } else {
            EXPECT_EQ(ret, Z_OK);
        }

        total_compressed = stream.total_out;
        offset += this_chunk;
    }

    gettimeofday(&end, NULL);
    total_compressed = stream.total_out;
    ASSERT_EQ(deflateEnd(&stream), Z_OK);

    double elapsed_us = get_time_diff_us(start, end);
    fprintf(stdout, "[PERF] Streaming compress: %lu -> %lu bytes, time=%.0f us\n",
            data_length, total_compressed, elapsed_us);

    uLong decompressed_size = data_length + 1024;
    Bytef* decompressed_data = new Bytef[decompressed_size];
    common_uncompress(15, compressed_data, total_compressed, decompressed_data, decompressed_size);

    EXPECT_EQ(data_length, decompressed_size);
    EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

/* ======================== 多线程并发测试 ======================== */

struct ThreadArg {
    Bytef* data;
    uLong data_length;
    int level;
    int windowBits;
    int thread_id;
    bool success;
};

static void* compress_thread_func(void* arg)
{
    ThreadArg* ta = (ThreadArg*)arg;
    ta->success = false;

    uLong compressed_size = compressBound(ta->data_length);
    Bytef* compressed_data = new Bytef[compressed_size];

    int ret = try_compress(ta->windowBits, ta->level, ta->data, ta->data_length,
                           compressed_data, compressed_size);
    if (ret != Z_OK) {
        delete[] compressed_data;
        return NULL;
    }

    uLong decompressed_size = ta->data_length + 1024;
    Bytef* decompressed_data = new Bytef[decompressed_size];
    ret = try_uncompress(ta->windowBits, compressed_data, compressed_size,
                         decompressed_data, decompressed_size);

    if (ret == Z_OK && decompressed_size == ta->data_length &&
        memcmp(ta->data, decompressed_data, ta->data_length) == 0) {
        ta->success = true;
    }

    delete[] compressed_data;
    delete[] decompressed_data;
    return NULL;
}

/*
 * 测试目的: 测量多线程并发压缩的性能和正确性
 *          验证zlib在多线程环境下(每个线程独立z_stream)的并发安全性
 * 预期结果: 所有线程压缩解压成功; 多线程吞吐量高于单线程
 * 测试数据: 每线程64KB文本数据, 4线程并发
 * 验证方法: 所有线程均成功; 记录总耗时
 */
TEST(PerformanceBenchmarkTest, MultiThreadConcurrent)
{
    const int num_threads = 4;
    const uLong data_length = 64UL * 1024;
    Bytef* shared_data = new Bytef[data_length];
    generate_text_data(shared_data, data_length);

    pthread_t threads[num_threads];
    ThreadArg args[num_threads];

    struct timeval start, end;
    gettimeofday(&start, NULL);

    for (int i = 0; i < num_threads; ++i) {
        args[i].data = shared_data;
        args[i].data_length = data_length;
        args[i].level = (i % 9) + 1;
        args[i].windowBits = 15;
        args[i].thread_id = i;
        args[i].success = false;
        pthread_create(&threads[i], NULL, compress_thread_func, &args[i]);
    }

    for (int i = 0; i < num_threads; ++i) {
        pthread_join(threads[i], NULL);
    }

    gettimeofday(&end, NULL);

    double elapsed_us = get_time_diff_us(start, end);
    fprintf(stdout, "[PERF] %d threads: total time=%.0f us\n", num_threads, elapsed_us);

    for (int i = 0; i < num_threads; ++i) {
        EXPECT_TRUE(args[i].success) << "Thread " << i << " failed";
    }

    delete[] shared_data;
}
