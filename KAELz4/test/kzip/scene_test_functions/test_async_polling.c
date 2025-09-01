#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <lz4.h>
#include <lz4frame.h>
#include <unistd.h>
#include <sys/stat.h>

static int g_has_done = 0; // 异步回调是否完成。需要初始化为0。
static int g_test_file = 1; //

struct my_custom_data {
    void *src;
    void *dst;
    void *src_decompd;
    size_t src_len;
    size_t dst_len;
    size_t src_decompd_len;
};

// 随机生成256KB的数据
static void generate_random_data(void *data, size_t size) {
    unsigned char *bytes = (unsigned char *)data;
    for (size_t i = 0; i < size; i++) {
        bytes[i] = rand() % 256;  // 随机生成字节
    }
}
static size_t read_inputFile(const char* fileName, void** input)
{
    FILE* sourceFile = fopen(fileName, "r");
    if (sourceFile == NULL) {
        fprintf(stderr, "%s not exist!\n", fileName);
        return 0;
    }
    int fd = fileno(sourceFile);
    struct stat fs;
    (void)fstat(fd, &fs);

    size_t input_size = fs.st_size;
    *input = malloc(input_size);
    if (*input == NULL) {
        return 0;
    }
    (void)fread(*input, 1, input_size, sourceFile);
    fclose(sourceFile);

    return input_size;
}

static void compression_callback2(struct kaelz4_result *result) {
    if (result->status != 0) {
        printf("Compression failed with status: %d\n", result->status);
        return;
    }

    // 在回调中获取压缩后的数据
    struct my_custom_data *my_data = (struct my_custom_data *)result->user_data;
    void *compressed_data = my_data->dst;
    size_t compressed_size = result->dst_len;

    my_data->dst_len = compressed_size;

    // 使用LZ4解压缩数据
    size_t tmp_src_len = result->src_size * 10;
    // 为解压数据分配内存
    void *dst_buffer = malloc(tmp_src_len);
    if (!dst_buffer) {
        printf("Memory allocation failed for decompressed data.\n");
        return;
    }

    LZ4F_decompressionContext_t dctx;
    LZ4F_createDecompressionContext(&dctx, 100);
    int ret = LZ4F_decompress(dctx, dst_buffer, &tmp_src_len,
                                            compressed_data, &compressed_size, NULL);
    if (ret < 0) {
        printf("Decompression failed with error code: %d\n", ret);
        free(dst_buffer);
        return;
    }
    my_data->src_decompd = dst_buffer;
    my_data->src_decompd_len = tmp_src_len;

    if (my_data->src_decompd_len != my_data->src_len) {
        printf("Test Error: 解压后与原始长度不一样. result->src_size=%ld   原始长度=%ld   压缩后解压长度=%ld \n",
            result->src_size,
            my_data->src_len,
            my_data->src_decompd_len);
    }

    // 比较解压后的数据和原始数据
    if (memcmp(my_data->src_decompd, my_data->src, result->src_size) == 0) {
        printf("Test Success.\n");
    } else {
        printf("Test Error:Decompressed data does not match the original data.\n");
    }

    // 释放解压后的数据
    free(dst_buffer);
    g_has_done = 1;
}

static int test_frame_polling(int contentChecksumFlag, int blockChecksumFlag, int contentSizeFlag)
{
    g_has_done = 0;
    size_t src_len = 256 * 1024;  // 256KB
    void *inbuf = malloc(src_len);
    if (!inbuf) {
        printf("Memory allocation failed for input data.\n");
        return -1;
    }
    // 生成随机数据
    generate_random_data(inbuf, src_len);

    if (g_test_file) {
        src_len = read_inputFile("../../../scripts/compressTestDataset/calgary", &inbuf);
    }


    // 为压缩数据分配内存
    size_t compressed_size = LZ4F_compressBound(src_len, NULL);
    void *compressed_data = malloc(compressed_size);
    if (!compressed_data) {
        printf("Memory allocation failed for compressed data.\n");
        free(inbuf);
        return -1;
    }

    // 初始化LZ4F压缩的参数
    LZ4F_preferences_t preferences = {0};
    preferences.frameInfo.blockSizeID = LZ4F_max64KB;  // 设定块大小
    if (contentChecksumFlag) {
        preferences.frameInfo.contentChecksumFlag = LZ4F_contentChecksumEnabled;
    }
    if (blockChecksumFlag) {
        preferences.frameInfo.blockChecksumFlag = LZ4F_blockChecksumEnabled;
    }
    if (contentSizeFlag) {
        preferences.frameInfo.contentSize = src_len;
    }

    void *sess = KAELZ4_create_async_compress_session(NULL);

    // 异步压缩
    struct kaelz4_result result = {0};
    struct my_custom_data mydata = {0};

    struct kaelz4_buffer_list src = {0};
    struct kaelz4_buffer src_buf[128];
    src.usr_data = &mydata;
    src.buf_num = 1;
    src.buf = src_buf;
    src.buf[0].data = inbuf;
    src.buf[0].buf_len = src_len;

    struct kaelz4_buffer dst_buf[128];
    struct kaelz4_buffer_list dst = {0};
    dst.buf_num = 1;
    dst.buf = dst_buf;
    dst.buf[0].data = compressed_data;
    dst.buf[0].buf_len = compressed_size;

    mydata.src = inbuf;
    mydata.src_len = src_len;
    mydata.dst = compressed_data;
    result.user_data = &mydata;
    result.src_size = src_len;
    result.dst_len = compressed_size;

    int compression_status = KAELZ4_compress_frame_async_in_session(sess, &src, &dst,
                                                      compression_callback2, &result, &preferences);

    if (compression_status != 0) {
        printf("Compression failed with error code: %d\n", compression_status);
        free(inbuf);
        free(compressed_data);
        return -1;
    }

    while (g_has_done != 1) {
        KAELZ4_async_polling_in_session(sess, 1);
        usleep(100);
    }
    KAELZ4_destroy_async_compress_session(sess);

    return compression_status;
}
int test_async_polling_interface()
{
    return test_frame_polling(0, 0, 0);
}
