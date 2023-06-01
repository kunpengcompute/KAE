#include "testsuit_common.h"

using namespace std;

#define ASSERT_UCHAR_EQ(size, buf1, buf2)     for (int i_macro = 0; i_macro < size; i_macro++) \
    { \
        if(buf1[i_macro]!=buf2[i_macro]) \
        { \
            FAIL(); \
        } \
    }
#define DEFINE_GENERATE_DATA_FUNCTION(bits)     static vector<DHData> GenerateData##bits() \
    { \
        vector<DHData> ret; \
        InternelGenerateData(bits, ret); \
        return ret; \
    }
#define DEFINE_GENERATE_DSA_DATA_FUNCTION(bits)     static vector<DHData> GenerateDSAData##bits() \
    { \
        vector<DHData> ret; \
        InternelGenerateDSAData(bits, ret); \
        return ret; \
    }
#define APPEND_DH_DATA(bits, dataset) { \
BIGNUM* p_##bits = BN_new(); \
BN_bin2bn(dhtest_##bits, sizeof(dhtest_##bits), p_##bits); \
dataset[bits] = DHData(bits, p_##bits, 2); \
}

#define INSTANTIATE_DH_CASE(bits) INSTANTIATE_TEST_SUITE_P(BitLen##bits, \
                                                          DHTest, \
                                                          ::testing::ValuesIn(DHTest::GenerateData##bits()));
#define INSTANTIATE_DSA_CASE(bits) INSTANTIATE_TEST_SUITE_P(DSA_BitLen##bits, \
                                                          DHTest, \
                                                          ::testing::ValuesIn(DHTest::GenerateDSAData##bits()));

// 质数p
static const unsigned char dhtest_768[] = {
    0xe2, 0x7f, 0x03, 0x40, 0x75, 0x67, 0xb2, 0x78, 0xaf, 0xb0, 0xa6, 0x2e, 0x96, 0xcf,
    0x79, 0x47, 0x42, 0x74, 0x01, 0x2f, 0x14, 0x88, 0x72, 0xc5, 0xff, 0x03, 0x9c, 0x70, 0x9a,
    0x3d, 0x89, 0x96, 0x14, 0x9b, 0x4d, 0x20, 0xbc, 0x4d, 0x56, 0xa6, 0xe8, 0x97, 0x66, 0x79,
    0x08, 0x0e, 0x44, 0x83, 0x79, 0xc8, 0xaa, 0xcc, 0x19, 0x4a, 0x23, 0xdb, 0xe6, 0x3f, 0xa0,
    0x69, 0x67, 0x6e, 0xf5, 0x4f, 0x7b, 0xab, 0x22, 0x6a, 0xbf, 0x97, 0x6f, 0x8b, 0xe9, 0x41,
    0xa3, 0x12, 0x6c, 0xc5, 0x24, 0x7a, 0x32, 0x01, 0x18, 0x22, 0x15, 0x36, 0xbc, 0xbc, 0xdf,
    0xa8, 0x3d, 0x82, 0xdc, 0x80, 0x03, 0x0b};

static const unsigned char dhtest_1024[] = {
    0xe5, 0x39, 0x7f, 0x9b, 0xad, 0x71, 0x82, 0x34, 0xb3, 0x07, 0x99, 0x0d, 0x8f, 0x4e,
    0xee, 0xdb, 0x66, 0x2b, 0xa1, 0xac, 0x3f, 0x7d, 0x92, 0xd4, 0xb3, 0x56, 0xed, 0x9d, 0x59,
    0x15, 0x6c, 0xcf, 0x5f, 0xf2, 0x12, 0x44, 0xa4, 0x1d, 0xa9, 0x7b, 0x41, 0x22, 0xfc, 0xdf,
    0xa9, 0xa0, 0x39, 0x54, 0x5d, 0xb2, 0x52, 0xde, 0xe5, 0x84, 0x5e, 0x8b, 0xe3, 0x57, 0xba,
    0x35, 0x1e, 0x62, 0x78, 0x92, 0x86, 0x74, 0xa8, 0xc7, 0x74, 0x62, 0xa7, 0xc7, 0xc9, 0x5d,
    0xc3, 0x17, 0xf8, 0xeb, 0xfa, 0x9b, 0xae, 0xe7, 0x2b, 0x59, 0x40, 0xa7, 0x08, 0xb9, 0xb0,
    0x53, 0x03, 0x43, 0xd1, 0xa8, 0xa1, 0xe1, 0xc8, 0x3a, 0xe6, 0x58, 0x64, 0xe1, 0xfb, 0x5c,
    0x4c, 0xd7, 0xbd, 0x94, 0xde, 0xc7, 0xdf, 0x9d, 0xe5, 0x65, 0xd9, 0x46, 0xf3, 0x0f, 0x42,
    0x1b, 0x30, 0xb8, 0x27, 0x02, 0x27, 0xe1, 0x57, 0x23};

static const unsigned char dhtest_1536[] = {
    0xe8, 0x85, 0xd8, 0xeb, 0xdc, 0xc9, 0x13, 0xe2, 0x1a, 0x81, 0xa6, 0x24, 0x64, 0xf0,
    0xa9, 0x57, 0x3d, 0xeb, 0xbe, 0x4c, 0x3c, 0xfb, 0xe4, 0x3c, 0x28, 0xea, 0x5b, 0x1b, 0x68,
    0x58, 0xaa, 0x50, 0x00, 0x9e, 0x99, 0xae, 0x24, 0x30, 0xda, 0x25, 0x73, 0xe8, 0x56, 0x16,
    0x2f, 0x23, 0x9b, 0x00, 0x00, 0x43, 0x07, 0xdb, 0xbf, 0x49, 0x45, 0x9f, 0x84, 0xa7, 0xd9,
    0x8d, 0xfb, 0x7c, 0x09, 0xa3, 0x38, 0x81, 0x59, 0x95, 0xc7, 0xd3, 0xf5, 0x0f, 0xd5, 0xa4,
    0x62, 0xcc, 0x06, 0x9f, 0x68, 0xea, 0x84, 0x7e, 0x3f, 0x6b, 0x45, 0xe9, 0x58, 0x65, 0x72,
    0x1d, 0x09, 0x41, 0xa5, 0x76, 0x1d, 0x0a, 0x2a, 0xaf, 0xe3, 0xaa, 0x30, 0x26, 0x2e, 0x2c,
    0xbb, 0x03, 0xc2, 0xc4, 0x49, 0xa7, 0xc5, 0x10, 0x37, 0x5a, 0x1d, 0x68, 0x5e, 0x7e, 0x10,
    0xfd, 0x2c, 0x25, 0x4a, 0xa6, 0x7d, 0x80, 0x9d, 0x27, 0x85, 0x1e, 0xd1, 0x38, 0x39, 0xec,
    0x93, 0x21, 0x00, 0xd7, 0x8e, 0xe5, 0xbc, 0x3e, 0x43, 0xc3, 0x90, 0x46, 0x00, 0x6e, 0x4f,
    0xcb, 0x7e, 0x69, 0x70, 0xfa, 0xeb, 0x93, 0x83, 0x2c, 0x43, 0x9f, 0xab, 0xde, 0x2d, 0x3d,
    0xd7, 0x45, 0x46, 0x24, 0x44, 0x46, 0x30, 0xda, 0xfe, 0x3c, 0x65, 0x19, 0x5f, 0x00, 0x45,
    0x8e, 0xba, 0xb4, 0x3f, 0x18, 0xbb, 0x0e, 0x34, 0x71, 0x4a, 0x35, 0x23, 0x23};

static const unsigned char dhtest_2048[] = {
    0xff, 0xf3, 0xc5, 0xaa, 0x89, 0xa7, 0x23, 0xe3, 0xe6, 0xd7, 0xb3, 0x87, 0xae, 0xa7,
    0x4f, 0x44, 0x3d, 0x07, 0x47, 0x4f, 0xac, 0x4e, 0x88, 0x68, 0x39, 0x4e, 0x1f, 0xa5, 0xf3,
    0x98, 0x8e, 0xb1, 0xd1, 0x00, 0x3e, 0xf4, 0x1a, 0x4b, 0x1c, 0x7e, 0xc4, 0xaa, 0xa3, 0xcc,
    0xb3, 0xab, 0x09, 0x47, 0x21, 0xcc, 0x7d, 0x37, 0x98, 0x81, 0x5b, 0x12, 0xd1, 0x94, 0x9f,
    0xe5, 0x22, 0x4a, 0x5c, 0xb5, 0x29, 0x58, 0x17, 0x26, 0xc8, 0x38, 0x09, 0x26, 0x44, 0x8d,
    0x25, 0x3b, 0xb7, 0x7e, 0xed, 0x23, 0xd3, 0x32, 0xa2, 0x3d, 0xc1, 0x08, 0x13, 0x03, 0x3a,
    0x7e, 0x7c, 0x44, 0x48, 0xa5, 0x7d, 0xc8, 0xda, 0x59, 0xfe, 0x0d, 0xff, 0xda, 0xf1, 0xcb,
    0xcb, 0x9a, 0x61, 0x14, 0xd2, 0x9f, 0xf3, 0x0c, 0x5d, 0xe9, 0x6b, 0xd7, 0xf0, 0x76, 0x30,
    0x4c, 0xee, 0x67, 0x85, 0x98, 0x5e, 0x4c, 0xea, 0x1d, 0xae, 0xbf, 0xb5, 0xc6, 0x0b, 0x39,
    0x7f, 0x0c, 0x08, 0x69, 0x26, 0xc9, 0x6f, 0xf3, 0xd0, 0x1f, 0x02, 0x55, 0x24, 0xd3, 0x26,
    0x6d, 0x77, 0xf9, 0xcf, 0x42, 0xe1, 0xeb, 0x7c, 0x92, 0x48, 0x60, 0x95, 0x61, 0x0e, 0x20,
    0x25, 0x26, 0x1c, 0xd0, 0xf0, 0xb0, 0x64, 0x24, 0x42, 0x3e, 0x3f, 0x57, 0x58, 0x25, 0x40,
    0xd3, 0xd6, 0x4f, 0x3c, 0x28, 0x24, 0x0c, 0x4f, 0x3c, 0x1b, 0xad, 0xf8, 0xb6, 0x43, 0x7c,
    0x5e, 0x56, 0x79, 0xf2, 0x47, 0xe7, 0xf9, 0x4f, 0x6f, 0xe7, 0x34, 0x5c, 0x95, 0x97, 0x81,
    0x2f, 0xd2, 0x0d, 0x3c, 0x56, 0x46, 0x06, 0x26, 0xeb, 0xa9, 0xd4, 0x02, 0xe1, 0xfa, 0x76,
    0x6e, 0xc9, 0x96, 0xc0, 0xaf, 0x74, 0x8d, 0xe6, 0x7b, 0x28, 0xf7, 0x7b, 0x38, 0x8c, 0xfc,
    0xf6, 0x55, 0x55, 0xd8, 0x07, 0x5a, 0x6f, 0x2b, 0x0b, 0x37, 0x65, 0x0a, 0xad, 0x36, 0xf8,
    0x73, 0x73};

static const unsigned char dhtest_3072[] = {
    0x84, 0x01, 0xd2, 0xc5, 0x9e, 0x8a, 0x44, 0x34, 0x5a, 0x18, 0xfa, 0xa5, 0x33, 0x51,
    0x23, 0xc1, 0xc3, 0x66, 0x95, 0x2f, 0xab, 0xc8, 0xb1, 0xf3, 0x9f, 0x59, 0x15, 0xe4, 0x0e,
    0x67, 0x20, 0xda, 0xcc, 0xc0, 0xc1, 0xfb, 0x3d, 0x62, 0xca, 0x98, 0xf3, 0xd2, 0x49, 0xed,
    0x5c, 0x36, 0x7f, 0x80, 0xd8, 0xe4, 0x9e, 0x6a, 0x33, 0x78, 0x57, 0xac, 0x94, 0x77, 0xe3,
    0x39, 0x84, 0xf4, 0x4a, 0xd0, 0xeb, 0x18, 0x5c, 0x1f, 0xd7, 0xa3, 0xf6, 0xd7, 0x90, 0x1a,
    0x4c, 0x8f, 0x38, 0x8b, 0xd2, 0x3d, 0x04, 0x72, 0xc1, 0x4d, 0xca, 0x17, 0xc9, 0x47, 0x7a,
    0x36, 0xdd, 0xe4, 0x18, 0x08, 0xaf, 0xba, 0x08, 0x34, 0x49, 0x08, 0x0b, 0xca, 0xad, 0xc2,
    0x5b, 0xb6, 0xf3, 0xd9, 0xca, 0xca, 0xfd, 0x87, 0xa7, 0x9b, 0xa2, 0x7b, 0xcb, 0xaf, 0xc3,
    0xeb, 0xc2, 0x69, 0x6d, 0x4f, 0x2d, 0x4a, 0xe3, 0xb2, 0x81, 0x1a, 0x29, 0x1b, 0xce, 0x92,
    0xfb, 0x71, 0xd3, 0xca, 0x27, 0xe7, 0xc4, 0xa0, 0x10, 0x0a, 0x34, 0x2a, 0x0f, 0x1c, 0xde,
    0xf5, 0x79, 0x56, 0x00, 0x08, 0xe1, 0xe5, 0xcf, 0xf5, 0x59, 0xfa, 0xc9, 0x90, 0x9c, 0x60,
    0xf6, 0x79, 0xa8, 0xa1, 0x27, 0xb2, 0xff, 0x54, 0xdd, 0xb7, 0x3f, 0xd3, 0x31, 0x01, 0xc3,
    0xca, 0xb7, 0x2a, 0x01, 0xa4, 0x2a, 0x04, 0xb8, 0x32, 0xe3, 0x18, 0xe8, 0x53, 0x74, 0x73,
    0x39, 0xd0, 0xa5, 0xac, 0x83, 0xb0, 0x8d, 0xe6, 0x8d, 0xc0, 0xe0, 0x95, 0x28, 0x36, 0x47,
    0xe3, 0xdd, 0x0f, 0x56, 0x87, 0x45, 0xfb, 0x6f, 0x45, 0x08, 0x63, 0xe5, 0xd3, 0x9d, 0x64,
    0x1c, 0x2b, 0xa2, 0x32, 0xb3, 0x5f, 0x82, 0xf3, 0xe6, 0x6c, 0x10, 0xb4, 0x36, 0xe9, 0x1a,
    0x1a, 0x57, 0x43, 0x8a, 0x81, 0xde, 0xb4, 0x21, 0xb0, 0x46, 0x60, 0x61, 0x65, 0x5c, 0x54,
    0x53, 0xe9, 0x73, 0xbb, 0x54, 0xff, 0xce, 0x9b, 0x8d, 0x56, 0x0f, 0xec, 0xb6, 0x36, 0x50,
    0xe9, 0x8b, 0xac, 0x3f, 0xee, 0x4e, 0x12, 0xc4, 0x81, 0x3d, 0x06, 0x66, 0xd9, 0x17, 0xbb,
    0xd0, 0x57, 0x60, 0x78, 0xcc, 0x68, 0xbe, 0x4b, 0x67, 0xbd, 0x76, 0xdc, 0x82, 0x57, 0x07,
    0xe1, 0x59, 0x2a, 0x14, 0xe0, 0x58, 0xc7, 0x43, 0xc1, 0xff, 0x96, 0xf6, 0x15, 0x65, 0x47,
    0x2b, 0xe6, 0x65, 0x1f, 0xd6, 0x31, 0x4e, 0x50, 0x16, 0x74, 0x97, 0xe2, 0x66, 0x11, 0x4d,
    0x56, 0x3b, 0x36, 0x4a, 0x39, 0x9a, 0x1e, 0x45, 0xd7, 0xee, 0x81, 0xf2, 0x17, 0x39, 0xfd,
    0xd3, 0xca, 0x15, 0x49, 0x8f, 0x89, 0xfe, 0x96, 0xa0, 0xaf, 0xe2, 0xc3, 0x09, 0x9f, 0x53,
    0xa7, 0x72, 0xc4, 0xba, 0xb8, 0xa7, 0xf2, 0x07, 0xe4, 0x9a, 0xd0, 0xd0, 0xb5, 0xd3, 0x48,
    0x5d, 0xb6, 0xcb, 0x0c, 0xf6, 0xc3, 0xaf, 0xf0, 0x0f, 0x03};

static const unsigned char dhtest_4096[] = {
    0xde, 0x7d, 0x47, 0xaf, 0x76, 0x03, 0xd9, 0xd7, 0x8f, 0x35, 0x03, 0x95, 0x8b, 0x4b,
    0xad, 0x2c, 0x74, 0x4a, 0x07, 0x21, 0xa6, 0x70, 0x54, 0x03, 0x9b, 0xb3, 0x86, 0x5f, 0x9c,
    0x04, 0x8b, 0x5e, 0x83, 0x83, 0x70, 0x27, 0xbf, 0x4c, 0x87, 0x65, 0x92, 0xa8, 0x93, 0x89,
    0xee, 0xb1, 0xed, 0xa6, 0xba, 0x40, 0xab, 0x21, 0xb8, 0x57, 0xac, 0x51, 0xb9, 0x72, 0x81,
    0xf8, 0x6c, 0x36, 0x07, 0x71, 0x7a, 0x31, 0xa8, 0x41, 0xa0, 0x32, 0xe6, 0x59, 0x72, 0xa4,
    0x2b, 0x16, 0xdf, 0xa9, 0x91, 0x71, 0xe4, 0x2a, 0x87, 0x65, 0xfa, 0x1e, 0x45, 0x92, 0xc4,
    0xf4, 0x32, 0xbe, 0x8b, 0xde, 0x4f, 0x95, 0x6e, 0xbc, 0xa7, 0xf7, 0x63, 0x66, 0xaa, 0x83,
    0x02, 0x33, 0xf1, 0xe9, 0x9e, 0x05, 0x1b, 0x06, 0x18, 0x40, 0x36, 0xca, 0xaa, 0xb2, 0xf4,
    0x31, 0xcf, 0x35, 0xdb, 0xa5, 0xd4, 0xd2, 0x2e, 0xb2, 0x28, 0xbd, 0xc2, 0x66, 0x39, 0x41,
    0xe2, 0xc5, 0x03, 0x06, 0x5c, 0x81, 0x85, 0x52, 0x49, 0xda, 0x17, 0x99, 0x33, 0x7d, 0x33,
    0x7e, 0x3e, 0x3f, 0x11, 0xe4, 0x2e, 0xe8, 0x8d, 0x08, 0x81, 0x48, 0xbf, 0x3e, 0xad, 0x35,
    0x3f, 0x49, 0xf2, 0xf7, 0x22, 0x57, 0xbd, 0x9d, 0x04, 0x66, 0x5a, 0x53, 0x7b, 0x78, 0xd7,
    0x09, 0x6a, 0xdb, 0x91, 0x2d, 0xf4, 0x13, 0xb5, 0xab, 0x6f, 0x9b, 0xaf, 0xdb, 0x4f, 0x7b,
    0x2f, 0x29, 0x34, 0xc0, 0x54, 0x9c, 0x1b, 0xa9, 0x24, 0xd5, 0x98, 0x8b, 0x75, 0xeb, 0xa8,
    0x0a, 0x04, 0xf5, 0xd2, 0xcf, 0x06, 0x1c, 0x00, 0xfe, 0xe7, 0x18, 0x5b, 0x3f, 0x80, 0x31,
    0xa4, 0x41, 0x44, 0x1f, 0x17, 0x8f, 0x8e, 0xa0, 0xaa, 0x33, 0xfb, 0x98, 0xaf, 0x72, 0x77,
    0x0d, 0x64, 0x29, 0x4e, 0xaa, 0x37, 0x73, 0x86, 0x61, 0x62, 0xb7, 0xcd, 0x75, 0xd5, 0x66,
    0x81, 0x70, 0x10, 0x91, 0x7c, 0xd3, 0x7d, 0x18, 0x55, 0xf9, 0x11, 0xe3, 0xc0, 0xd6, 0x3a,
    0x33, 0x13, 0x92, 0x8d, 0xda, 0x0e, 0x82, 0x89, 0xd4, 0xf6, 0x41, 0x83, 0xd0, 0xd6, 0x64,
    0x94, 0x2a, 0xd7, 0xf8, 0x8b, 0x0a, 0x4f, 0xe8, 0x6c, 0x76, 0xe3, 0xfd, 0x25, 0x47, 0x32,
    0xb9, 0x97, 0x6d, 0xec, 0xf1, 0xee, 0xb0, 0xa3, 0x59, 0x3a, 0xdd, 0x32, 0x14, 0x10, 0xb9,
    0xcd, 0x5b, 0x9e, 0x35, 0xcc, 0xaa, 0x14, 0x58, 0x9e, 0xcf, 0x48, 0x13, 0x12, 0x93, 0xcd,
    0x15, 0xac, 0x1e, 0x78, 0xae, 0x4b, 0x17, 0xaa, 0xf1, 0x63, 0x26, 0x8e, 0x11, 0xc3, 0xf3,
    0x67, 0x2a, 0x3b, 0x2e, 0x08, 0x3a, 0xf7, 0xee, 0xc8, 0xa0, 0x9d, 0x02, 0x51, 0x12, 0x39,
    0x2c, 0x78, 0x04, 0xdd, 0x8a, 0x9f, 0x25, 0x03, 0x40, 0x55, 0x32, 0x74, 0xc3, 0x36, 0xf8,
    0x61, 0xf7, 0x2a, 0x22, 0xd5, 0x26, 0x12, 0xad, 0xde, 0xe3, 0x73, 0xe8, 0xff, 0x8b, 0xd0,
    0xee, 0x29, 0xb8, 0x77, 0xfd, 0xe0, 0xb0, 0x02, 0x67, 0xaf, 0x42, 0x74, 0x8d, 0xbb, 0x83,
    0x0d, 0x58, 0xe4, 0xdf, 0x4e, 0x70, 0x42, 0xb0, 0x21, 0xef, 0x75, 0xdb, 0xe6, 0x3d, 0x52,
    0xab, 0x47, 0xb4, 0xab, 0x02, 0x02, 0xde, 0xa3, 0x96, 0x8d, 0xfa, 0xb4, 0x78, 0xbf, 0xca,
    0xe2, 0xb2, 0xf4, 0x95, 0xd0, 0xc9, 0x6a, 0xb4, 0x68, 0x80, 0xd1, 0x12, 0x9c, 0x97, 0x39,
    0x06, 0xf5, 0x59, 0xba, 0x62, 0x69, 0xbf, 0x8f, 0x7d, 0x39, 0xc2, 0xb5, 0x8a, 0x6e, 0xc9,
    0x7a, 0xbb, 0xd4, 0x35, 0x92, 0x24, 0xde, 0x50, 0xba, 0x3b, 0x53, 0x98, 0xed, 0xf3, 0xf0,
    0x3c, 0x39, 0x58, 0xff, 0x53, 0x1d, 0xf9, 0x7a, 0xc7, 0xdd, 0xb8, 0x6c, 0x39, 0x74, 0x18,
    0x6e, 0xfd, 0x16, 0x0f, 0x51, 0x06, 0x8c, 0x2c, 0x0f, 0x82, 0xc5, 0x84, 0x51, 0xcb, 0x97,
    0xd3, 0xfd, 0x03};

struct DHData
{
    // dh算法的位数
    int bits;
    // 质数
    BIGNUM *p;
    int g;

    // DSA参数
    BIGNUM *q;
    BIGNUM *g_dsa;

public:
    DHData(){}

    DHData(int bits_, const BIGNUM *p_, int g_, const BIGNUM *q_ = NULL, const BIGNUM *g_dsa_ = NULL) : 
        bits(bits_), p((BIGNUM *)p_), g(g_),q((BIGNUM *)q_),g_dsa((BIGNUM *)g_dsa_)
    {
        
    }
};

class dh_async_arg_t
{
public:
    DH *dh;
    EVP_PKEY *dh_key;
    EVP_PKEY *dh_other_key;
    BIGNUM *other_pub_key;
    int loop_cnt;
    int evp;
    ENGINE *e;
    ASYNC_JOB *inprogress_job;
    ASYNC_WAIT_CTX *wait_ctx;
    unsigned char *out;
};

class dh_async_evp_arg_t: public dh_async_arg_t
{
public:
    DH *dh_hw;
    DH *dh_sw;
    unsigned char *out_hw;
    unsigned char *out_sw;
} ;

int ASYNC_JOBS = 3;

int run_async_jobs(vector<dh_async_arg_t*> dh_array, int jobs, int (*loop_function)(void *));
EVP_PKEY* generate_key_sync_evp(ENGINE *e, DH* dh);
int generate_key_sync_dh(DH* dh);
int run_generate_key(void *arg);
int compute_key_sync_dh(DH *dh, const BIGNUM *other_pub_key, unsigned char *out);
int compute_key_sync_evp(EVP_PKEY *dh, EVP_PKEY *otherDH, ENGINE *e, unsigned char *out);
int run_compute_key(void *arg);
int run_evp(void *arg);
int generate_compute_key_evp(ENGINE *e, DH* dh_hw, DH* dh_sw,  unsigned char *out_hw,  unsigned char *out_sw);
void run_threads(vector<dh_async_arg_t*> dh_array, void *(*start_routine) (void *));
void* run_generate_key_thread(void *arg);
void* run_compute_key_thread(void *arg);
int get_hpre_queue_instances();
void* run_evp_thread(void *arg);

class DHTest : public testing::TestWithParam<DHData>
{
    static ENGINE *_engine;
    static map<int,DHData> _primes;
public:
    ENGINE* GetEngine()
    {
        return _engine;
    }

    DEFINE_GENERATE_DATA_FUNCTION(768);
    DEFINE_GENERATE_DATA_FUNCTION(1024);
    DEFINE_GENERATE_DATA_FUNCTION(1536);
    DEFINE_GENERATE_DATA_FUNCTION(2048);
    DEFINE_GENERATE_DATA_FUNCTION(3072);
    DEFINE_GENERATE_DATA_FUNCTION(4096);

    DEFINE_GENERATE_DSA_DATA_FUNCTION(768);
    DEFINE_GENERATE_DSA_DATA_FUNCTION(1024);
    DEFINE_GENERATE_DSA_DATA_FUNCTION(1536);
    DEFINE_GENERATE_DSA_DATA_FUNCTION(2048);
    DEFINE_GENERATE_DSA_DATA_FUNCTION(3072);
    DEFINE_GENERATE_DSA_DATA_FUNCTION(4096);

    static void InternelGenerateData(int bits, vector<DHData>& ret)
    {
        if(_primes.count(bits) == 0) throw exception();
        const int g_array[] = {2, 5, 6, 8, 12};
        for (int i = 0; i < 5; ++i)
        {
            auto data = _primes[bits];
            data.g = g_array[i];
            ret.push_back(data);
        }
    }

    static void InternelGenerateDSAData(int bits, vector<DHData> &ret)
    {
        DSA *dsa = DSA_new();
        DSA_generate_parameters_ex(dsa, bits, NULL, 0, NULL, NULL, NULL);
        const BIGNUM *g, *p, *q;
        DSA_get0_pqg(dsa, &p, &q, &g);
        DHData data(bits, p, 0, q, g);
        ret.push_back(data);
    }

    static map<int,DHData> PreparePrimes()
    {
        init_openssl();
        OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
        _engine = ENGINE_by_id("kae");

        map<int, DHData> ret;
        APPEND_DH_DATA(768,ret);
        APPEND_DH_DATA(1024,ret);
        APPEND_DH_DATA(1536,ret);
        APPEND_DH_DATA(2048,ret);
        APPEND_DH_DATA(3072,ret);
        APPEND_DH_DATA(4096,ret);
        return ret;
    }

    virtual void SetUp()
    {
        // init_openssl();
        // OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
        // _engine = ENGINE_by_id("kae");
    }
    virtual void TearDown()
    {
        // ENGINE_free(_engine);
        // _engine = NULL;
    }

    DH* CreateDH(const DHData& data, BIGNUM* priv_key = NULL)
    {
        if (_engine == NULL)
            return NULL;
        DH *dh = DH_new_method(_engine);
        if (dh == NULL)
            return NULL;
        if (data.q != NULL)
        {
            if (!DH_set0_pqg(dh, BN_dup(data.p), BN_dup(data.q), BN_dup(data.g_dsa)))
                return NULL;
        }
        else
        {
            BIGNUM *g = BN_new();
            if (g == NULL)
                return NULL;
            if (!BN_set_word(g, data.g))
                return NULL;
            if (!DH_set0_pqg(dh, BN_dup(data.p), NULL, g))
                return NULL;
        }

        if (priv_key)
        {
            BIGNUM *cp_priv_key = BN_new();
            BN_copy(cp_priv_key, priv_key);
            if (!DH_set0_key(dh, NULL, cp_priv_key))
            {
                return NULL;
            }
        }
        return dh;
    }

    BIGNUM *CreatePrivKey(int bits)
    {
        unsigned int l = bits - 1;
        BIGNUM *priv_key = BN_secure_new();
        if (!BN_priv_rand(priv_key, l, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
        {
            return NULL;
        }

        return priv_key;
    }

    const BIGNUM* GetPubKey(DH* dh)
    {
        return DH_get0_pub_key(dh);
    }

    const BIGNUM* GetPubKey(EVP_PKEY* dh_key)
    {
        return DH_get0_pub_key(EVP_PKEY_get0_DH(dh_key));
    }

    vector<dh_async_arg_t*> PrepareAsyncData(DHData dh_data, ENGINE *engine, int jobs, BIGNUM* priv_key)
    {
        vector<dh_async_arg_t*> dh_array;
        for (int i = 0; i < jobs; i++)
        {
            DH *dh = CreateDH(dh_data, priv_key);
            if (dh == NULL)
                return vector<dh_async_arg_t*>();
            
            dh_async_arg_t* arg = new dh_async_arg_t();
            arg->dh = dh;
            arg->loop_cnt = 1;
            arg->inprogress_job = NULL;
            arg->wait_ctx = ASYNC_WAIT_CTX_new();
            arg->evp = 0;
            arg->e = engine;
            arg->dh_key = NULL;
            arg->dh_other_key = NULL;
            arg->other_pub_key = NULL;
            arg->out = NULL;

            if(engine == NULL)
            {
                DH_set_method(arg->dh, DH_get_default_method());
            }

            dh_array.push_back(arg);
        }
        return dh_array;
    }

    vector<dh_async_arg_t*> PrepareAsyncCompKeyData(DHData dh_data, ENGINE *engine, int jobs, BIGNUM* priv_key1, BIGNUM* priv_key2)
    {
        vector<dh_async_arg_t*> dh_array;
        for (int i = 0; i < jobs; i++)
        {
            DH *dh = CreateDH(dh_data, priv_key1);
            if (dh == NULL)
                return vector<dh_async_arg_t*>();
            DH *otherDH = CreateDH(dh_data, priv_key2);
            if (otherDH == NULL)
                return vector<dh_async_arg_t*>();
            if (engine == NULL)
            {
                DH_set_method(dh, DH_get_default_method());
                DH_set_method(otherDH, DH_get_default_method());
            }
            if(!DH_generate_key(dh))
            {
                return vector<dh_async_arg_t*>();
            }
            if(!DH_generate_key(otherDH))
            {
                return vector<dh_async_arg_t*>();
            }

            dh_async_arg_t* arg = new dh_async_arg_t();
            arg->dh = dh;
            arg->other_pub_key = (BIGNUM *)GetPubKey(otherDH);
            arg->loop_cnt = 1;
            arg->inprogress_job = NULL;
            arg->wait_ctx = ASYNC_WAIT_CTX_new();
            arg->e = engine;
            arg->evp = 0;
            arg->dh_key = NULL;
            arg->dh_other_key = NULL;
            arg->out = (unsigned char*)OPENSSL_malloc(DH_size(dh));

            dh_array.push_back(arg);
        }
        return dh_array;
    }

    vector<dh_async_arg_t*> PrepareAsyncCompKeyEVPData(DHData dh_data, ENGINE *engine, int jobs)
    {
        vector<dh_async_arg_t*> dh_array;
        for (int i = 0; i < jobs; i++)
        {
            DH *dh = CreateDH(dh_data, NULL);
            if (dh == NULL)
                return vector<dh_async_arg_t*>();
            DH *otherDH = CreateDH(dh_data, NULL);
            if (otherDH == NULL)
            {
                DH_free(dh);
                dh = NULL;
                return vector<dh_async_arg_t*>();
            }
            DH_set_method(otherDH, DH_get_default_method());

            dh_async_evp_arg_t* arg = new dh_async_evp_arg_t();
            if (arg == NULL)
            {
                DH_free(dh);
                DH_free(otherDH);
                dh = NULL;
                otherDH = NULL;

                return vector<dh_async_arg_t*>();
            }
            arg->dh_hw = dh;
            arg->dh_sw = otherDH;
            arg->inprogress_job = NULL;
            arg->wait_ctx = ASYNC_WAIT_CTX_new();
            arg->e = engine;
            arg->out_hw = (unsigned char *)OPENSSL_malloc(DH_size(dh));
            if (arg->out_hw == NULL)
            {
                DH_free(dh);
                DH_free(otherDH);
                dh = NULL;
                otherDH = NULL;
                arg->dh_hw = NULL;
                arg->dh_sw = NULL;

                delete arg;
                arg = NULL;
                
                return vector<dh_async_arg_t*>();
            }
            arg->out_sw = (unsigned char *)OPENSSL_malloc(DH_size(otherDH));
            if (arg->out_sw == NULL)
            {
                DH_free(dh);
                DH_free(otherDH);
                dh = NULL;
                otherDH = NULL;
                arg->dh_hw = NULL;
                arg->dh_sw = NULL;

                OPENSSL_free(arg->out_hw);
                arg->out_hw = NULL;

                delete arg;
                arg = NULL;
                
                return vector<dh_async_arg_t*>();
            }
            memset(arg->out_hw, 0, DH_size(dh));
            memset(arg->out_sw, 0, DH_size(otherDH));
            dh_array.push_back(arg);
        }
        return dh_array;
    }

    void FreeAsyncArg(vector<dh_async_arg_t*> dh_array)
    {
        for (size_t i = 0; i < dh_array.size(); i++)
        {
            if (dh_array[i]->wait_ctx != NULL)
            {
                ASYNC_WAIT_CTX_free(dh_array[i]->wait_ctx);
            }
            if (dh_array[i]->dh != NULL)
            {
                DH_free(dh_array[i]->dh);
            }
            // if (dh_array[i].other_pub_key != NULL)
            // {
            //     BN_free(dh_array[i].other_pub_key);
            // }
            if (dh_array[i]->out != NULL)
            {
                OPENSSL_free(dh_array[i]->out);
            }
            EVP_PKEY_free(dh_array[i]->dh_key);
            EVP_PKEY_free(dh_array[i]->dh_other_key);
        }
    }

    void FreeAsyncEVPArg(vector<dh_async_arg_t*> dh_array)
    {
        for (size_t i = 0; i < dh_array.size(); i++)
        {
            dh_async_evp_arg_t* arg = (dh_async_evp_arg_t*)dh_array[i];
            DH_free(arg->dh_hw);
            DH_free(arg->dh_sw);
            ASYNC_WAIT_CTX_free(arg->wait_ctx);
            OPENSSL_free(arg->out_hw);
            OPENSSL_free(arg->out_sw);
        }
    }
};

ENGINE* DHTest::_engine = NULL;
map<int,DHData> DHTest::_primes = DHTest::PreparePrimes();

INSTANTIATE_DH_CASE(768);
INSTANTIATE_DH_CASE(1536);
INSTANTIATE_DH_CASE(2048);
INSTANTIATE_DH_CASE(1024);
INSTANTIATE_DH_CASE(3072);
INSTANTIATE_DH_CASE(4096);

INSTANTIATE_DSA_CASE(768);
// INSTANTIATE_DSA_CASE(1024);
// INSTANTIATE_DSA_CASE(1536);
// INSTANTIATE_DSA_CASE(2048);
// INSTANTIATE_DSA_CASE(3072);
// INSTANTIATE_DSA_CASE(4096);

TEST(DHTest,InvalidParameter)
{
    DH *dh = DH_new_method(NULL);
    BIGNUM *p = BN_new();
    ASSERT_TRUE(BN_set_word(p, 2));
    ASSERT_TRUE(DH_set0_pqg(dh, p, NULL, p));

    BIGNUM *pub_key = BN_new();
    ASSERT_TRUE(BN_set_word(pub_key, 10));
    unsigned char *buf1 = new unsigned char[DH_size(dh)];
    ASSERT_FALSE(compute_key_sync_dh(dh, pub_key, buf1));
}

// 调用API_DH接口，生成公钥私钥测试
TEST_P(DHTest,ComputeKey_DH)
{
    auto dh_data = GetParam();
    DH* dh = CreateDH(dh_data);
    ASSERT_TRUE(dh!=NULL);
    DH* otherDH = CreateDH(dh_data);
    ASSERT_TRUE(otherDH!=NULL);

    ASSERT_TRUE(generate_key_sync_dh(dh));
    ASSERT_TRUE(generate_key_sync_dh(otherDH));

    const BIGNUM* pub_key1 = GetPubKey(dh);
    const BIGNUM* pub_key2 = GetPubKey(otherDH);

    DH_set_method(otherDH, DH_get_default_method());

    auto dh_eng = ENGINE_get_DH(GetEngine());
    ASSERT_TRUE(dh_eng!=NULL);
    DH_set_method(dh, dh_eng);

    unsigned char *buf1 = new unsigned char[DH_size(dh)];
    memset(buf1, 0, DH_size(dh));
    int compute_len1 = compute_key_sync_dh(dh, pub_key2, buf1);
    ASSERT_GE(compute_len1, 0);
    unsigned char *buf2 = new unsigned char[DH_size(otherDH)];
    memset(buf2, 0, DH_size(dh));
    int compute_len2 = compute_key_sync_dh(otherDH, pub_key1, buf2);
    ASSERT_GE(compute_len2, 0);
    ASSERT_TRUE(compute_len1 == compute_len2);

    ASSERT_UCHAR_EQ(DH_size(dh), buf1, buf2);

    DH_free(dh);
    DH_free(otherDH);
    delete[] buf1;
    delete[] buf2;
}

// 生成公钥，软硬一致性
TEST_P(DHTest,GenerateKey_DH_HW_SW)
{
    auto dh_data = GetParam();
    auto priv_key = CreatePrivKey(dh_data.bits);
    DH* dh_hw = CreateDH(dh_data, priv_key);
    ASSERT_TRUE(dh_hw!=NULL);
    DH* dh_sw = CreateDH(dh_data, priv_key);
    ASSERT_TRUE(dh_sw!=NULL);
    DH_set_method(dh_sw, DH_get_default_method());

    ASSERT_TRUE(generate_key_sync_dh(dh_hw));
    ASSERT_TRUE(generate_key_sync_dh(dh_sw));


    const BIGNUM* pub_key1 = GetPubKey(dh_hw);
    const BIGNUM* pub_key2 = GetPubKey(dh_sw);

    ASSERT_EQ(BN_cmp(pub_key1,pub_key2),0);

    DH_free(dh_hw);
    DH_free(dh_sw);
}

// 生成共享私钥，软硬一致性
TEST_P(DHTest,ComputeKey_DH_HW_SW)
{
    auto dh_data = GetParam();

    for (int i = 0; i < 200; i++) {
        auto priv_key = CreatePrivKey(dh_data.bits);
        DH* dh = CreateDH(dh_data, priv_key);
        ASSERT_TRUE(dh!=NULL);
        DH_set_method(dh, ENGINE_get_DH(GetEngine()));
        auto priv_key2 = CreatePrivKey(dh_data.bits);
        DH* dh_other = CreateDH(dh_data, priv_key2);
        ASSERT_TRUE(dh_other!=NULL);
        DH_set_method(dh_other, DH_get_default_method());

        ASSERT_TRUE(generate_key_sync_dh(dh));
        ASSERT_TRUE(generate_key_sync_dh(dh_other));

        const BIGNUM* pub_key2 = GetPubKey(dh_other);

        unsigned char *buf_sw = new unsigned char[DH_size(dh_other)];
        ASSERT_TRUE(compute_key_sync_dh(dh, pub_key2, buf_sw));

        unsigned char *buf_hw = new unsigned char[DH_size(dh)];
        ASSERT_TRUE(compute_key_sync_dh(dh, pub_key2, buf_hw));

        ASSERT_UCHAR_EQ(DH_size(dh_other), buf_sw, buf_hw);

        DH_free(dh);
        DH_free(dh_other);
    }
}

// 生成公钥时不管私钥是否存在，最后得到的公钥都是一样的
TEST_P(DHTest, PriveKeyExistence_DH_GenerateKey)
{
    auto dh_data = GetParam();
    DH* dh_no_priv = CreateDH(dh_data);
    ASSERT_TRUE(dh_no_priv!=NULL);

    ASSERT_TRUE(generate_key_sync_dh(dh_no_priv));

    auto priv_key = DH_get0_priv_key(dh_no_priv);
    DH *dh_priv = CreateDH(dh_data, (BIGNUM*)priv_key);

    ASSERT_TRUE(generate_key_sync_dh(dh_priv));

    const BIGNUM *pub_key1 = GetPubKey(dh_no_priv);
    const BIGNUM *pub_key2 = GetPubKey(dh_priv);

    ASSERT_EQ(BN_cmp(pub_key1, pub_key2), 0);

    DH_free(dh_no_priv);
    DH_free(dh_priv);
}

// evp接口生成共享私钥一致性
TEST_P(DHTest,ComputeKey_EVP_HW_SW)
{
    auto dh_data = GetParam();
    DH* dh = CreateDH(dh_data);
    ASSERT_TRUE(dh!=NULL);
    DH* otherDH = CreateDH(dh_data);
    ASSERT_TRUE(otherDH!=NULL);

    auto dh_key = generate_key_sync_evp(GetEngine(), dh);
    ASSERT_TRUE(dh_key != NULL);
    auto dh_other_key = generate_key_sync_evp(NULL, otherDH);
    ASSERT_TRUE(dh_other_key != NULL);

    unsigned char *buf1 = new unsigned char[DH_size(dh)];
    ASSERT_GE(compute_key_sync_evp(dh_key, dh_other_key, GetEngine(), buf1),0);
    unsigned char *buf2 = new unsigned char[DH_size(otherDH)];
    ASSERT_GE(compute_key_sync_evp(dh_other_key, dh_key, NULL, buf2), 0);

    ASSERT_UCHAR_EQ(DH_size(dh), buf1, buf2);

    EVP_PKEY_free(dh_key);
    EVP_PKEY_free(dh_other_key);
    DH_free(dh);
    DH_free(otherDH);
    delete[] buf1;
    delete[] buf2;
}

TEST_P(DHTest,ComputeKey_EVP_HW_HW)
{
    auto dh_data = GetParam();
    DH* dh = CreateDH(dh_data);
    ASSERT_TRUE(dh!=NULL);
    DH* otherDH = CreateDH(dh_data);
    ASSERT_TRUE(otherDH!=NULL);

    auto dh_key = generate_key_sync_evp(GetEngine(), dh);
    ASSERT_TRUE(dh_key != NULL);
    auto dh_other_key = generate_key_sync_evp(GetEngine(), otherDH);
    ASSERT_TRUE(dh_other_key != NULL);

    unsigned char *buf1 = new unsigned char[DH_size(dh)];
    ASSERT_GE(compute_key_sync_evp(dh_key, dh_other_key, GetEngine(), buf1),0);
    unsigned char *buf2 = new unsigned char[DH_size(otherDH)];
    ASSERT_GE(compute_key_sync_evp(dh_other_key, dh_key, GetEngine(), buf2), 0);

    ASSERT_UCHAR_EQ(DH_size(dh), buf1, buf2);

    EVP_PKEY_free(dh_key);
    EVP_PKEY_free(dh_other_key);
    DH_free(dh);
    DH_free(otherDH);
    delete[] buf1;
    delete[] buf2;
}

// 异步生成公钥
TEST_P(DHTest,GenerateKeyAsync)
{
    int jobs = ASYNC_JOBS;
    auto dh_data = GetParam();
    auto priv_key = CreatePrivKey(dh_data.bits);
    auto dh_array_hw = PrepareAsyncData(dh_data, GetEngine(),jobs, priv_key);
    auto dh_array_sw = PrepareAsyncData(dh_data, NULL,jobs, priv_key);
    ASSERT_TRUE(!dh_array_hw.empty());
    ASSERT_TRUE(!dh_array_sw.empty());

    if (!run_async_jobs(dh_array_hw, jobs, run_generate_key))
    {
        FAIL();
    }
    if (!run_async_jobs(dh_array_sw, jobs, run_generate_key))
    {
        FAIL();
    }

    for (int i = 0; i < jobs; i++)
    {
        auto pub1 = GetPubKey(dh_array_hw[i]->dh);
        auto pub2 = GetPubKey(dh_array_sw[i]->dh);
        ASSERT_EQ(BN_cmp(pub1,pub2),0);
    }

    FreeAsyncArg(dh_array_hw);
    FreeAsyncArg(dh_array_sw);
    BN_free(priv_key);
}

// 异步生成共享私钥
TEST_P(DHTest,ComputeKeyAsync)
{
    int jobs = ASYNC_JOBS;
    auto dh_data = GetParam();
    auto priv_key1 = CreatePrivKey(dh_data.bits);
    auto priv_key2 = CreatePrivKey(dh_data.bits);
    auto dh_array_hw = PrepareAsyncCompKeyData(dh_data, GetEngine(),jobs, priv_key1,priv_key2);
    auto dh_array_sw = PrepareAsyncCompKeyData(dh_data, NULL,jobs, priv_key1,priv_key2);
    ASSERT_TRUE(!dh_array_hw.empty());
    ASSERT_TRUE(!dh_array_sw.empty());

    if (!run_async_jobs(dh_array_hw, jobs, run_compute_key))
    {
        FAIL();
    }
    if (!run_async_jobs(dh_array_sw, jobs, run_compute_key))
    {
        FAIL();
    }

    for (int i = 0; i < jobs; i++)
    {
        ASSERT_UCHAR_EQ(DH_size(dh_array_hw[i]->dh), dh_array_hw[i]->out, dh_array_sw[i]->out);
    }

    FreeAsyncArg(dh_array_hw);
    FreeAsyncArg(dh_array_sw);
    BN_free(priv_key1);
    BN_free(priv_key2);
}

TEST_P(DHTest,EVPAsync)
{
    int jobs = ASYNC_JOBS;
    auto dh_data = GetParam();
    auto dh_array = PrepareAsyncCompKeyEVPData(dh_data, GetEngine(),jobs);
    ASSERT_TRUE(!dh_array.empty());

    if (!run_async_jobs(dh_array, jobs, run_evp))
    {
        FAIL();
    }

    for (int i = 0; i < jobs; i++)
    {
        dh_async_evp_arg_t* arg = (dh_async_evp_arg_t*)dh_array[i];
        ASSERT_UCHAR_EQ(DH_size(arg->dh_hw), arg->out_hw, arg->out_sw);
    }

    FreeAsyncEVPArg(dh_array);
}

// 异步开关测试, generate_key
TEST_P(DHTest,AsyncConfigTest_GenerateKey)
{
    int jobs = 1;
    auto dh_data = GetParam();
    auto priv_key = CreatePrivKey(dh_data.bits);
    auto dh_array = PrepareAsyncData(dh_data, GetEngine(),jobs, priv_key);
    ASSERT_TRUE(!dh_array.empty());

    ENGINE_ctrl_cmd_string(GetEngine(), "KAE_CMD_ENABLE_ASYNC", "0", 0); 
    if (!run_async_jobs(dh_array, jobs, run_generate_key))
    {
        FAIL();
    }
    auto pub_off = BN_dup(GetPubKey(dh_array[0]->dh));

    ENGINE_ctrl_cmd_string(GetEngine(), "KAE_CMD_ENABLE_ASYNC", "1", 0); 
    if (!run_async_jobs(dh_array, jobs, run_generate_key))
    {
        FAIL();
    }
    auto pub_on = GetPubKey(dh_array[0]->dh);

    ASSERT_EQ(BN_cmp(pub_on, pub_off), 0);
    FreeAsyncArg(dh_array);
}

TEST_P(DHTest,AsyncConfigTest_ComputeKey)
{
    int jobs = 1;
    auto dh_data = GetParam();
    auto priv_key1 = CreatePrivKey(dh_data.bits);
    auto priv_key2 = CreatePrivKey(dh_data.bits);
    auto dh_array = PrepareAsyncCompKeyData(dh_data, GetEngine(),jobs, priv_key1,priv_key2);
    ASSERT_TRUE(!dh_array.empty());

    ENGINE_ctrl_cmd_string(GetEngine(), "KAE_CMD_ENABLE_ASYNC", "0", 0); 
    if (!run_async_jobs(dh_array, jobs, run_compute_key))
    {
        FAIL();
    }
    unsigned char* out_off = (unsigned char*)OPENSSL_malloc(DH_size(dh_array[0]->dh));
    memcpy(out_off, dh_array[0]->out, DH_size(dh_array[0]->dh));

    ENGINE_ctrl_cmd_string(GetEngine(), "KAE_CMD_ENABLE_ASYNC", "1", 0); 
    if (!run_async_jobs(dh_array, jobs, run_compute_key))
    {
        FAIL();
    }
    ASSERT_UCHAR_EQ(DH_size(dh_array[0]->dh), out_off, dh_array[0]->out);

    FreeAsyncArg(dh_array);
    BN_free(priv_key1);
    BN_free(priv_key2);
}

TEST_P(DHTest,GenerateKeyThread)
{
    int jobs = ASYNC_JOBS;
    auto dh_data = GetParam();
    auto priv_key = CreatePrivKey(dh_data.bits);
    auto dh_array_hw = PrepareAsyncData(dh_data, GetEngine(),jobs, priv_key);
    run_threads(dh_array_hw, run_generate_key_thread);

    auto dh_array_sw = PrepareAsyncData(dh_data, NULL,jobs, priv_key);
    for(size_t i = 0;i< dh_array_sw.size(); ++i)
    {
        ASSERT_TRUE(generate_key_sync_dh(dh_array_sw[i]->dh));
        auto pub1 = GetPubKey(dh_array_hw[i]->dh);
        auto pub2 = GetPubKey(dh_array_sw[i]->dh);
        ASSERT_EQ(BN_cmp(pub1,pub2),0);
    }

    FreeAsyncArg(dh_array_hw);
    FreeAsyncArg(dh_array_sw);
}

TEST_P(DHTest,ComputeKeyThread)
{
    // int jobs = ASYNC_JOBS;
    // auto dh_data = GetParam();
    // auto priv_key1 = CreatePrivKey(dh_data.bits);
    // auto priv_key2 = CreatePrivKey(dh_data.bits);
    // auto dh_array_hw = PrepareAsyncCompKeyData(dh_data, GetEngine(), jobs, priv_key1, priv_key2);
    // auto dh_array_sw = PrepareAsyncCompKeyData(dh_data, NULL, jobs, priv_key1, priv_key2);
    // ASSERT_TRUE(!dh_array_hw.empty());
    // ASSERT_TRUE(!dh_array_sw.empty());

    // run_threads(dh_array_hw, run_compute_key_thread);

    // for (size_t i = 0; i < dh_array_sw.size(); ++i)
    // {
    //     ASSERT_TRUE(compute_key_sync_dh(dh_array_sw[i]->dh, dh_array_sw[i]->other_pub_key, dh_array_sw[i]->out));
    //     ASSERT_UCHAR_EQ(DH_size(dh_array_sw[i]->dh), dh_array_sw[i]->out, dh_array_hw[i]->out);
    // }
    
    // FreeAsyncArg(dh_array_hw);
    // FreeAsyncArg(dh_array_sw);
}

TEST_P(DHTest,QueueReuse)
{
    int jobs = 10;
    auto dh_data = GetParam();
    auto priv_key = CreatePrivKey(dh_data.bits);
    auto dh_array = PrepareAsyncData(dh_data, GetEngine(),jobs, priv_key);

    //int init_queues = get_hpre_queue_instances();
    run_threads(dh_array, run_generate_key_thread);
    //int now_queues = get_hpre_queue_instances();

    sleep(3);

    run_threads(dh_array, run_generate_key_thread);
}

TEST_P(DHTest, QueueReuse_EVP)
{
    int jobs = 10;
    auto dh_data = GetParam();
    auto dh_array = PrepareAsyncCompKeyEVPData(dh_data, GetEngine(), jobs);
    ASSERT_TRUE(!dh_array.empty());

    run_threads(dh_array, run_evp_thread);

    sleep(3);

    run_threads(dh_array, run_evp_thread);
}

TEST_P(DHTest,QueueRelease)
{
    int jobs = 10;
    auto dh_data = GetParam();
    auto priv_key = CreatePrivKey(dh_data.bits);
    auto dh_array = PrepareAsyncData(dh_data, GetEngine(),jobs, priv_key);

    //int init_queues = get_hpre_queue_instances();
    run_threads(dh_array, run_generate_key_thread);
    //int now_queues = get_hpre_queue_instances();

    sleep(8);

    run_threads(dh_array, run_generate_key_thread);
}

TEST_P(DHTest, QueueRelease_EVP)
{
    int jobs = 10;
    auto dh_data = GetParam();
    auto dh_array = PrepareAsyncCompKeyEVPData(dh_data, GetEngine(), jobs);
    ASSERT_TRUE(!dh_array.empty());

    run_threads(dh_array, run_evp_thread);

    sleep(8);

    run_threads(dh_array, run_evp_thread);
}

int run_async_jobs(vector<dh_async_arg_t*> dh_array, int jobs, int (*loop_function)(void *))
{
    int job_op_count = 0;
    int num_inprogress = 0;
    size_t num_job_fds = 0;
    OSSL_ASYNC_FD job_fd = 0;
    int ret = 0;
    for (int i = 0; i < jobs; i++)
    {
        dh_async_arg_t* looparg_item = dh_array[i];
        ret = ASYNC_start_job(&dh_array[i]->inprogress_job, dh_array[i]->wait_ctx,
                              &job_op_count, loop_function,
                              (void *)looparg_item, sizeof(dh_async_evp_arg_t));
        switch (ret)
        {
        case ASYNC_PAUSE:
            ++num_inprogress;
            break;
        case ASYNC_FINISH:
            if (job_op_count == -1)
            {
                return 0;
            }
            break;
        case ASYNC_NO_JOBS:
        case ASYNC_ERR:
            return 0;
        }
    }

    while (num_inprogress > 0)
    {
        int select_result = 0;
        OSSL_ASYNC_FD max_fd = 0;
        fd_set waitfdset;

        FD_ZERO(&waitfdset);

        for (int i = 0; i < jobs && num_inprogress > 0; i++)
        {
            if (dh_array[i]->inprogress_job == NULL)
                continue;

            if (!ASYNC_WAIT_CTX_get_all_fds(dh_array[i]->wait_ctx, NULL, &num_job_fds) || num_job_fds > 1)
            {
                return 0;
            }
            ASYNC_WAIT_CTX_get_all_fds(dh_array[i]->wait_ctx, &job_fd,
                                       &num_job_fds);
            FD_SET(job_fd, &waitfdset);
            if (job_fd > max_fd)
                max_fd = job_fd;
        }

        if (max_fd >= (OSSL_ASYNC_FD)FD_SETSIZE)
        {
            return 0;
        }

        select_result = select(max_fd + 1, &waitfdset, NULL, NULL, NULL);
        if (select_result == -1 && errno == EINTR)
            continue;

        if (select_result == -1)
        {
            return 0;
        }

        if (select_result == 0)
            continue;

        for (int i = 0; i < jobs; i++)
        {
            if (dh_array[i]->inprogress_job == NULL)
                continue;

            if (!ASYNC_WAIT_CTX_get_all_fds(dh_array[i]->wait_ctx, NULL, &num_job_fds) || num_job_fds > 1)
            {
                return 0;
            }
            ASYNC_WAIT_CTX_get_all_fds(dh_array[i]->wait_ctx, &job_fd,
                                       &num_job_fds);

            if (num_job_fds == 1 && !FD_ISSET(job_fd, &waitfdset))
                continue;
            ret = ASYNC_start_job(&dh_array[i]->inprogress_job,
                                  dh_array[i]->wait_ctx, &job_op_count,
                                  loop_function, (void *)(dh_array[i]),
                                  sizeof(dh_async_evp_arg_t));
            switch (ret)
            {
            case ASYNC_PAUSE:
                break;
            case ASYNC_FINISH:
                if (job_op_count == -1)
                {
                    return 0;
                }
                --num_inprogress;
                dh_array[i]->inprogress_job = NULL;
                break;
            case ASYNC_NO_JOBS:
            case ASYNC_ERR:
                --num_inprogress;
                dh_array[i]->inprogress_job = NULL;
                return 0;
            }
        }
    }

    return 1;
}

int run_generate_key(void *arg)
{
    dh_async_arg_t *dh_arg = (dh_async_arg_t *)arg;
    if(dh_arg->evp)
    {
        if(!generate_key_sync_evp(dh_arg->e,dh_arg->dh))
        {
            return 0;
        }
    }
    else
    {
        if(!generate_key_sync_dh(dh_arg->dh))
        {
            return 0;
        }
    }

    return 1;
}

EVP_PKEY* generate_key_sync_evp(ENGINE *e, DH* dh)
{
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_set1_DH(pkey, dh);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, e);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY *outpkey = NULL;

    if (EVP_PKEY_keygen(ctx, &outpkey) != 1)
        return NULL;

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return outpkey;
}

int generate_key_sync_dh(DH *dh)
{
    if (DH_generate_key(dh) != 1)
        return 0;
    return 1;
}

int run_compute_key(void *arg)
{
    dh_async_arg_t *dh_arg = (dh_async_arg_t *)arg;
    if(dh_arg->evp)
    {
        if(!compute_key_sync_evp(dh_arg->dh_key, dh_arg->dh_other_key, dh_arg->e, dh_arg->out))
        {
            return 0;
        }
    }
    else
    {
        if(!compute_key_sync_dh(dh_arg->dh,dh_arg->other_pub_key,dh_arg->out))
        {
            return 0;
        }
    }

    return 1;
}

int compute_key_sync_dh(DH *dh, const BIGNUM *other_pub_key, unsigned char *out)
{
    int len = DH_compute_key(out, other_pub_key, dh);
    if (len <= 0)
    {
        return 0;
    }

    return len;
}

int compute_key_sync_evp(EVP_PKEY *dh, EVP_PKEY *otherDH, ENGINE *e, unsigned char *out)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(dh, e);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx,otherDH);

    size_t keylen = 0;
    if (EVP_PKEY_derive(ctx, out, &keylen) == 0)
        return 0;

    EVP_PKEY_CTX_free(ctx);

    return 1;
}

int run_evp(void *arg)
{
    dh_async_evp_arg_t *dh_arg = (dh_async_evp_arg_t*)arg;
    return generate_compute_key_evp(dh_arg->e,dh_arg->dh_hw,dh_arg->dh_sw,dh_arg->out_hw,dh_arg->out_sw);
}

int generate_compute_key_evp(ENGINE *e, DH* dh_hw, DH* dh_sw,  unsigned char *out_hw,  unsigned char *out_sw)
{
    EVP_PKEY *pkey_hw = generate_key_sync_evp(e, dh_hw);
    EVP_PKEY *pkey_sw = generate_key_sync_evp(e, dh_sw);
    if(pkey_hw == NULL) return 0;
    if(pkey_sw == NULL) return 0;

    if(!compute_key_sync_evp(pkey_hw,pkey_sw,e,out_hw))
    {
        return 0;
    }
    if(!compute_key_sync_evp(pkey_sw,pkey_hw,e,out_sw))
    {
        return 0;
    }

    return 1;
}

void* run_generate_key_thread(void *arg)
{
    (void)run_generate_key(arg);
    return NULL;
}

void* run_compute_key_thread(void *arg)
{
    (void)run_compute_key(arg);
    return NULL;
}

void* run_evp_thread(void *arg)
{
    (void)run_evp(arg);
    return NULL;
}

void run_threads(vector<dh_async_arg_t*> dh_array, void *(*start_routine) (void *))
{
    pthread_t *tids = new pthread_t[dh_array.size()];

    for (size_t i = 0; i < dh_array.size(); ++i) {
        pthread_create(&tids[i], NULL, start_routine, dh_array[i]);
    }

    for (size_t i = 0; i < dh_array.size(); ++i) {
        pthread_join(tids[i], NULL);
    }

    delete[] tids;
}

int get_hpre_queue_instances() 
{
    FILE *pp = popen("cat /sys/class/uacce/hisi_hpre-*/attrs/available_instances", "r");
    if (!pp)
    {
        return -1;
    }

    int sum = 0;
    char tmp[1024]; 
    while (fgets(tmp, sizeof(tmp), pp) != NULL) {
        if (tmp[strlen(tmp) - 1] == '\n') {
            tmp[strlen(tmp) - 1] = '\0'; 
        }
        sum += atoi(tmp);
    }
    pclose(pp);
    return sum;
}
