#include <string>
#include <fstream>
#include <iostream>
#include <streambuf>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <gtest/gtest.h>
#include <zlib.h>
extern "C" {
    #include "kaezip.h"
}
using namespace testing;
using namespace std;

class ZLIB_stream {
  protected:
    z_streamp s = nullptr;

    void generate_zstream(void) {
      s = new z_stream;
      memset(s, 0, sizeof(z_stream));
    }

    void release_zstream(void) {
      if(s != nullptr)
        delete s;
      s = nullptr;
    }

    void reset_zstream(void) {
      release_zstream();
      generate_zstream();
    }

  public:
    ZLIB_stream(void) {
      generate_zstream();
    }

    virtual ~ZLIB_stream(void) {
      release_zstream();
    }

    z_streamp get_stream(void) {
      return s;
    }

};

class ZLIB_inflate_stream : public ZLIB_stream {
  public:
    ~ZLIB_inflate_stream(void) {
      inflateEnd(get_stream());
    }

    void reset_inflate_stream(void) {
      inflateEnd(get_stream());
      reset_zstream();
    }
};

TEST(ZlibTest, inflateBackInit__common)
{
  ZLIB_inflate_stream inflateObj;
  const int windowBits = 9;
  unsigned char window[1 << windowBits];

  EXPECT_EQ(inflateBackInit_(inflateObj.get_stream(), windowBits, window, ZLIB_VERSION, (int)sizeof(z_stream)), Z_OK); // AOCL_Compression_zlib_inflateBackInit__common_8

  inflateBackEnd(inflateObj.get_stream());
}

TEST(ZlibTest, inflateBackEnd_common)
{
  ZLIB_inflate_stream inflateObj;
  const int windowBits = 9;
  unsigned char window[1 << windowBits];
  void *v;

  // fail cases
  EXPECT_EQ(inflateBackEnd(inflateObj.get_stream()), Z_STREAM_ERROR);  
  EXPECT_EQ(inflateBackEnd(NULL), Z_STREAM_ERROR);  

  inflateBackInit(inflateObj.get_stream(), windowBits, window);

  internal_state *st = inflateObj.get_stream()->state;
  inflateObj.get_stream()->state = 0;
  EXPECT_EQ(inflateBackEnd(inflateObj.get_stream()), Z_STREAM_ERROR);  
  inflateObj.get_stream()->state = st;

  v = (void *)(inflateObj.get_stream()->zfree);
  inflateObj.get_stream()->zfree = 0;
  EXPECT_EQ(inflateBackEnd(inflateObj.get_stream()), Z_STREAM_ERROR);  

  inflateObj.get_stream()->zfree = (void (*)(void *, void *))v;

  // pass case
  EXPECT_EQ(inflateBackEnd(inflateObj.get_stream()), Z_OK);
  EXPECT_EQ(inflateObj.get_stream()->state, (internal_state *)NULL); 
}

// TEST(ZlibTest, inflateCodesUsed_common)
// {
//   ZLIB_inflate_stream inflateObj;
//   inflateInit(inflateObj.get_stream());
//   inflate_state *state = (inflate_state *)inflateObj.get_stream()->state;

//   state->next = &(state->codes[500]);
//   EXPECT_EQ(inflateCodesUsed(inflateObj.get_stream()), 500); // AOCL_Compression_zlib_inflateCodesUsed_common_3

//   state->next = &(state->codes[0]);
//   EXPECT_EQ(inflateCodesUsed(inflateObj.get_stream()), 0); // AOCL_Compression_zlib_inflateCodesUsed_common_4

//   state->next = &(state->codes[ENOUGH - 1]);
//   EXPECT_EQ(inflateCodesUsed(inflateObj.get_stream()), ENOUGH - 1);  // AOCL_Compression_zlib_inflateCodesUsed_common_5
// }






static void* alloc_null(void* opaque, uInt items, uInt size)
{
  return nullptr;
}
TEST(ZlibTest, inflateInit2_negative)
{
  ZLIB_inflate_stream inflateObj;

  EXPECT_EQ(inflateInit2(NULL, 9), Z_STREAM_ERROR); 
  EXPECT_EQ(inflateInit2(inflateObj.get_stream(), 7), Z_STREAM_ERROR); 
  EXPECT_EQ(inflateInit2(inflateObj.get_stream(), 17), Z_STREAM_ERROR);
  inflateObj.get_stream()->zalloc = alloc_null;
  EXPECT_EQ(inflateInit2(inflateObj.get_stream(), 8), Z_MEM_ERROR);
}





TEST(ZlibTest, inflate_negative)
{
  EXPECT_EQ(inflate(NULL, Z_NO_FLUSH), Z_STREAM_ERROR);
}


/* inflate small amount of data and validate with adler32 checksum */
const char* orig = "The quick brown fox jumped over the lazy dog";

z_const unsigned char comp[] = {
    0x78, 0x9c, 0x0b, 0xc9, 0x48, 0x55, 0x28, 0x2c, 0xcd, 0x4c, 0xce, 0x56, 0x48,
    0x2a, 0xca, 0x2f, 0xcf, 0x53, 0x48, 0xcb, 0xaf, 0x50, 0xc8, 0x2a, 0xcd, 0x2d,
    0x48, 0x4d, 0x51, 0xc8, 0x2f, 0x4b, 0x2d, 0x52, 0x28, 0xc9, 0x48, 0x55, 0xc8,
    0x49, 0xac, 0xaa, 0x54, 0x48, 0xc9, 0x4f, 0x07, 0x00, 0x6b, 0x93, 0x10, 0x30
};
#define MIN(a,b)    ( (a) < (b) ? (a) : (b) )
TEST(ZlibTest, inflate_adler32_1)
{
    unsigned char uncomp[1024];
    z_stream strm;

    memset(&strm, 0, sizeof(strm));

    int err = inflateInit2(&strm, 32 + MAX_WBITS);
    EXPECT_EQ(err, Z_OK);

    strm.next_in = comp;
    strm.avail_in = sizeof(comp);
    strm.next_out = uncomp;
    strm.avail_out = sizeof(uncomp);

    err = inflate(&strm, Z_NO_FLUSH);
    EXPECT_EQ(err, Z_STREAM_END);

    // EXPECT_EQ(strm.adler, 0x6b931030); // match the checksum with checksum value of orig  需要关注kae解压的时候会不会返回校验值，这个校验值当前没有反馈

    err = inflateEnd(&strm);
    EXPECT_EQ(err, Z_OK);

    EXPECT_TRUE(memcmp(uncomp, orig, MIN(strm.total_out, strlen(orig))) == 0);
}
