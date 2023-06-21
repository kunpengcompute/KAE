#ifndef KAEZIP_INIT_H
#define KAEZIP_INIT_H

int kz_deflate_init(z_streamp strm, int level, int windowbits);
int kz_deflate_reset(z_streamp strm);
int kz_deflate_end(z_streamp strm);

int kz_inflate_init(z_streamp strm, int windowbits);
int kz_inflate_reset(z_streamp strm);
int kz_inflate_end(z_streamp strm);

#endif