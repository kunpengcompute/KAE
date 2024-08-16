#ifndef SM4_CBC_H
#define SM4_CBC_H

#ifdef __cplusplus  
extern "C" {  
#endif  

int kae_sm4_cbc_encrypt(ENGINE *engine, const unsigned char *plantext, int plen, unsigned char *outbuf, int * outlen);
int kae_sm4_cbc_decrypt(ENGINE *engine, const unsigned char *ciphertext, int clen, unsigned char *outbuf, int * outlen);

#ifdef __cplusplus  
}  
#endif  
#endif