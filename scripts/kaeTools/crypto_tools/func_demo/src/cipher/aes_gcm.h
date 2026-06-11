/*
 * @Date: 2024-07-31 14:21:17
 * @FilePath: \KAE_kae2\KAE\KAEOpensslEngine\test\func_demo\src\cipher\aes_gcm.h
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */

#ifndef AES_GCM_H
#define AES_GCM_H

#ifdef __cplusplus  
extern "C" {  
#endif  

int kae_gcm_encrypt(ENGINE *engine, unsigned char *plaintext, int plaintext_len,
                    unsigned char *outbuf, int *outlen,
                    unsigned char *outtag);
int kae_gcm_decrypt(ENGINE *engine, unsigned char *ciphertext, int ciphertext_len,
                unsigned char *tag,
                unsigned char *outbuf, int *outlen);

#ifdef __cplusplus  
}  
#endif  
#endif

