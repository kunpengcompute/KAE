#ifndef DIGEST_H
#define DIGEST_H

#ifdef __cplusplus  
extern "C" {  
#endif  

int demonstrate_digest(const EVP_MD *message_digest, char * msg1, char * msg2, unsigned char *digest_value,  unsigned int *digest_length);

#ifdef __cplusplus  
}  
#endif  
#endif