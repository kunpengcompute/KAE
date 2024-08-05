

#ifndef DEMO_UTILS_H
#define DEMO_UTILS_H
#include <stdio.h>

#ifdef __cplusplus  
extern "C" {  
#endif  

int rand_buffer(unsigned char *buf, unsigned long len);
void handleErrors(void);

#ifdef __cplusplus  
}  
#endif  
#endif


