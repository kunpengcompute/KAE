/*
 * An example that uses EVP_PKEY_encrypt and EVP_PKEY_decrypt methods
 * to encrypt and decrypt data using an RSA keypair.
 * RSA encryption produces different encrypted output each time it is run,
 * hence this is not a known answer test.
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/evp.h>
// #include <openssl/decoder.h>
// #include <openssl/core_names.h>
#include "rsa_encrypt.h"

/* Input data to encrypt */
static const unsigned char rsa_msg[] =
    "To be, or not to be, that is the question,\n"
    "Whether tis nobler in the minde to suffer\n"
    "The slings and arrowes of outragious fortune,\n"
    "Or to take Armes again in a sea of troubles";

/*
 * The length of the input data that can be encrypted is limited by the
 * RSA key length minus some additional bytes that depends on the padding mode.
 *
 */


void rsa_key_copy_all(RSA *rsa_src, RSA *rsa_dst)  
{  
    // 检查输入参数的有效性  
    if (rsa_src == NULL || rsa_dst == NULL) {  
        return; // 或者抛出错误  
    }  

    // 获取原始 RSA 的关键部分  
    const BIGNUM *n_in_st = RSA_get0_n(rsa_src);  
    const BIGNUM *e_in_st = RSA_get0_e(rsa_src);  
    const BIGNUM *d_in_st = RSA_get0_d(rsa_src);  
    const BIGNUM *p_in_st = NULL;  
    const BIGNUM *q_in_st = NULL;  
    const BIGNUM *dmp1_in_st = NULL;  
    const BIGNUM *dmq1_in_st = NULL;  
    const BIGNUM *iqmp_in_st = NULL;  

    // 复制 BIGNUM  
    BIGNUM *n_copy = BN_new();  
    BIGNUM *e_copy = BN_new();  
    BIGNUM *d_copy = d_in_st ? BN_new() : NULL;  
    BIGNUM *p_copy = NULL;  
    BIGNUM *q_copy = NULL;  
    BIGNUM *dmp1_copy = NULL;  
    BIGNUM *dmq1_copy = NULL;  
    BIGNUM *iqmp_copy = NULL;  

    if (n_copy == NULL || e_copy == NULL || (d_in_st && d_copy == NULL)) {  
        // 处理内存分配错误  
        BN_free(n_copy);  
        BN_free(e_copy);  
        BN_free(d_copy);  
        return; // 或者抛出错误  
    }  

    // 进行复制  
    BN_copy(n_copy, n_in_st);  
    BN_copy(e_copy, e_in_st);  
    if (d_in_st) {  
        BN_copy(d_copy, d_in_st);  
    }  

    // 获取并复制 p, q, dmp1, dmq1, iqmp  
    RSA_get0_factors(rsa_src, &p_in_st, &q_in_st);  
    RSA_get0_crt_params(rsa_src, &dmp1_in_st, &dmq1_in_st, &iqmp_in_st);  
    
    if (p_in_st) {  
        p_copy = BN_new();  
        if (p_copy == NULL) {  
            // 处理内存分配错误  
            BN_free(n_copy);  
            BN_free(e_copy);  
            BN_free(d_copy);  
            return; // 或者抛出错误  
        }  
        BN_copy(p_copy, p_in_st);  
    }  

    if (q_in_st) {  
        q_copy = BN_new();  
        if (q_copy == NULL) {  
            // 处理内存分配错误  
            BN_free(n_copy);  
            BN_free(e_copy);  
            BN_free(d_copy);  
            BN_free(p_copy);  
            return; // 或者抛出错误  
        }  
        BN_copy(q_copy, q_in_st);  
    }  

    if (dmp1_in_st) {  
        dmp1_copy = BN_new();  
        if (dmp1_copy == NULL) {  
            // 处理内存分配错误  
            BN_free(n_copy);  
            BN_free(e_copy);  
            BN_free(d_copy);  
            BN_free(p_copy);  
            BN_free(q_copy);  
            return; // 或者抛出错误  
        }  
        BN_copy(dmp1_copy, dmp1_in_st);  
    }  

    if (dmq1_in_st) {  
        dmq1_copy = BN_new();  
        if (dmq1_copy == NULL) {  
            // 处理内存分配错误  
            BN_free(n_copy);  
            BN_free(e_copy);  
            BN_free(d_copy);  
            BN_free(p_copy);  
            BN_free(q_copy);  
            BN_free(dmp1_copy);  
            return; // 或者抛出错误  
        }  
        BN_copy(dmq1_copy, dmq1_in_st);  
    }  

    if (iqmp_in_st) {  
        iqmp_copy = BN_new();  
        if (iqmp_copy == NULL) {  
            // 处理内存分配错误  
            BN_free(n_copy);  
            BN_free(e_copy);  
            BN_free(d_copy);  
            BN_free(p_copy);  
            BN_free(q_copy);  
            BN_free(dmp1_copy);  
            BN_free(dmq1_copy);  
            return; // 或者抛出错误  
        }  
        BN_copy(iqmp_copy, iqmp_in_st);  
    }  

    // 将复制的 BIGNUM 赋值给目标 RSA  
    RSA_set0_key(rsa_dst, n_copy, e_copy, d_copy);  
    RSA_set0_factors(rsa_dst, p_copy, q_copy);  
    RSA_set0_crt_params(rsa_dst, dmp1_copy, dmq1_copy, iqmp_copy);  

    // 释放引用内存  
    // RSA_set0_key 和 RSA_set0_factors, RSA_set0_crt_params 接管了内存管理，所以不需要释放它们  

    return;  
} 

void rsa_key_copy_NED(RSA *rsa_src, RSA *rsa_dst)  
{  
    // 检查输入参数的有效性  
    if (rsa_src == NULL || rsa_dst == NULL) {  
        return; // 或者抛出错误  
    }  

    // 获取原始 RSA 的关键部分  
    const BIGNUM *n_in_st = RSA_get0_n(rsa_src);  
    const BIGNUM *e_in_st = RSA_get0_e(rsa_src);  
    const BIGNUM *d_in_st = RSA_get0_d(rsa_src);  

    // 复制 BIGNUM  
    BIGNUM *n_copy = BN_new();  
    BIGNUM *e_copy = BN_new();  
    BIGNUM *d_copy = d_in_st ? BN_new() : NULL;  

    if (n_copy == NULL || e_copy == NULL || (d_in_st && d_copy == NULL)) {  
        // 处理内存分配错误  
        BN_free(n_copy);  
        BN_free(e_copy);  
        BN_free(d_copy);  
        return; // 或者抛出错误  
    }  

    // 进行复制  
    BN_copy(n_copy, n_in_st);  
    BN_copy(e_copy, e_in_st);  
    if (d_in_st) {  
        BN_copy(d_copy, d_in_st);  
    }  

    // 将复制的 BIGNUM 赋值给目标 RSA  
    RSA_set0_key(rsa_dst, n_copy, e_copy, d_copy);  

    // 释放引用内存  
    // RSA_set0_key 接管了 n_copy, e_copy 和 d_copy 的内存管理，所以不需要释放它们  
    // 但我们不能在这里释放 d_copy，因为如果 d_in_st 是 NULL，那么 d_copy 不会被使用  

    return;  
}  
