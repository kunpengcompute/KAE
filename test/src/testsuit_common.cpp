#include "testsuit_common.h"

static int cipher_encrypt_outlen[100] = {0};

void init_openssl()
{
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
}

void operate_config(std::string operate)
{
    const char *configfile = "/var/log/kae.cnf";
    const char *logfile = "/var/log/kae.log";
    if (operate == "create"){
        if (access(configfile,0) != 0){
            FILE *fp = fopen(configfile, "w+");
            fprintf(fp, "[LogSection]\n");
            fprintf(fp,"debug_level=debug\n");
            fclose(fp);
        }
        if (access(logfile,0) == 0){
            FILE *fp = fopen(logfile,"w");
            fclose(fp);
        }
    }else if (operate == "remove"){
        if (access(configfile,0) == 0){
            remove(configfile);
        }
        if (access(logfile,0) == 0){
            remove(logfile);
        }
    }else
        printf("No legal input method");
}

int GetExpectedResults(char *cmpstr, int size)
{
    const char *logfile = "/var/log/kae.log";
    if (access(logfile,0) != 0){
        printf("the logfile is not exist!");
        return -1;
    }
    FILE *fp = fopen(logfile,"rb");

    int i = 0, end;
    char *part = (char *)malloc(size * sizeof(char));
    fseek(fp, 0L, SEEK_END);
    end = ftell(fp) - size + 2;

    while(i < end){
        int j = 0;
        fseek(fp, i++, SEEK_SET);
        fgets(part, size, fp);
        while(*part){
            if(*cmpstr == *part){
                j++;
                cmpstr++;
                part++;
                continue;
            }
            break;
        }
        if(j == size - 1)
            return 0;
        else {
            cmpstr -= j;
            part -= j;
        }
    }
    fclose(fp);
    free(part);
    return -1;
}

int rand_buffer(unsigned char *buf, unsigned long len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        printf("can't open /dev/urandom\n");
        return -1;
    }
    if (read(fd, buf, len) < 0) {
        printf("[%s][%d] read from /dev/urandom failed\n", __FUNCTION__, __LINE__);
    }
    close(fd);

    return 0;
}

int do_md(const EVP_MD *md, int buf_len, uint8_t *buf_in, uint8_t *buf_out, ENGINE *e, int update_cnt)
{
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    unsigned int out_len;

    if (!EVP_DigestInit_ex(md_ctx, md, e)) {
        printf("EVP_DigestInit failed.\n");
        return -1;
    }

    int i = 0;
    for (i = 0; i < update_cnt; i++) {
        if (!EVP_DigestUpdate(md_ctx, buf_in, buf_len)) {
            printf("EVP_DigestUpdate failed.\n");
            return -1;
        }
        buf_in = buf_in + buf_len;
    }
    if (!EVP_DigestFinal_ex(md_ctx, buf_out, &out_len)) {
        printf("EVP_DigestFinal failed.\n");
        return -1;
    }

    EVP_MD_CTX_free(md_ctx);
    return 0;
}

int sec2_loop_digest(ENGINE *e, const EVP_MD *md, int buf_len, int update_cnt)
{
    int ret = 0 ;
    uint8_t *buf_in = (uint8_t *)malloc(buf_len * update_cnt);
    uint8_t *buf_dec = (uint8_t *)malloc(buf_len * update_cnt);

    ret = rand_buffer(buf_in, buf_len * update_cnt);
    ret = rand_buffer(buf_dec, buf_len * update_cnt);
    ret = do_md(md, buf_len, buf_in, buf_dec, e, update_cnt);

    free(buf_in);
    free(buf_dec);
    return ret;
}

int do_cipher_Encrypt(const EVP_CIPHER *cipher_type, int *buf_len, uint8_t *buf_in,
                     uint8_t *buf_out, uint8_t *key, uint8_t *iv, ENGINE *e, int update_cnt, int fillmode, EVP_CIPHER_CTX *ctx)
{
    int out_len1;
    int out_len2;
    int out_len11[update_cnt];
    /* Encrypt */
    if (!EVP_EncryptInit_ex(ctx, cipher_type, e, key, iv)) {
        printf("EVP_EncryptInit failed.\n");
        return -1;
    }
    if (fillmode == 1){
        EVP_CIPHER_CTX_set_padding(ctx, 1);
    }else{
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }
    for (int i = 0; i < update_cnt; i++) {
        if (!EVP_EncryptUpdate(ctx, buf_out, &out_len1, buf_in, *buf_len)) {
            printf("EVP_EncryptUpdate failed.\n");
            return -1;
        }
        buf_out = buf_out + out_len1;
        buf_in = buf_in + out_len1;
        out_len11[i] = out_len1;
    }
    if (!EVP_EncryptFinal(ctx, buf_out, &out_len2)) {
        printf("EVP_EncryptFinal failed.\n");
        return -1;
    }
    for (int j = 0; j < update_cnt; j++){
        cipher_encrypt_outlen[j] = out_len11[j];
        if (j%2 == 0){
            cipher_encrypt_outlen[j] += out_len2;
        }
    }
    return 0;
}

int do_cipher_Decrypt(const EVP_CIPHER *cipher_type, uint8_t *buf_in,
                     uint8_t *buf_out, uint8_t *key, uint8_t *iv, ENGINE *e, int update_cnt, int fillmode, EVP_CIPHER_CTX *ctx)
{
    int out_len1;
    int out_len2;
    /* Decrypt */
    if (!EVP_DecryptInit_ex(ctx, cipher_type, e, key, iv)) {
        printf("EVP_DecryptInit failed.\n");
        return -1;
    }
    if (fillmode == 1){
        EVP_CIPHER_CTX_set_padding(ctx, 1);
    }
    else{
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }
    for (int i = 0; i < update_cnt; i++) {
        if (!EVP_DecryptUpdate(ctx, buf_out, &out_len1, buf_in, cipher_encrypt_outlen[i])) {
            printf("EVP_DecryptUpdate failed.\n");
            return -1;
        }
        if (i == (update_cnt - 1) && (update_cnt > 1)){
            if (fillmode != 1){
                buf_out = buf_out + (cipher_encrypt_outlen[i] - 16);
            }
            else{
                buf_out = buf_out + out_len1;
            }
        }else{
            if ((i > 0) && (i%2 == 0)){
                buf_out = buf_out + out_len1 - 16;
            }
            else{
                buf_out = buf_out + out_len1;
            }
            buf_in = buf_in + out_len1;
        }
    }
    if (!EVP_DecryptFinal(ctx, buf_out, &out_len2)) {
        printf("EVP_DecryptFinal failed.\n");
        return -1;
    }
    return 0;
}

int sec_loop_cipher(ENGINE *e, const EVP_CIPHER *cipher_type, int buf_len, int update_cnt, int fillmode)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t *buf_in = (uint8_t *)malloc(buf_len * update_cnt);
    uint8_t *buf_enc = (uint8_t *)malloc(buf_len * update_cnt + 16);
    uint8_t *buf_dec = (uint8_t *)malloc(buf_len * update_cnt + 16);
    uint8_t key[64];
    uint8_t iv[16];

    ret = rand_buffer(buf_in, buf_len * update_cnt);
    ret = rand_buffer(key, 64);
    ret = rand_buffer(iv, 16);
    ret = do_cipher_Encrypt(cipher_type, &buf_len, buf_in, buf_enc, key, iv, e, update_cnt, fillmode, ctx);
    ret = do_cipher_Decrypt(cipher_type, buf_enc, buf_dec, key, iv, e, update_cnt, fillmode, ctx);

    buf_len *= update_cnt;
    ret = memcmp(buf_in, buf_dec, buf_len);
/*
    printf("\033[31m FAILED with buflen[%d] update_cnt[%d]\033[0m\n",buf_len, update_cnt);
        dump_data("in", buf_in, buf_len);
        dump_data("dec", buf_dec, buf_len);
*/
    free(buf_in);
    free(buf_enc);
    free(buf_dec);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

//RSA
int rsa_encrypt(RSA *key, unsigned char *encData, unsigned char *srcStr, unsigned int padding_mode)
{
    int ret;
    if (padding_mode == RSA_PKCS1_PADDING )
        ret = RSA_public_encrypt(strlen((const char *)srcStr), srcStr, encData, key, RSA_PKCS1_PADDING);

    if(padding_mode == RSA_PKCS1_OAEP_PADDING)
        ret = RSA_public_encrypt(strlen((const char *)srcStr), srcStr, encData, key, RSA_PKCS1_OAEP_PADDING);
    if(padding_mode == RSA_NO_PADDING)
        ret = RSA_public_encrypt(strlen((const char *)srcStr), srcStr, encData, key, RSA_NO_PADDING);
    if (ret < 0) {
        unsigned long ulErr = ERR_get_error();  
        char szErrMsg[1024] = { 0 };
        ERR_error_string(ulErr, szErrMsg);  
        printf("public key encrypt error:%s\n", szErrMsg);
    }
    return ret;
}

int evp_encrypt(EVP_PKEY *key, unsigned char *encData, size_t *enclen, unsigned char *srcStr, ENGINE *eng)
{
    int ret;
    EVP_PKEY_CTX *ectx;
    ectx = EVP_PKEY_CTX_new(key, eng);
    EVP_PKEY_encrypt_init(ectx);
    ret = EVP_PKEY_encrypt(ectx, encData, enclen, srcStr, strlen((const char *)srcStr));
    EVP_PKEY_CTX_free(ectx);
    if (ret < 0) {
        unsigned long ulErr = ERR_get_error();  
        char szErrMsg[1024] = { 0 };
        ERR_error_string(ulErr, szErrMsg);  
        printf("public key encrypt error:%s\n", szErrMsg);
    }
    return ret;
}

int rsa_decrypt(RSA *key, unsigned char *decData, unsigned char *encData, size_t enclen, unsigned int padding_mode)
{
    int declen;
    if (padding_mode == RSA_PKCS1_PADDING)
        declen = RSA_private_decrypt(enclen, encData, decData, key, RSA_PKCS1_PADDING);
    if (padding_mode == RSA_PKCS1_OAEP_PADDING)
        declen = RSA_private_decrypt(enclen, encData, decData, key, RSA_PKCS1_OAEP_PADDING);
    if (padding_mode == RSA_NO_PADDING) 
        declen = RSA_private_decrypt(enclen, encData, decData, key, RSA_NO_PADDING);

    if (declen < 0) {
        unsigned long ulErr = ERR_get_error();  
        char szErrMsg[1024] = { 0 };
        ERR_error_string(ulErr, szErrMsg);  
        printf("private key decode error:%s\n", szErrMsg);
    }
    return declen;
}

int evp_decrypt(EVP_PKEY *key, unsigned char *decData, size_t *declen, unsigned char *encData, size_t enclen, ENGINE *eng)
{
    int ret;
    EVP_PKEY_CTX *dctx;
    dctx = EVP_PKEY_CTX_new(key, eng);
    EVP_PKEY_decrypt_init(dctx);
    ret = EVP_PKEY_decrypt(dctx, decData, declen, encData, enclen);
    EVP_PKEY_CTX_free(dctx);
    if (ret < 0) 
    {
        unsigned long ulErr = ERR_get_error();  
        char szErrMsg[1024] = { 0 };
        ERR_error_string(ulErr, szErrMsg);  
        printf("private key decrtpt error:%s\n", szErrMsg);
    }
    return ret;
}

int rsa_sign(RSA *key, unsigned char *encData, unsigned char *srcStr, unsigned int padding_mode)
{
    int ret;
    if (padding_mode == RSA_PKCS1_PADDING)
        ret = RSA_private_encrypt(strlen((const char *)srcStr), srcStr, encData, key, RSA_PKCS1_PADDING);
    if (padding_mode == RSA_NO_PADDING)
        ret = RSA_private_encrypt(strlen((const char *)srcStr), srcStr, encData, key, RSA_NO_PADDING);
    if (ret < 0) {
        unsigned long ulErr = ERR_get_error();  
        char szErrMsg[1024] = { 0 };
        ERR_error_string(ulErr, szErrMsg);  
        printf("sign error:%s\n", szErrMsg);
    }
    return ret;
}

int rsa_verify(RSA *key, unsigned char *decData, unsigned char *encData, size_t enclen, unsigned int padding_mode)
{
    int declen;
    if (padding_mode == RSA_PKCS1_PADDING)
        declen = RSA_public_decrypt(enclen, encData, decData, key, RSA_PKCS1_PADDING);
    if (padding_mode == RSA_NO_PADDING)
        declen = RSA_public_decrypt(enclen, encData, decData, key, RSA_NO_PADDING);
    if (declen < 0) {
        unsigned long ulErr = ERR_get_error();  
        char szErrMsg[1024] = { 0 };
        ERR_error_string(ulErr, szErrMsg);  
        printf("verify error:%s\n", szErrMsg);
    }
    return declen;
}

int evp_sign(EVP_PKEY *key, unsigned char *encData, size_t *enclen, unsigned char *srcStr, ENGINE *eng)
{
    int ret = 0;
    EVP_PKEY_CTX *ectx;
    ectx = EVP_PKEY_CTX_new(key, eng);
    EVP_PKEY_sign_init(ectx);
    ret = EVP_PKEY_sign(ectx, encData, enclen, srcStr, strlen((const char *)srcStr));
    EVP_PKEY_CTX_free(ectx);
    if (ret < 0) {
        unsigned long ulErr = ERR_get_error();  
        char szErrMsg[1024] = { 0 };
        ERR_error_string(ulErr, szErrMsg);  
        printf("sign error:%s\n", szErrMsg);
    }
    return ret;
}

int evp_verify(EVP_PKEY *key, unsigned char *decData, size_t declen, unsigned char *encData, size_t enclen, ENGINE *eng)
{
    int ret = 1;
    EVP_PKEY_CTX *dctx;
    dctx = EVP_PKEY_CTX_new(key, eng);
    EVP_PKEY_verify_init(dctx);
    ret = EVP_PKEY_verify(dctx, encData, enclen, decData, declen);
    EVP_PKEY_CTX_free(dctx);
    if (ret <= 0) {
        unsigned long ulErr = ERR_get_error();  
        char szErrMsg[1024] = { 0 };
        ERR_error_string(ulErr, szErrMsg); 
        printf("verify error:%s\n", szErrMsg);
    }
    return ret;
}

int rsa_various_padding_mode(int keylen, unsigned char *srcStr, int padding) 
{   

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    ENGINE *engine = ENGINE_by_id("kae");

    int bit = keylen;
    unsigned long e = RSA_F4;  // 65537
    BIGNUM *e_value = BN_new();
    BN_set_word(e_value, e);
    RSA *rsa = RSA_new_method(engine);
    RSA_generate_key_ex(rsa, bit, e_value, NULL);
    if (RSA_check_key_ex(rsa, NULL) < 0) {
        printf("Failed to generate the key.\n");
        return FALSE;
    }
    int enclen, declen, siglen, verlen;
    int key_len = RSA_size(rsa);
    unsigned char *encData = (unsigned char *)malloc(key_len + 1);
    memset(encData, 0, key_len + 1);
    unsigned char *decData = (unsigned char *)malloc(key_len + 1);
    memset(decData, 0, key_len + 1);
    unsigned char *signData = (unsigned char *)malloc(key_len + 1);
    memset(signData, 0, key_len + 1);
    unsigned char *verData = (unsigned char *)malloc(key_len + 1);
    memset(verData, 0, key_len + 1);

    enclen = rsa_encrypt(rsa, encData, (unsigned char *)srcStr, padding);
    if (enclen < 0) {
        printf("Encryption failed.\n");
        return FALSE;
    }
    declen = rsa_decrypt(rsa, decData, encData, enclen, padding);
    if(declen < 0) {
        printf("Decryption failed.\n");
        return FALSE;
    }
    if(memcmp(decData, srcStr, declen) != 0) {
        printf("Failed to encrypt or decrypt the result.\n");
        return FALSE;
    }

    siglen = rsa_sign(rsa, signData, (unsigned char *)srcStr, padding);
    if(siglen < 0) {
        printf("Failed to sign the signature.\n");
        return FALSE;
    }
    verlen = rsa_verify(rsa, verData, signData, siglen, padding);
    if(verlen < 0) {
        printf("Failed to verify the signature.\n");
        return FALSE;
    }

    free(encData);
    free(decData);
    free(signData);
    free(verData);
    RSA_free(rsa);
    return TRUE ;	
}

int rsa_software_and_hardware_switch_mode(int keylen)
{
    ENGINE *engine;
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    engine = ENGINE_by_id("kae");
    EVP_PKEY *pkey, *pri_key;
    int bit = keylen;
    unsigned long e = RSA_F4;  // 65537
    BIGNUM *e_value = BN_new();
    BN_set_word(e_value, e);
    RSA *rsa = RSA_new_method(NULL);
    RSA_generate_key_ex(rsa, bit, e_value, NULL);
    if(RSA_check_key_ex(rsa, NULL) <= 0) {
        printf("Failed to generate the key.\n");
        return FALSE;
    }

    pkey = EVP_PKEY_new();
    pri_key = EVP_PKEY_new();

    RSA *public_key = RSAPublicKey_dup(rsa);
    RSA *private_key = RSAPrivateKey_dup(rsa);
    EVP_PKEY_set1_RSA(pkey, public_key);
    EVP_PKEY_set1_RSA(pri_key, private_key);

    int ret;
    size_t enclen, declen, siglen;
    unsigned char *srcStr = (unsigned char *)"123456789";
    int key_len = RSA_size(rsa);
    unsigned char *encData = (unsigned char *)malloc(key_len + 1);
    memset(encData, 0, key_len + 1);
    unsigned char *decData = (unsigned char *)malloc(key_len + 1);
    memset(decData, 0, key_len + 1);

    unsigned char *signData = (unsigned char *)malloc(key_len + 1);
    memset(signData, 0, key_len + 1);

    ret = evp_encrypt(pkey, encData, &enclen, srcStr, engine);
    if(ret < 0) {
        printf("Encryption failed.\n");
        return FALSE;
    }
    ret = evp_decrypt(pri_key, decData, &declen, encData, enclen, engine);
    if(ret < 0) {
        printf("Decryption failed.\n");
        return FALSE;
    }
    if(memcmp(decData, srcStr, declen) != 0) {
        printf("Failed to encrypt or decrypt the result.\n");
        return FALSE;
    }

    ret = evp_sign(pri_key, signData, &siglen, srcStr, engine);
    if(ret < 0) {
        printf("Failed to sign the signature.\n");
        return FALSE;
    }
    ret = evp_verify(pkey, srcStr, strlen((const char *)srcStr), signData, siglen, engine);
    if(ret != 1) {
        printf("Failed to verify the signature.\n");
        return FALSE;
    }
   
    return TRUE;

}

