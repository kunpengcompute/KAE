/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: sm2 functest try
 * @Author: LiuYongYang
 * @Date: 2024-03-21
 * @LastEditTime: 2024-03-25
 */

#include <cstdio>
#include <iostream>
#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
using std::cout;
using std::endl;
using std::string;

static inline void PrintBufferHex(const char* buffer, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        if (i % 10 == 0) {
            fprintf(stderr, "\n");
        }
        fprintf(stderr, "%#04x\t", buffer[i]);
    }
    fprintf(stderr, "\n");
}

EVP_PKEY* SM2_CreateEVP_PKEY(const string& keyStr, bool isPublic)
{
    BIO* bio_key = BIO_new_mem_buf(keyStr.c_str(), -1);
    EVP_PKEY* evp_pkey = isPublic ?
        PEM_read_bio_PUBKEY(bio_key, NULL, NULL, NULL) : PEM_read_bio_PrivateKey(bio_key, NULL, NULL, NULL);

    EVP_PKEY_set_alias_type(evp_pkey, EVP_PKEY_SM2);
    BIO_free_all(bio_key);
    return evp_pkey;
}

void SM2_GenKey(string& prikeyStr, string& pubkeyStr)
{
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    EC_GROUP* ec_group = EC_GROUP_new_by_curve_name(NID_sm2);
    EC_KEY_set_group(ec_key, ec_group);

    EC_KEY_generate_key(ec_key);
    BIO* bpri_key = BIO_new(BIO_s_mem());
    BIO* bpub_key = BIO_new(BIO_s_mem());
    PEM_write_bio_ECPrivateKey(bpri_key, ec_key, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_EC_PUBKEY(bpub_key, ec_key);

    size_t prk_len = BIO_pending(bpri_key);
    size_t pbk_len = BIO_pending(bpub_key);
    fprintf(stderr, "private_key_len = %lu, public_key_len = %lu\n", prk_len, pbk_len);

    char *prkBuff = new char[prk_len + 1]();
    char *pbkBuff = new char[pbk_len + 1]();
    BIO_read(bpri_key, prkBuff, prk_len);
    BIO_read(bpub_key, pbkBuff, pbk_len);
    prikeyStr = prkBuff;
    pubkeyStr = pbkBuff;

free_mem:
    delete[] pbkBuff;
    delete[] prkBuff;
    BIO_free_all(bpub_key);
    BIO_free_all(bpri_key);
    EC_GROUP_free(ec_group);
    EC_KEY_free(ec_key);
}

string SM2_enc(EVP_PKEY* pubKey, const string& message, ENGINE* e = NULL)
{
    size_t encSize = 1024;
    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new(pubKey, e);
    EVP_PKEY_encrypt_init(pkey_ctx);
    if (EVP_PKEY_CTX_ctrl(pkey_ctx, -1, -1, EVP_PKEY_CTRL_MD, -1, (void *)EVP_sm3()) <= 0) {
        cout << "SM2 EVP_PKEY_CTX_ctr control pctx failed" << endl;
    }

    const unsigned char* pMsg = (const unsigned char*)message.c_str();
    // EVP_PKEY_encrypt(pkey_ctx, NULL, &encSize, pMsg, message.size());//为了计算输出长度，无效
    unsigned char* pEncMsg = new unsigned char[1024+1]();
    EVP_PKEY_encrypt(pkey_ctx, pEncMsg, &encSize, pMsg, message.size());
    cout << "enc length is " << encSize << endl;
    string retStr((const char*)pEncMsg, encSize);

free_mem:
    delete[] pEncMsg;
    EVP_PKEY_CTX_free(pkey_ctx);

    return retStr;
}

string SM2_dec(EVP_PKEY* priKey, const string& encMsg, ENGINE* e = NULL)
{
    size_t decSize = 1024;
    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new(priKey, e);
    EVP_PKEY_decrypt_init(pkey_ctx);
    // EVP_PKEY_CTX_ctrl_str(pkey_ctx, "digest", "sm3");
    if (EVP_PKEY_CTX_ctrl(pkey_ctx, -1, -1, EVP_PKEY_CTRL_MD, -1, (void *)EVP_sm3()) <= 0) {
        cout << "SM2 EVP_PKEY_CTX_ctr control pctx failed" << endl;
    }

    const unsigned char* pMsg = (const unsigned char*)encMsg.c_str();
    // EVP_PKEY_decrypt(pkey_ctx, NULL, &decSize, pMsg, encMsg.size());
    unsigned char* pDecMsg = new unsigned char[1024+1]();
    EVP_PKEY_decrypt(pkey_ctx, pDecMsg, &decSize, pMsg, encMsg.size());
    cout << "dec length is " << decSize << endl;
    string retStr((const char*)pDecMsg, decSize);

free_mem:
    delete[] pDecMsg;
    EVP_PKEY_CTX_free(pkey_ctx);

    return retStr;
}

string SM2_sign(EVP_PKEY* priKey, const string& message, const string& sm2_id, ENGINE* e = NULL)
{
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new(priKey, e);
    EVP_PKEY_CTX_set1_id(pkey_ctx, sm2_id.c_str(), sm2_id.size());
    EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx);

    EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), e, priKey);

    size_t sign_len = 1024;
    const unsigned char* pmsg = (const unsigned char*)message.c_str();
    // EVP_DigestSign(md_ctx, NULL, &sign_len, pmsg, message.size());  //  just get sign_len
    cout << "sign_len = " << sign_len << endl;
    unsigned char* signBuff = new unsigned char[1024 + 1]();

    EVP_DigestSign(md_ctx, signBuff, &sign_len, pmsg, message.size());
    string retStr((const char*)signBuff, sign_len);

free_mem:
    delete[] signBuff;
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_CTX_free(pkey_ctx);

    return retStr;
}

void SM2_verify(EVP_PKEY* pubKey, const string& message, const string& signMsg, const string& sm2_id,
    ENGINE* e = NULL)
{
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new(pubKey, e);
    EVP_PKEY_CTX_set1_id(pkey_ctx, sm2_id.c_str(), sm2_id.size());
    EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx);

    EVP_DigestVerifyInit(md_ctx, NULL, EVP_sm3(), e, pubKey);
    const unsigned char* pSign = (const unsigned char*)signMsg.c_str();
    const unsigned char* pmesg = (const unsigned char*)message.c_str();
    if (EVP_DigestVerify(md_ctx, pSign, signMsg.size(), pmesg, message.size()) != 1) {
        cout << "SM2 signature verify failed!" << endl;
    } else {
        cout << "SM2 signature verify succeeded!" << endl;
    }

free_mem:
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_CTX_free(pkey_ctx);
}

int main()
{
    string prikeyStr, pubkeyStr;
    SM2_GenKey(prikeyStr, pubkeyStr);
    cout << "\n----------------------------TEST SM2---------------------------------------\n";
    cout << "prikey : \n" << prikeyStr << "\n\npubkey: \n" << pubkeyStr << endl;

    EVP_PKEY* evp_priKey = SM2_CreateEVP_PKEY(prikeyStr, false);
    EVP_PKEY* evp_pubKey = SM2_CreateEVP_PKEY(pubkeyStr, true);
    if (!evp_priKey || !evp_pubKey) {
        cout << "evp key is NULL" << endl;
    }

    OpenSSL_add_all_algorithms();
    ENGINE_load_dynamic();
    ENGINE* e = ENGINE_by_id("kae");
    if (!e) {
        cout << "Engine kae failed!" << endl;
    }

    const string message("Hello openssl sm2!");
    const string sm2_id("snowdance1997");
    cout << "\n---------------------------sign and verify---------------------------------------\n";
    /* 签名与验签 */
    string signStr = SM2_sign(evp_priKey, message, sm2_id, e);
    PrintBufferHex(signStr.c_str(), signStr.size());
    SM2_verify(evp_pubKey, message, signStr, sm2_id, e);

    cout << "\n---------------------------encode and decode---------------------------------------\n";
    /* 加密与解密 */
    PrintBufferHex(message.c_str(), message.size());
    string encStr = SM2_enc(evp_pubKey, message, e);
    string decStr = SM2_dec(evp_priKey, encStr,  e);
    PrintBufferHex(decStr.c_str(), decStr.size());
    cout << "[PUBKEY]" << evp_pubKey << endl;
    cout << "[PRIKEY]" << evp_priKey << endl;
    cout << "[message]" << message << endl;
    // cout << "[encStr]" << encStr << endl;
    cout << "[decStr]" << decStr << endl;
    

    if (message == decStr) {
        cout << "[RES]SM2 enc&dec succeeded!" << endl;
    } else {
        cout << "[RES]SM2 enc&dec failed!" << endl;
    }

    EVP_PKEY_free(evp_priKey);
    EVP_PKEY_free(evp_pubKey);

    return 0;
}
