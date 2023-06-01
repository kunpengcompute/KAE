function main()
{
    if [ "$1" == "clean" ]; then
        make clean
    else
        make clean
        make UTESTCONF_TEST_RSA_NORMAL=y
            #  UTESTCONF_TEST_SM4_QUEUE=y  \
            #  UTESTCONF_TEST_SM4_NORMAL=y \
            #  UTESTCONF_TEST_SM4_QUEUE=y  \
            #  UTESTCONF_TEST_SM4_MULTI=y  \
            #  UTESTCONF_TEST_SM3_NORMAL=y \
            #  UTESTCONF_TEST_SM3_QUEUE=y  \
            #  UTESTCONF_TEST_SM3_MULTI=y  \
            #  UTESTCONF_TEST_RSA_QUEUE=y  \
            #  UTESTCONF_TEST_RSA_MULTI=y  \
            #  UTESTCONF_TEST_DH=y         \
            #  UTESTCONF_TEST_ASYNC_CIPHER=y  \
            #  UTESTCONF_TEST_AES=y  \
            #  UTESTCONF_TEST_ASYNC_DIGEST=y  \
            #  UTESTCONF_TEST_SM4_AES_MULTITHREAD=y  
    fi

    return 1
}

main "$@"
exit $?
