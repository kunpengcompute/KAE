function main()
{
    if [ "$1" == "clean" ]; then
        make clean
    else
        make clean
        make KAE_DEMO_CIPHER=y KAE_DEMO_RSA=y KAE_DEMO_DIGEST=y
    fi

    return 1
}

main "$@"
exit $?
