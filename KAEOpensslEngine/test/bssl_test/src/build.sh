function main()
{
    if [ "$1" == "clean" ]; then
        make clean
    else
        make clean
        make KAE_DEMO_RSA=y 
    fi

    return 1
}

main "$@"
exit $?
