all:
        gcc zpipe_gzip.c -o gzip_sw -L/usr/local/lib -lz
        gcc zpipe_gzip.c -o gzip_test -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz
        gcc zpipe.c -o zpipe_sw -L/usr/local/lib -lz
        gcc zpipe.c -o zpipe_test -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz

.PHONY : clean
clean :
        -rm -f gzip_sw gzip_test zpipe_sw zpipe_test