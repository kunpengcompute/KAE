all:
	gcc zpipe_gzip.c -o gzip_sw -L/usr/local/lib -lz -DCHUNK_VALUE=16
	gcc zpipe_gzip.c -o gzip_test -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=16
	gcc zpipe.c -o zpipe_sw -L/usr/local/lib -lz -DCHUNK_VALUE=16
	gcc zpipe.c -o zpipe_test -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=16
	
	gcc zpipe_gzip.c -o zpipe_1_gzip -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=1 
	gcc zpipe.c -o zpipe_1_zlib -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=1 
	gcc zpipe_gzip.c -o zpipe_16_gzip -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=16 
	gcc zpipe.c -o zpipe_16_zlib -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=16 
	gcc zpipe_gzip.c -o zpipe_40_gzip -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=40 
	gcc zpipe.c -o zpipe_40_zlib -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=40
	gcc zpipe_gzip.c -o zpipe_100_gzip -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=100 
	gcc zpipe.c -o zpipe_100_zlib -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=100
	gcc zpipe_gzip.c -o zpipe_200_gzip -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=200 
	gcc zpipe.c -o zpipe_200_zlib -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=200
	gcc zpipe_gzip.c -o zpipe_256_gzip -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=256 
	gcc zpipe.c -o zpipe_256_zlib -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=256
	gcc zpipe_gzip.c -o zpipe_300_gzip -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=300 
	gcc zpipe.c -o zpipe_300_zlib -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=300
	gcc zpipe_gzip.c -o zpipe_400_gzip -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=400 
	gcc zpipe.c -o zpipe_400_zlib -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=400
	gcc zpipe_gzip.c -o zpipe_512_gzip -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=512 
	gcc zpipe.c -o zpipe_512_zlib -L/usr/local/kaezip/lib/ -lkaezip -lwd -lz -DCHUNK_VALUE=512
	
	gcc zpipe_multi_thread.c -o zpipe_multi_thread_test -L. -I. -lz -Wl,-rpath,/usr/local/kaezip/lib -lpthread 
.PHONY : clean
clean :
	-rm -f gzip_sw gzip_test zpipe_sw zpipe_test zpipe_multi_thread_test zpipe_*_gzip zpipe_*_zlib