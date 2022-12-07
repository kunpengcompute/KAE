cd kae_driver
make -j
make install
cd ../uadk
sh autogen.sh
sh conf.sh
make -j
make install
cd ../kae_engine
autoreconf -i
./configure --libdir=/usr/local/lib/engines-1.1/ --enable-kae
make -j
make install