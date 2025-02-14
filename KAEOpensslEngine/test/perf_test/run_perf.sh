#!/bin/sh

echo "start openssl perf test."

sh bandwidth.sh
sh openssl_perf.sh
python convert.py 

echo "All openssl perf scripts have been executed."