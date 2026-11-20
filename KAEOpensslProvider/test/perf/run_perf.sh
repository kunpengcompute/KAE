#!/bin/sh

echo "start openssl perf test."

chmod +x bandwidth.sh
chmod +x multi_perf.sh
sh bandwidth.sh
sh multi_perf.sh
python convert.py 

echo "All openssl perf scripts have been executed."