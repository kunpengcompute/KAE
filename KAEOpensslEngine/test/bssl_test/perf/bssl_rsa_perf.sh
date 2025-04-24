#!/bin/bash

core_count=$(nproc)
half_cores=$((core_count / 2))
run_times=3;

output_dir="./output"
mkdir -p "$output_dir"

# 单P
for i in $(seq 0 $((run_times-1))); do
    for core_id in $(seq 0 $((half_cores-1))); do
        index=$((i * half_cores + core_id))
        taskset -c $core_id ./bssl speed -filter RSA -timeout 12 > "$output_dir/bssl_rsa_${index}.txt" &
    done
    wait
done


# 单核
taskset -c 0 ./bssl speed -filter RSA -timeout 12 | awk -v OFS="," '
BEGIN { print "bits,op_type,ops/sec" }
/Did/ {
    if (match($0, /Did [0-9]+ RSA ([0-9]+) ([^ ]+.*[^ ]) operations in [0-9]+us \(([0-9.]+) ops\/sec/, arr)) {
        print arr[1], arr[2], arr[3]
    }
}' > bssl_rsa_one_core.csv
