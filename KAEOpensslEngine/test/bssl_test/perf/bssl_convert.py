import os
import re
import csv

def main():
    data = {}
    output_dir = 'output'
    output_file = 'bssl_rsa_haft_core.csv'
    run_times = 3

    # 遍历目录中的所有文件
    for filename in os.listdir(output_dir):
        if filename.endswith('.txt'):
            process_file(os.path.join(output_dir, filename), data)

    # 汇总结果并写入 CSV 文件
    results = []
    for (rsa_bit, operation), total_ops in data.items():
        avg_ops = total_ops / run_times
        results.append((rsa_bit, operation, f"{avg_ops:.2f}"))

    # 输出结果到 CSV 文件
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['bits', 'type', 'ops/sec'])
        writer.writerows(results)

    print(f"数据已保存至 {output_file}")

def process_file(file_path, data):
    with open(file_path, 'r') as f:
        for line in f:
            match = re.match(
                r'Did \d+ RSA (\d+) ([a-zA-Z0-9 ()]+) operations in \d+us \(([\d.]+) ops/sec\)$',
                line.strip()
            )
            if match:
                rsa_bit = int(match.group(1))
                operation = match.group(2).strip()
                ops = float(match.group(3))

                key = (rsa_bit, operation)
                if key not in data:
                    data[key] = 0.0
                data[key] += ops

if __name__ == "__main__":
    main()
