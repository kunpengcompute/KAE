import os
import csv

# 获取当前目录
current_directory = os.getcwd()

# 定义输出文件夹路径
output_folder = os.path.join(current_directory, 'output')  # 存放转换后的 CSV 文件

# 创建输出文件夹（如果不存在）
os.makedirs(output_folder, exist_ok=True)

# 定义表头
columns_header = [
    '测试环境', '算法', '同步异步', '进程数量', '包长', 
    '软算速度 KB/s', '硬算速度 KB/s', '硬软比',
    '软算速度 Gbps', '硬算速度 Gbps'
]

# 遍历当前目录下的所有 .txt 文件
for filename in os.listdir(current_directory):
    # 判断文件是否为 .txt 文件
    if filename.endswith('.txt'):
        input_file = os.path.join(current_directory, filename)
        
        # 创建一个新的 CSV 文件
        output_file = os.path.join(output_folder, f"{os.path.splitext(filename)[0]}.csv")
        
        with open(input_file, 'r', encoding='utf-8') as infile, open(output_file, 'w', newline='', encoding='utf-8-sig') as outfile:
            reader = infile.readlines()
            writer = csv.writer(outfile)
            
            # 写入表头
            writer.writerow(columns_header)
            
            # 跳过第一行（表头）
            for i, line in enumerate(reader):
                if i == 0:
                    continue  # 跳过第一行

                line = line.strip()  # 去掉前后的空白字符
                if line:
                    columns = line.split(',')
                    
                    # 如果数据不足，填充0
                    columns = [col.strip() if col.strip() else '0' for col in columns]
                    
                    # 获取软算和硬算速度（单位：KB/s）
                    try:
                        soft_speed = float(columns[5])
                        hard_speed = float(columns[6])
                    except ValueError:
                        soft_speed = 0
                        hard_speed = 0
                    
                    # 转换为带宽（单位：Gbps/s），注意1KB = 8Kb
                    soft_bandwidth = (soft_speed * 8) / 1e6  # KB/s 转 Gbps/s
                    hard_bandwidth = (hard_speed * 8) / 1e6  # KB/s 转 Gbps/s
                    
                    # 保留两位小数
                    soft_bandwidth = round(soft_bandwidth, 2)
                    hard_bandwidth = round(hard_bandwidth, 2)
                    
                    # 添加带宽到数据列表
                    columns.append(soft_bandwidth)  # 软算带宽 Gbps/s
                    columns.append(hard_bandwidth)  # 硬算带宽 Gbps/s
                    
                    # 写入数据到 CSV 文件
                    writer.writerow(columns)

        print(f"文件 {filename} 已成功转换为 {output_file}")

print("所有文件已转换完成！")
