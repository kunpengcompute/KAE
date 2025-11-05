import os
import sys

from parse_perf_log import extract_log_data, create_excel

def process_folder(folder_path, output_file, file_prefix):
    # 初始化数据字典
    data_dict = {}

    # 遍历文件夹中的所有文件
    for filename in sorted(os.listdir(folder_path)):
        file_path = os.path.join(folder_path, filename)
        # print(f"遍历：{file_path}")
        # 仅处理文件，不处理子目录，且文件名符合前缀
        if os.path.isfile(file_path) and filename.startswith(file_prefix):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    log_text = f.read()
            except Exception as e:
                print(f"读取文件 {filename} 错误: {e}")
                continue

            # 提取并处理数据
            file_data = extract_log_data(log_text, file_path)

            # 将提取的数据添加到data_dict中
            for suffix, data in file_data.items():
                if suffix not in data_dict:
                    data_dict[suffix] = []
                data_dict[suffix].extend(data)

    # 生成Excel
    create_excel(data_dict, output_file)

def main():
    if len(sys.argv) < 2:
        print("错误：请指定日志文件名作为参数")
        print("用法：python script.py <日志文件名> [输出文件名]")
        sys.exit(1)

    # 第一个参数：要处理的文件夹。
    log_file_path = sys.argv[1]
    # 第二个参数：最终要输出的文件路径。
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'output.xlsx'
    # 指定日志文件的前缀，仅处理符合前缀的文件。
    file_prefix = "kzip-delay.log."

    if not os.path.isdir(log_file_path):
        print("错误：指定的路径不是有效的文件夹")
        return

    # 处理文件夹中的所有符合条件的文件
    process_folder(log_file_path, output_file, file_prefix)

if __name__ == "__main__":
    main()
