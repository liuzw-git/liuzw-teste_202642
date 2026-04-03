import json
from collections import Counter

def parse_ndjson_file(file_path):
    data_list = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # 使用 raw_decode 循环解析，直到文件结束
            idx = 0
            while idx < len(content):
                # 尝试从当前位置解析一个 JSON 对象
                try:
                    # raw_decode 返回两个值：解析出的对象，和该对象的结束位置索引
                    obj, idx = json.JSONDecoder().raw_decode(content, idx)
                    data_list.append(obj)
                except json.JSONDecodeError as e:
                    # 如果解析出错，打印错误并停止
                    print(f"解析中断: {e}")
                    print(f"停止位置索引: {idx}")
                    # 为了调试，可以打印停止位置附近的字符
                    print(f"停止位置附近内容: ...{content[max(0, idx-20):idx+20]}...")
                    break
        
        print(f"成功解析数据，总共 {len(data_list)} 条记录。")
        return data_list

    except FileNotFoundError:
        print(f"错误：找不到文件 {file_path}")
        return []
    except Exception as e:
        print(f"发生未知错误: {e}")
        return []

def analyze_seeds(file_path):
    # 1. 使用新的解析函数读取数据
    data = parse_ndjson_file(file_path)
    
    if not data:
        print("没有读取到有效数据。")
        return

    # 2. 提取种子字段
    # 注意：这里需要根据您实际的数据结构调整 'seed' 这个键名
    # 如果数据是列表套列表，或者其他结构，这里需要相应修改
    seeds = []
    for item in data:
        # 假设 item 是字典，且包含 'seed' 键
        if isinstance(item, dict) and 'seed' in item:
            seeds.append(str(item['seed']))
        # 如果 item 本身就是种子字符串
        elif isinstance(item, str):
            seeds.append(item)
        # 如果数据结构复杂，可以在这里添加更多判断逻辑
        else:
            # 暂时跳过无法识别的结构，或者打印出来调试
            pass

    # 3. 统计重复度
    total_count = len(seeds)
    if total_count == 0:
        print("未找到有效的种子数据。")
        return

    unique_count = len(set(seeds))
    duplicate_count = total_count - unique_count
    
    print("-" * 30)
    print(f"总数据量: {total_count}")
    print(f"唯一数据量: {unique_count}")
    print(f"重复数据量: {duplicate_count}")
    print("-" * 30)

    counter = Counter(seeds)
    if duplicate_count > 0:
        print("重复最多的数据 (Top 10):")
        for seed, count in counter.most_common(10):
            if count > 1:
                print(f"  {seed}: 出现 {count} 次")
    else:
        print("没有发现重复数据。")

# --- 主程序入口 ---
if __name__ == "__main__":
    # 请确保路径正确，建议使用 r'' 原始字符串避免转义问题
    # 注意：这里我使用了您之前提供的路径，如果文件名变了请修改
    input_file = r"D:\1.LZW-2025测试项目\2025-渗透测试\4.渗透测试执行\渗透测试-20260331-V5L\输出\27服务\seed-1003-2701 - 副本.json"
    
    print(f"正在读取文件: {input_file}")
    analyze_seeds(input_file)
