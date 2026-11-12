# 用于检查日志文件是否存在。
import os
# 用于将项目根目录加入 Python 模块搜索路径。
import sys
# 用于在轮询日志文件时暂停一小段时间。
import time
# 用于跨平台地解析当前文件和项目目录路径。
from pathlib import Path

# Redis 客户端，用于将采集到的日志写入队列。
import redis

# 计算项目根目录，供下面导入项目级配置模块使用。
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
# 仅在项目根目录尚未加入搜索路径时添加它。
if PROJECT_ROOT not in sys.path:
    # 将项目根目录放在搜索路径前部，确保可以导入根目录的 config.py。
    sys.path.insert(0, PROJECT_ROOT)

# 读取 Redis 连接参数，避免在本文件重复维护配置值。
from config import REDIS_HOST, REDIS_PORT

# 使用配置中的主机和端口创建 Redis 连接，db=0 表示使用默认数据库。
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)
# 设置 Nginx 访问日志的相对路径，路径基于程序启动时的工作目录。
LOG_FILE = "../nginx/logs/nginx_access.log"

def collect():
    """等待访问日志出现，并持续转发新写入的日志行。"""
    # 输出采集器启动提示。
    print("[采集器] 启动，正在监听 Nginx 日志...")
    # 当日志文件还不存在时持续等待。
    while not os.path.exists(LOG_FILE):
        # 每次检查后暂停一秒，避免忙等。
        time.sleep(1)
        
    # 以文本模式读取日志，并忽略无法解码的字节。
    with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        # 将文件指针移至末尾，只处理启动后新追加的内容。
        f.seek(0, 2)
        # 持续监听日志文件后续写入。
        while True:
            # 读取一行新增日志；无新内容时返回空字符串。
            line = f.readline()
            # 没有新日志时进入等待分支。
            if not line:
                # 稍作暂停，降低空轮询的 CPU 消耗。
                time.sleep(0.5)
                # 结束本轮循环并重新读取文件。
                continue
            
            # 去掉行尾空白后推入 Redis 列表，供分析器异步消费。
            r.lpush("security_logs", line.strip())
            # 打印当前日志的前 50 个字符作为采集状态提示。
            print(f"[采集器] 推送日志: {line.strip()[:50]}...")

# 仅当直接运行本文件时启动采集循环；被导入时不自动运行。
if __name__ == '__main__':
    # 启动持续监听和转发任务。
    collect()