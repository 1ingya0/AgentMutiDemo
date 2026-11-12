# 用于向飞书机器人发送告警请求。
import requests
# 用于获取当前时间并计算告警窗口。
import time
# 用于在日志文本中查找特征。
import re
# 用于连接 Redis 队列。
import redis
# 用于将项目根目录加入模块搜索路径。
import sys
# 为每个告警 IP 自动创建状态记录。
from collections import defaultdict
# 用于定位当前文件相对于项目根目录的位置。
from pathlib import Path

# 根据当前文件所在位置计算项目根目录。
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
# 检查项目根目录是否已存在于模块搜索路径中。
if PROJECT_ROOT not in sys.path:
    # 将项目根目录放到搜索路径前部，以便导入根目录配置。
    sys.path.insert(0, PROJECT_ROOT)

# 从项目配置中读取 Redis 服务地址与端口。
from config import REDIS_HOST, REDIS_PORT

# 指定接收告警消息的飞书机器人地址。
FEISHU_WEBHOOK = "https://open.feishu.cn/open-apis/bot/v2/hook/cc90f814-c0a7-4656-ae8d-cfe9350c2c81"
# 创建 Redis 连接，供后续读取日志队列。
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)

# 按来源 IP 保存命中数、窗口开始时间和最近一条日志。
alert_pool = defaultdict(lambda: {"count": 0, "first_time": time.time(), "last_log": ""})

def send_feishu(ip, data):
    """把指定 IP 的聚合告警摘要发送到飞书。"""
    # 组合告警正文，并截取最后日志的前 80 个字符。
    text = f"🚨 【Redis聚合告警】\n源 IP: {ip}\n攻击次数: {data['count']}\n最后攻击: {data['last_log'][:80]}..."
    # 通过飞书机器人接口发送文本消息。
    requests.post(FEISHU_WEBHOOK, json={"msg_type": "text", "content": {"text": text}})
    # 输出已发送告警的状态提示。
    print(f"\n[分析器] 📨 已发送飞书告警")

def block_ip(ip):
    """记录模拟封禁动作；此实现仅输出信息，不修改系统防火墙。"""
    # 打印蓝队对该 IP 的风险判定。
    print(f"🛑 [蓝队主动防御] 判定 {ip} 为高危攻击者！")
    # 打印模拟阻断提示，便于测试时观察流程。
    print(f"⚡ [执行阻断] 已向 Nginx/防火墙 下发封锁指令 (模拟执行：drop tcp from {ip})")


def flush_alerts():
    """发送已到期的聚合告警，并按命中次数触发模拟封禁。"""
    # 获取当前时间，用于判断聚合窗口是否结束。
    now = time.time()
    # 遍历键的副本，以便在循环中安全删除已处理项。
    for ip in list(alert_pool.keys()):
        # 仅处理已超过五秒且存在命中记录的告警项。
        if now - alert_pool[ip]["first_time"] > 5 and alert_pool[ip]["count"] > 0:
            # 发送该 IP 在当前窗口内的聚合信息。
            send_feishu(ip, alert_pool[ip])
            # 命中数达到五次时执行模拟封禁提示。
            if alert_pool[ip]["count"] >= 5:
                block_ip(ip)
            # 删除已汇总的状态，等待后续日志创建新窗口。
            del alert_pool[ip]

def analyze():
    """持续消费 Redis 日志、匹配特征并汇总告警。"""
    # 输出分析器启动状态。
    print("[分析器] 启动，正在从 Redis 消费日志...")
    # 记录上次检查告警窗口的时间。
    last_flush = time.time()
    
    # 持续监听队列并分析新日志。
    while True:
        # 最多等待一秒读取日志，避免告警汇总逻辑长期得不到执行。
        item = r.brpop("security_logs", timeout=1)
        
        # 有队列数据时才解码并分析日志。
        if item:
            # 将 Redis 返回的字节数据转换为 UTF-8 字符串。
            log_line = item[1].decode('utf-8')
            # 用简单字符串特征判断日志是否需要进入告警流程。
            if re.search(r"(OR\+|UNION|SELECT|--|AI_GUARD_BLOCKED)", log_line, re.IGNORECASE) or re.search(r'urt="[2-9]\.', log_line):
                # 根据日志标记选择用于控制台展示的类别名称。
                attack_type = "底层抓包拦截" if "RAW_TRAFFIC" in log_line else "Nginx日志拦截"
                # 增加本地测试地址对应的命中次数。
                alert_pool["127.0.0.1"]["count"] += 1
                # 更新该聚合项中最近一次命中的日志文本。
                alert_pool["127.0.0.1"]["last_log"] = log_line
                # 输出当前类别和累计命中数量。
                print(f"[分析器] 捕获攻击 ({attack_type})，当前池子: {alert_pool['127.0.0.1']['count']} 条")
        
        # 每隔五秒检查一次是否需要发送聚合告警。
        if time.time() - last_flush > 5:
            # 处理所有已达到时间窗口的告警项。
            flush_alerts()
            # 重置计时起点。
            last_flush = time.time()

# 仅在直接运行该文件时启动分析器。
if __name__ == '__main__':
    # 开始从 Redis 队列消费日志。
    analyze()