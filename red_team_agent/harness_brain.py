import asyncio
import requests
import chromadb
import sys
import os
import json
import redis            # ← 新增: 上报红队状态到 Redis
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import TARGET_IP, NGINX_PORT

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "qwen2.5:14b-instruct"

# ============================================================
# 📡 红队状态上报层 (新增): 把状态推进 Redis, 供 Dashboard 左栏实时展示
# ============================================================
REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0
RED_STATUS_KEY = "red_team_status"   # 与 dashboard.py 约定一致
RED_STATUS_FIELD = "current"
MAX_STATUS_LINES = 10                # 左栏最多保留多少条状态

try:
    redis_client = redis.Redis(
        host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True
    )
    redis_client.ping()
    _REDIS_OK = True
    print("📡 [状态上报] Redis 已连接, 红队状态将实时同步到大屏。")
except redis.RedisError as e:
    _REDIS_OK = False
    redis_client = None
    print(f"⚠️ [状态上报] Redis 不可用({e}), 大屏左栏将退化为日志反推模式。")

# 内存里维护一个状态列表, 保证多次上报能累加(而不是每次覆盖)
_status_buffer: list[str] = []


def push_status(line: str, persist: bool = True) -> None:
    """
    上报一条红队状态到大屏左栏。
    - line    : 要展示的一行状态文本(建议带 emoji 前缀)
    - persist : 是否累加进缓冲区; False 表示"临时替换"当前状态(如单步提示)
    Redis 不可用时静默降级, 不影响攻击主流程。
    """
    global _status_buffer
    if persist:
        _status_buffer.append(line)
        # 只保留最近 N 条, 防止无限增长
        _status_buffer = _status_buffer[-MAX_STATUS_LINES:]
    else:
        _status_buffer = [line]

    if not _REDIS_OK:
        return
    try:
        redis_client.hset(RED_STATUS_KEY, RED_STATUS_FIELD, json.dumps(_status_buffer, ensure_ascii=False))
    except redis.RedisError:
        pass


# 初始化 ChromaDB 本地记忆库
print("🧠 正在加载记忆库...")
chroma_client = chromadb.PersistentClient(path="./red_team_memory")
memory_collection = chroma_client.get_or_create_collection(name="experiences")

# 更新 Agent 角色库
AGENTS = {
    "Recon": {"system": "你是红队侦察兵。请调用 Nmap 扫描 " + TARGET_IP + "，并总结出哪些端口开放。"},
    "Attack": {"system": "你是红队突击手。目标 URL 是 http://" + TARGET_IP + ":" + str(NGINX_PORT) + "/query。请尝试 SQL 注入。如果收到了 FLAG，直接返回 FLAG。如果报错或未发现 FLAG，请直接回答：【攻击失败】。"},
        "Explore": {"system": "你是红队情报员。请调用 dir_search 扫描 http://" + TARGET_IP + ":" + str(NGINX_PORT) + "。如果发现后台路径，请输出完整的 URL（必须带 http://）。"},
    "Exploit_Admin": {"system": "你是红队突击手。请调用 admin_login 工具，目标 URL 是 http://" + TARGET_IP + ":" + str(NGINX_PORT) + "/login，账号密码是 admin / Admin@2026。登录成功后，立刻调用 fetch_admin_flag 工具访问 http://" + TARGET_IP + ":" + str(NGINX_PORT) + "/admin/get_flag，获取真正的 FLAG。"},
    "Report": {"system": "你是红队书记员。根据前面的过程，生成一份简短的安全评估结论。"},
     "VulnScan": {"system": "你是红队漏洞扫描专家。请调用 run_nuclei_scan 工具对 http://127.0.0.1:8080 进行漏洞扫描，并总结发现的漏洞。"}
}

# 各 Agent 在"开始思考"时的状态文案, 让大屏一眼看出当前谁在干活
AGENT_STATUS_LABEL = {
    "Recon": "🔍 侦察兵启动: 端口与目录扫描中",
    "Attack": "⚔️ 突击手启动: 尝试 SQL 注入",
    "Explore": "🧭 情报员启动: 目录爆破寻找新入口",
    "Exploit_Admin": "🥷 横向渗透: 后台弱口令爆破中",
    "Report": "📝 书记员: 生成评估报告",
}

async def run_agent_step(agent_name, user_goal, session, tools):
    system_prompt = AGENTS[agent_name]["system"]
    
    # 🚨 Harness 层的硬控：根据 Agent 角色，限制它能使用的工具！
    allowed_tools = []
    if agent_name == "Recon":
        allowed_tools = ["scan_ports"]
    elif agent_name == "Attack":
        allowed_tools = ["check_sql_vulnerability"]
    elif agent_name == "Explore":
        allowed_tools = ["dir_search"]
    elif agent_name == "VulnScan":
        # 到了 Nuclei 阶段，大模型只能调 Nuclei，绝对不能调 admin_login！
        allowed_tools = ["run_nuclei_scan"]
    elif agent_name == "Exploit_Admin":
        allowed_tools = ["admin_login", "fetch_admin_flag"]
        
    # 过滤工具列表，只把白名单里的工具喂给大模型
    filtered_tools = [t for t in tools if t.name in allowed_tools]
    ollama_tools = [{"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.inputSchema}} for t in filtered_tools]

    messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_goal}]

    step = 1
    while step <= 4:
        print(f"\n--- [{agent_name}] 思考中 (第 {step} 轮) ---")
        resp = requests.post(OLLAMA_URL, json={"model": MODEL, "messages": messages, "tools": ollama_tools, "stream": False}, timeout=120).json()
        msg = resp.get("message", {})
        messages.append(msg)

        if "tool_calls" in msg and msg["tool_calls"]:
            for tool_call in msg["tool_calls"]:
                func_name = tool_call["function"]["name"]
                args = tool_call["function"]["arguments"]
                print(f"🤖 [{agent_name}] 调用工具: {func_name}")

                # 📡 上报: 具体调用了哪个武器
                push_status(f"🧨 [{agent_name}] 调用武器: {func_name}")

                try:
                    result = await session.call_tool(func_name, arguments=args)
                    result_text = result.content[0].text
                    print(f"📄 [返回结果截取]: {result_text[:100].strip()}...")

                    # 🚨 2. 记记忆：如果工具报错了，把它记进错题本！
                    if "错误" in result_text or "失败" in result_text or "502" in result_text:
                        exp = f"尝试调用 {func_name} 时发生错误，报错内容：{result_text}"
                        memory_collection.add(documents=[exp], ids=[f"exp_{len(memory_collection.get()['ids']) + 1}"])
                        print(f"💾 [系统] 记录新错题至记忆库！")
                        # 📡 上报: 工具失败
                        push_status(f"❌ [{agent_name}] {func_name} 执行失败, 已记入错题本")

                    # 📡 上报: 命中 FLAG 的瞬间(高亮红)
                    if "FLAG{" in result_text:
                        flag_preview = result_text[result_text.find("FLAG{"):result_text.find("FLAG{") + 40]
                        push_status(f"🚩 捕获 FLAG: {flag_preview}")

                    messages.append({"role": "tool", "content": result_text})
                except Exception as e:
                    messages.append({"role": "tool", "content": f"失败: {e}"})
                    # 📡 上报: 调用工具时异常
                    push_status(f"💥 [{agent_name}] {func_name} 调用异常: {str(e)[:40]}")
        else:
            final_content = msg.get('content', '')
            print(f"✅ [{agent_name}] 最终结论: {final_content}")
            # 📡 上报: 该 Agent 给出结论(截断避免过长)
            summary = final_content.replace("\n", " ")[:60]
            push_status(f"✅ [{agent_name}] 结论: {summary}")
            return final_content
        step += 1
    return "Agent 超出思考上限。"

async def main():
    server_params = StdioServerParameters(command="python", args=["red_team_agent/tools_server.py"])
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = (await session.list_tools()).tools
            
            print("========== [开始渗透任务] ==========")
            
            # 1. 侦察阶段
            recon = await run_agent_step("Recon", "请扫描目标 127.0.0.1", session, tools)
            
            # 2. 攻击阶段
            attack_result = await run_agent_step("Attack", f"侦察情报：{recon}\n请立刻发起 SQL 注入攻击。", session, tools)
            
            # 🚨 核心逻辑：判断是否拿到 FLAG
            if "FLAG{" not in attack_result:
                print("\n⚠️ [系统判定] SQL 注入未能获取 FLAG。触发状态回退，切换攻击路径...")
                
                # 3. 代码硬控：直接调用 dir_search（秒回）
                print("\n🔍 [系统硬控] 强制调用目录扫描工具...")
                dir_res = await session.call_tool("dir_search", arguments={"url": "http://127.0.0.1:8080"})
                explore_info = dir_res.content[0].text
                print(f"📄 [目录扫描结果]: {explore_info}")
                
                # 4. 真实调用大模型去执行 Nuclei
                print("\n🔍 [系统调度] 呼叫 Nuclei 工业级漏扫...")
                vuln_scan_info = await run_agent_step("VulnScan", "请调用 Nuclei 扫描工具探测目标漏洞。", session, tools)
                
                # 5. 突击手出场，直接喂饭（带上准确的 URL）
                context_for_attack = f"情报显示：发现后台路径 http://127.0.0.1:8080/login。请立刻调用 admin_login 工具，传入正确的 URL、账号 admin、密码 Admin@2026。成功后立刻调用 fetch_admin_flag 访问 http://127.0.0.1:8080/admin/get_flag。"
                
                exploit = await run_agent_step("Exploit_Admin", context_for_attack, session, tools)
                final_result = f"新路径结果：{exploit}"
            else:
                print("\n✅ [系统判定] 首次攻击成功拿到 FLAG！")
                final_result = attack_result
                
            # 6. 生成报告
            await run_agent_step("Report", f"攻击过程结果：{final_result}", session, tools)
            print("\n========== [渗透任务结束] ==========")

if __name__ == "__main__":
    asyncio.run(main())