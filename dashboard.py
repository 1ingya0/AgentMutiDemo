"""
🛡️ Agentic Security 实时红蓝对抗监控大屏 (Streamlit 版)

布局:
  顶部 3 个指标卡
  主体左右两栏, 每栏一个"命令行终端"组件
    左栏终端 = 红队动态 (读 Redis hash: red_team_status)
    右栏终端 = 蓝队告警 (读 Redis list: security_logs_archive)

关键点:
  - 每条日志保持"单行不折行", 长内容用横向滚动, 绝不截断
  - 蓝队读归档列表(analyzer 消费时留档), 避免 brpop 销毁导致读不到

依赖: pip install streamlit redis
运行: streamlit run dashboard.py
"""

import re
import time
import json

import redis
import streamlit as st

# ============================================================
# 0. 全局配置
# ============================================================
REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0

ARCHIVE_KEY = "security_logs_archive"   # 蓝队日志归档列表(analyzer 留档)
RED_STATUS_KEY = "red_team_status"      # 红队状态哈希
RED_STATUS_FIELD = "current"

BLUE_N = 500       # 蓝队终端最多读取并展示的条数(靠滚动查看全部)
RED_N = 50         # 红队终端最多展示的条数
REFRESH_SECONDS = "2s"

# 高亮 / 攻击特征关键词
HIGHLIGHT_KEYWORDS = ["FLAG", "AI_GUARD_BLOCKED"]
ATTACK_FEATURE_KEYWORDS = [
    "UNION", "SELECT", "OR 1=1", "' OR", "SLEEP(", "INJECT",
    "INJECTION", "PROMPT", "投毒", "<system>", "BRUTE", "爆破",
]

st.set_page_config(
    page_title="Agentic Security SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# 1. 深色科技风样式
# ============================================================
def inject_dark_theme() -> None:
    st.markdown(
        """
        <style>
        .stApp {
            background: radial-gradient(circle at 50% 0%, #0b1f33 0%, #050a12 60%, #02040a 100%);
            color: #d6e4f0;
        }
        .soc-title {
            text-align: center; font-size: 34px; font-weight: 800; letter-spacing: 2px;
            padding: 12px 0 4px 0;
            background: linear-gradient(90deg, #00e5ff, #4d7cff, #b14dff);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            text-shadow: 0 0 18px rgba(0, 229, 255, 0.35);
        }
        .soc-subtitle {
            text-align: center; color: #5f7d96; font-size: 13px;
            margin-bottom: 10px; letter-spacing: 1px;
        }
        div[data-testid="stMetric"] {
            background: rgba(15, 35, 55, 0.65);
            border: 1px solid rgba(0, 229, 255, 0.18);
            border-radius: 12px; padding: 14px 18px;
        }
        /* 命令行终端块 */
        .log-terminal {
            background: #05090f;
            border: 1px solid rgba(0, 229, 255, 0.22);
            border-radius: 10px;
            padding: 14px 16px;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.9;
            height: 540px;
            overflow-y: auto;      /* 纵向滚动看更多条 */
            overflow-x: auto;      /* 横向滚动看长日志, 不丢内容 */
        }
        /* 每条日志单行显示, 绝不折行/截断 */
        .log-line {
            white-space: nowrap;
            padding: 1px 0;
        }
        .log-prefix { color: #4d7cff; margin-right: 6px; user-select: none; }
        /* 美化滚动条 */
        .log-terminal::-webkit-scrollbar { width: 8px; height: 8px; }
        .log-terminal::-webkit-scrollbar-thumb {
            background: rgba(0, 229, 255, 0.25); border-radius: 4px;
        }
        .log-terminal::-webkit-scrollbar-track { background: transparent; }
        </style>
        """,
        unsafe_allow_html=True,
    )


# ============================================================
# 2. Redis 连接 (全应用只建一次)
# ============================================================
@st.cache_resource
def get_redis_client() -> redis.Redis:
    return redis.Redis(
        host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True
    )


# ============================================================
# 3. 数据读取
# ============================================================
def fetch_blue_logs(client: redis.Redis, n: int = BLUE_N) -> list[str]:
    """读取蓝队日志归档列表(最新在前)。analyzer 消费时留档, 所以能读全。"""
    try:
        return list(client.lrange(ARCHIVE_KEY, 0, n - 1))
    except redis.RedisError:
        return []


def fetch_red_status(client: redis.Redis) -> list[str]:
    """读取红队状态哈希里的 JSON 数组。"""
    try:
        raw = client.hget(RED_STATUS_KEY, RED_STATUS_FIELD)
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
            return [str(x) for x in parsed] if isinstance(parsed, list) else [raw]
        except json.JSONDecodeError:
            return [raw]
    except redis.RedisError:
        return []


# ============================================================
# 4. 判定工具
# ============================================================
def is_highlight(text: str) -> bool:
    up = text.upper()
    return any(kw.upper() in up for kw in HIGHLIGHT_KEYWORDS)


def is_attack(text: str) -> bool:
    up = text.upper()
    return any(kw.upper() in up for kw in ATTACK_FEATURE_KEYWORDS)


def extract_ip(text: str):
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    return m.group(0) if m else None


def compute_metrics(blue_logs: list[str], red_lines: list[str]) -> tuple[int, int, int]:
    """返回 (累计攻击数, AI护栏拦截数, 高危IP数)。"""
    attack = guard = 0
    ips = set()
    for log in blue_logs:
        if is_attack(log):
            attack += 1
        if "AI_GUARD_BLOCKED" in log.upper():
            guard += 1
        if is_highlight(log) or is_attack(log):
            ip = extract_ip(log)
            if ip:
                ips.add(ip)
    for line in red_lines:
        if "FLAG{" in line.upper():
            attack += 1
    return attack, guard, len(ips)


# ============================================================
# 5. 终端渲染
# ============================================================
def _pick_color(line: str, mode: str) -> str:
    """根据关键词和红/蓝模式来决定该行颜色。"""
    if is_highlight(line):
        return "#ff4d4f"                       # FLAG / 护栏拦截 -> 红
    if mode == "blue" and is_attack(line):
        return "#ff9f43"                       # 蓝队攻击特征 -> 橙
    if mode == "red":
        if "回退" in line or "失败" in line or "❌" in line or "💥" in line:
            return "#ffd93d"                   # 红队失败/回退 -> 黄
        if "✅" in line or "🚩" in line:
            return "#3ddc84"                   # 红队成功 -> 绿
        return "#4dd0e1"                       # 红队普通 -> 青
    return "#9fb3c8"                           # 蓝队普通 -> 灰蓝


def render_terminal(title: str, lines: list[str], mode: str) -> None:
    """把字符串列表渲染成命令行终端块, 每条日志完整单行显示。"""
    st.markdown(f"**{title}**")

    if not lines:
        st.markdown(
            '<div class="log-terminal">'
            '<span style="color:#5f7d96;"># 暂无数据 (Redis 为空或服务未启动)</span>'
            '</div>',
            unsafe_allow_html=True,
        )
        return

    rows = []
    for line in lines:
        # 仅转义 HTML 特殊字符, 不截断任何内容
        safe = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        color = _pick_color(line, mode)
        rows.append(
            f'<div class="log-line" style="color:{color};">'
            f'<span class="log-prefix">$</span>{safe}</div>'
        )

    html = '<div class="log-terminal">' + "".join(rows) + "</div>"
    st.markdown(html, unsafe_allow_html=True)


# ============================================================
# 6. 侧边栏
# ============================================================
def render_sidebar(client: redis.Redis) -> None:
    with st.sidebar:
        st.header("⚙️ 控制台")
        st.caption(f"Redis: {REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}")
        if st.button("🧹 一键清空日志", type="primary", use_container_width=True):
            try:
                d1 = client.delete(ARCHIVE_KEY)
                d2 = client.delete(RED_STATUS_KEY)
                st.success(f"已清空 (蓝队归档 {d1} key + 红队状态 {d2} key)")
            except redis.RedisError as e:
                st.error(f"清空失败: {e}")


# ============================================================
# 7. 主刷新区块 (每 2 秒局部刷新, 不卡死)
# ============================================================
@st.fragment(run_every=REFRESH_SECONDS)
def live_panel() -> None:
    client = get_redis_client()

    blue_logs = fetch_blue_logs(client)
    red_lines = fetch_red_status(client)

    # 顶部指标卡
    attack, guard, ips = compute_metrics(blue_logs, red_lines)
    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("🎯 累计捕获攻击数", attack)
    with c2:
        st.metric("🛡️ AI 护栏拦截数", guard)
    with c3:
        st.metric("🚨 高危 IP 数量", ips)
    st.divider()

    # 左右两栏, 每栏一个终端
    left, right = st.columns(2)
    with left:
        # 红队缓冲是追加式, 反转让最新在上
        render_terminal("⚔️ 红队动态 · 终端", list(reversed(red_lines))[:RED_N], mode="red")
    with right:
        # 归档列表本身最新在前
        render_terminal("🚨 蓝队告警 · 终端", blue_logs[:BLUE_N], mode="blue")

    st.caption(f"🕒 最近刷新: {time.strftime('%H:%M:%S')} · 每 {REFRESH_SECONDS} 自动刷新 | "
               f"红队 {len(red_lines)} 条 / 蓝队归档 {len(blue_logs)} 条")


# ============================================================
# 8. 入口
# ============================================================
def main() -> None:
    inject_dark_theme()
    st.markdown('<div class="soc-title">🛡️ Agentic Security 实时红蓝对抗监控大屏</div>',
                unsafe_allow_html=True)
    st.markdown('<div class="soc-subtitle">MULTI-AGENT RED / BLUE TEAM LIVE SOC</div>',
                unsafe_allow_html=True)

    client = get_redis_client()
    render_sidebar(client)
    live_panel()


if __name__ == "__main__":
    main()