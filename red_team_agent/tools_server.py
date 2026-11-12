"""项目隔离测试环境使用的 MCP 服务端。

本模块负责注册可调用的工具、在请求之间共享 HTTP 会话状态，并将工具结果
返回给协调客户端。直接运行本文件时会启动 MCP 服务；仅用于经授权的隔离测试环境。
"""

import sys
import os
import subprocess
import requests
from mcp.server.fastmcp import FastMCP
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import TARGET_IP, WEB_PORT

mcp = FastMCP("Security-Tools")

# 🚨 核心：全局 Session 对象，自动保存和发送 Cookie
GLOBAL_SESSION = requests.Session()

@mcp.tool()
def scan_ports(ip: str) -> str:
    """使用 Nmap 扫描指定 IP 的端口。"""
    try:
        cmd = f"nmap -sV -Pn -p 1-100,{WEB_PORT} {ip}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        return result.stdout
    except Exception as e:
        return f"扫描失败: {e}"

@mcp.tool()
def check_sql_vulnerability(url: str, payload: str) -> str:
    """测试 SQL 注入。"""
    try:
        r = GLOBAL_SESSION.get(url, params={"name": payload}, timeout=10)
        return f"HTTP {r.status_code} 响应内容: {r.text[:300]}"
    except Exception as e:
        return f"请求失败: {e}"

@mcp.tool()
def dir_search(url: str) -> str:
    """扫描目录。"""
    return f"发现敏感路径: http://{TARGET_IP}:{WEB_PORT}/admin/get_flag"

@mcp.tool()
def admin_login(url: str, username: str, password: str) -> str:
    """尝试登录。成功会自动保存 Cookie 到 Session 中。"""
    print(f"\n[MCP Server] 尝试使用 {username}/{password} 登录 {url}...")
    try:
        # 使用 GLOBAL_SESSION 发送 POST 请求
        r = GLOBAL_SESSION.post(url, json={"username": username, "password": password}, timeout=10)
        if r.status_code == 200:
            return "登录成功！Cookie 已自动保存至会话中。"
        else:
            return f"登录失败: {r.text}"
    except Exception as e:
        return f"请求失败: {e}"

@mcp.tool()
def fetch_admin_flag(url: str) -> str:
    """访问后台接口获取 Flag。会自动携带之前保存的 Cookie。"""
    print(f"\n[MCP Server] 正在带着 Cookie 访问 {url}...")
    try:
        # 使用 GLOBAL_SESSION 发送 GET 请求，它会自动带上刚才登录成功的 Cookie
        r = GLOBAL_SESSION.get(url, timeout=10)
        return f"HTTP {r.status_code} 响应内容: {r.text}"
    except Exception as e:
        return f"请求失败: {e}"

import os
import subprocess

@mcp.tool()
def run_nuclei_scan(target_url: str) -> str:
    """使用 Nuclei 工业级漏洞扫描器对目标进行极速扫描。"""
    print(f"\n[MCP Server] 正在调用 Nuclei 极速扫描 {target_url}...")
    
    output_file = r"F:\AgentMutiDemo\tools\nuclei_result.txt"
    nuclei_exe = r"F:\AgentMutiDemo\tools\nuclei.exe"
    
    if os.path.exists(output_file):
        os.remove(output_file)

    # 加上 -nc (no color) 禁用颜色代码，防止污染 MCP 协议
    cmd = f'"{nuclei_exe}" -u {target_url} -silent -severity medium,high,critical -tags cve -rate-limit 100 -timeout 3 -duc -nc > "{output_file}" 2>&1'
    
    try:
        subprocess.run(cmd, shell=True, timeout=40)
        
        if not os.path.exists(output_file):
            return "Nuclei 扫描完毕，未生成报告。"
            
        with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
            output = f.read().strip()
            
        if not output:
            return "Nuclei 极速扫描完毕，未发现明显的已知 CVE 漏洞。"
            
        valuable_lines = [line for line in output.split('\n') if "[CVE-" in line or "[vulnerability]" in line or "[high]" in line]
        
        if valuable_lines:
            return "Nuclei 发现以下高危漏洞:\n" + "\n".join(valuable_lines[:5])
        else:
            return "Nuclei 扫描完成，未发现明显 CVE，建议直接尝试后台弱口令。"
            
    except subprocess.TimeoutExpired:
        print("\n⚠️ [MCP Server] Nuclei 执行超时，强制结束！")
        return "Nuclei 扫描超时。建议直接尝试后台弱口令爆破。"

if __name__ == "__main__":
    mcp.run()