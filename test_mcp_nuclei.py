import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def test_mcp_tool():
    print("🔍 [单测] 正在启动 MCP Server 子进程...")
    # 1. 启动武器库
    server_params = StdioServerParameters(
        command="python", 
        args=["red_team_agent/tools_server.py"]
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("✅ [单测] MCP 握手成功！")
            
            # 2. 打印当前加载了哪些工具
            tools = (await session.list_tools()).tools
            print(f"✅ [单测] 成功加载 {len(tools)} 个工具: {[t.name for t in tools]}")
            
            # 3. 单点爆破：直接强行调用 run_nuclei_scan
            print("\n🚀 [单测] 开始强行调用 run_nuclei_scan...")
            print("⏳ 注意看这里会不会卡住...")
            
            try:
                result = await session.call_tool("run_nuclei_scan", arguments={"target_url": "http://127.0.0.1:8080"})
                print("\n🎉 [单测] run_nuclei_scan 成功返回！")
                print(f"📄 [单测] 返回结果: {result.content[0].text}")
            except Exception as e:
                print(f"\n❌ [单测] 调用失败，报错: {e}")

if __name__ == "__main__":
    asyncio.run(test_mcp_tool())