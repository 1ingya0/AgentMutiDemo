# 测试用例 1：Web 靶场自动化攻击测试
import subprocess
import os

print("启动 Web 靶场攻击测试...")
# 直接调用红队多智能体大脑
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
subprocess.run(["python", "red_team_agent/harness_brain.py"])