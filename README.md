# 🛡️ AgentMutiDemo: 基于大模型与 MCP 协议的智能红蓝对抗靶场

> **项目定位**：一个基于多智能体（Multi-Agent）、MCP (Model Context Protocol) 协议与 RAG（检索增强生成）技术构建的微型企业级自动化攻防演练平台。
> 
> **项目目标**：在 AI 时代，探索大模型在自动化渗透测试（Red Teaming）与安全防御（Blue Teaming）中的实际应用与落地边界。系统涵盖了传统 Web 漏洞、AI 提示词注入、会话横向移动等高阶攻防场景，并实现了底层日志采集、告警降噪与联动防御的完整闭环。

---

## 🏗️ 一、 核心架构设计

本系统采用**高内聚、低耦合**的微服务架构，分为四大核心层：

### 1. 基础设施与监控层 (Infrastructure)
*   **Nginx 网关**：作为反向代理，监听 8080 端口。负责将红队火力转发至后端业务靶场，并记录全量 HTTP 深度审计日志。
*   **Redis 消息队列**：作为蓝队的数据总线，解耦日志采集与研判分析，防止高并发攻击导致日志丢失。

### 2. 业务靶场层 (Business Targets)
*   **传统 Web 靶场 (5001 端口)**：基于 Flask 构建。预设了 SQL 注入漏洞以及包含弱口令的 `/login` 后台接口。接口通过 Cookie 鉴权，用于测试红队的横向移动能力。
*   **AI 智能体靶场 (5003 端口)**：接入了本地 ChromaDB 向量数据库。模拟企业 AI 客服的 RAG 检索过程。包含“间接提示词注入（恶意文档投毒）”漏洞，并内置了基于正则的工程护栏进行兜底。

### 3. 红队攻击智能体层 (Red Team Agent)
*   **MCP 武器库 (tools_server.py)**：遵循 MCP 协议封装了 Nmap 扫描、SQL 注入、目录爆破及弱口令爆破等工具。利用 `requests.Session` 实现会话保持（Cookie 维持）。
*   **多智能体大脑 (harness_brain.py)**：包含 `Recon`（侦察）、`Attack`（突击）、`Explore`（情报）、`Exploit_Admin`（横向渗透）等角色。通过 Python 状态机控制各角色的流转与回退。

### 4. 蓝队防御智能体层 (Blue Team SOC)
*   **日志采集器 (collector.py)**：实时监控 Nginx 日志的增量变化，清洗后推入 Redis 队列。
*   **研判分析器 (analyzer.py)**：从 Redis 拉取日志，利用正则特征匹配攻击。采用**滑动时间窗口算法**实现告警聚合降噪，并联动飞书 Webhook 发送警报。达到阈值后，具备自动封禁 IP 的逻辑。

---

## 💡 二、 核心攻防亮点 (Kill Chain 解析)

*   **⚔️ 动态状态机回退 (Adaptive Fallback)**：
    当红队突击手正面强攻 SQL 注入失败（被参数化查询拦截）时，Python 状态机检测到未获取到 Flag，自动触发战术回退。调度 `Explore` 智能体扫描后台敏感目录，随后指挥 `Exploit_Admin` 进行弱口令爆破。
*   **🥷 会话保持与横向移动 (Lateral Movement)**：
    红队 MCP 工具放弃了低效的单次请求，改用 `requests.Session()` 维持状态。在利用 `admin/Admin@2026` 弱口令登录成功并吃下 `Set-Cookie` 后，无缝调用后续接口，带着 Cookie 成功打穿后台，获取机密 Flag。
*   **☠️ RAG 知识库投毒与防御 (Indirect Prompt Injection)**：
    红队通过上传带有隐藏指令（如 `<system>` 标签）的恶意文档，诱导系统自动切片入库。当 14B 模型检索到该毒药文档时，防线被撕破并试图输出 Flag。但在最后一毫秒，被业务代码中的正则规则强制拦截并脱敏。
*   **🧠 智能体记忆反思 (ChromaDB Memory)**：
    引入了向量数据库作为红队的“错题本”。当工具执行报错或攻击失败时，经验会被记录。下一轮攻击前，系统会自动检索历史错误，避免大模型陷入死循环或重复犯错。

---

## 🛠️ 三、 技术栈清单
*   **大模型基座**：Ollama (Qwen2.5:14b-instruct, nomic-embed-text)
*   **智能体协议**：MCP (Model Context Protocol)
*   **开发语言**：Python 3.10+
*   **Web 框架**：Flask
*   **中间件与数据库**：Nginx, Redis (Docker), ChromaDB, SQLite
*   **外部联动**：飞书 Webhook API

---

## 🚦 四、 快速启动指南

1. **启动基础设施**：
   * 确保 Docker 正在运行，启动 Redis：`docker run -d -p 6379:6379 --name my-redis redis`
   * 进入 nginx 目录，启动网关：`start nginx.exe`
2. **启动业务靶场**：
   * `python business_targets/web_target_5001.py`
   * `python business_targets/rag_ai_target_5003.py`
3. **启动蓝队防御**：
   * `python blue_team_soc/collector.py`
   * `python blue_team_soc/analyzer.py`
4. **启动红队智能化进攻**：
   * `python red_team_agent/harness_brain.py`

---

## 🐞 五、 开发复盘与踩坑实录

在开发过程中，遇到了诸多工程落地与 AI 环境的痛点，主要复盘如下：

1.  **大模型的“策略漂移”与幻觉**：
    *   **现象**：14B 模型在打 SQL 注入时，经常忽略环境提示，去尝试 SQLite 不支持的 `SLEEP()` 时间盲注，或者把 JSON 参数格式写错（如 `payloa` 未定义）。
    *   **解决**：不仅要在 Tool 描述中强约束数据库类型，还引入了 ChromaDB 向量库记录错误经验。系统通过 RAG 方式将“错误记录”注入系统提示词，模型看到踩坑记录后，会立刻收敛并改变策略。
2.  **Windows 环境下的编码与终端转义**：
    *   **现象**：使用 PowerShell 的 `curl.exe` 发送带有 `{}` 的 JSON Payload 给 RAG 靶场时，由于 Windows 终端对特殊字符的解析机制，导致请求被截断或转义失败。
    *   **解决**：放弃使用命令行测试，改用编写 `tests/run_rag_poison.py` 的 Python 脚本，利用 `requests` 库封装发包，彻底解决编码兼容问题。
3.  **底层抓包的环境妥协**：
    *   **现象**：尝试在 Windows 下使用 `scapy` 或 `pyshark` 监听 `localhost` 回环流量时，遭遇驱动权限和 Npcap Loopback 网卡适配等玄学问题，导致漏报。
    *   **解决**：在工程实现上放弃底层造轮子，改用“Nginx 深度日志（记录真实IP、耗时、UA）+ Redis 采集”的方案，证明了**“成熟的网关组件优于底层的折腾”**。
4.  **MCP 子进程通信的路径地雷**：
    *   **现象**：MCP 客户端拉起工具服务器时，由于 `python -m` 的模块化启动逻辑与子进程工作目录不一致，导致 `from config import...` 报错，引发 `Connection closed`。
    *   **解决**：删除了全局的 `config.py`，对 MCP Server 内的配置采用绝对硬编码，以确保底层通信的绝对稳定。

---

## ⚠️ 六、 免责声明
本项目所涉及的代码、漏洞靶场与技术文章，仅供**安全研究、技术学习与授权测试**使用。严禁在任何未经授权的真实网络环境中使用本项目的工具进行攻击。由于滥用本项目所导致的一切法律后果，由使用者自行承担。