import logging,sqlite3,sys
from pathlib import Path
from flask import Flask, jsonify, make_response, request

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config import WEB_PORT

# 创建 Web 应用并配置请求日志。
app = Flask(__name__)
logging.basicConfig(filename='web_access.log', level=logging.INFO, format='%(asctime)s %(message)s')

def init_db():
    """创建业务数据表，并确保示例用户记录存在。"""
    conn = sqlite3.connect('business.db')
    conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT, secret TEXT)')
    conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'alice', 'FLAG{sql_injection_success}')")
    conn.commit()
    conn.close()

@app.route('/query')
def query():
    # 之前的 SQL 注入漏洞保留
    name = request.args.get('name', '')
    # 使用参数化查询，将用户输入作为数据值处理。
    sql = "SELECT id, name, secret FROM users WHERE name = ?"
    logging.info(f"QUERY name={name}")
    try:
        # 执行查询并将结果转换为 JSON 响应。
        conn = sqlite3.connect('business.db')
        rows = conn.execute(sql).fetchall()
        conn.close()
        return jsonify({"result": rows})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    """校验登录信息，并在成功时返回带会话 Cookie 的响应。"""
    data = request.json
    if data.get('username') == 'admin' and data.get('password') == 'Admin@2026':
        # 登录成功后设置会话 Cookie。
        resp = make_response(jsonify({"message": "登录成功"}))
        resp.set_cookie('session_token', 'secret_admin_token_123')
        return resp
    return jsonify({"error": "账号或密码错误"}), 401

@app.route('/admin/get_flag')
def admin_get_flag():
    """验证请求中的会话 Cookie 后返回后台示例数据。"""
    token = request.cookies.get('session_token')
    if token == 'secret_admin_token_123':
        return jsonify({"FLAG": "FLAG{admin_session_hijack_success}"})
    return jsonify({"error": "未授权，请先登录"}), 403

if __name__ == '__main__':
    init_db()
    print(f"Web 靶场已启动，端口 {WEB_PORT}")
    app.run(port=WEB_PORT)