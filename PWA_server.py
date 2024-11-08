from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import os
import json
import base64
import secrets
import hashlib
import logging
from datetime import datetime

# 配置日志
logging.basicConfig(level=logging.DEBUG,
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='.')
CORS(app)

# 全局配置
RP_ID = "localhost"
RP_NAME = "WebAuthn Demo"
ORIGIN = "http://localhost:8080"

# 存储用户信息和挑战
users = {}
challenges = {}

def generate_challenge():
    """生成随机挑战值"""
    return secrets.token_bytes(32)

def base64url_encode(data):
    """Base64URL 编码"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    elif isinstance(data, bytes):
        pass
    else:
        data = str(data).encode('utf-8')
        
    encoded = base64.urlsafe_b64encode(data).decode('utf-8')
    return encoded.rstrip('=')

def base64url_decode(data):
    """Base64URL 解码"""
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)

def log_request_info(endpoint):
    """记录请求信息的装饰器"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            logger.info(f"\n{'='*20} {endpoint} 开始 {'='*20}")
            logger.debug(f"Method: {request.method}, Endpoint: {request.path}")
            if request.is_json:
                logger.debug(f"请求数据: {json.dumps(request.json, indent=2, ensure_ascii=False)}")
            result = f(*args, **kwargs)
            logger.info(f"{'='*20} {endpoint} 结束 {'='*20}\n")
            return result
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

@app.route('/register/begin', methods=['POST'])
@log_request_info('注册开始')
def register_begin():
    try:
        data = request.json
        username = data.get("username")

        if not username:
            logger.error("缺少用户名")
            return jsonify({"error": "Missing username"}), 400

        # 生成随机用户ID和挑战
        user_id = secrets.token_bytes(32)
        challenge = generate_challenge()

        logger.info(f"开始为用户 {username} 生成注册参数")

        # 保存挑战值以供后续验证
        challenges[username] = challenge

        # 构建注册请求数据
        publicKey = {
            "challenge": base64url_encode(challenge),
            "rp": {
                "name": RP_NAME,
                "id": RP_ID
            },
            "user": {
                "id": base64url_encode(user_id),
                "name": username,
                "displayName": username
            },
            "pubKeyCredParams": [
                {
                    "type": "public-key",
                    "alg": -7  # ES256
                }
            ],
            "timeout": 60000,
            "attestation": "none",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "userVerification": "preferred"
            }
        }

        # 保存用户信息
        users[username] = {
            "id": base64url_encode(user_id),
            "name": username,
            "registered": False
        }

        logger.info(f"成功生成用户 {username} 的注册参数")
        return jsonify({"publicKey": publicKey})

    except Exception as e:
        logger.error(f"注册开始阶段发生错误: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/register/complete', methods=['POST'])
@log_request_info('注册完成')
def register_complete():
    try:
        data = request.json
        username = data.get("username")
        credential = data.get("credential")

        if not username or not credential:
            logger.error("无效的注册数据")
            return jsonify({"error": "Invalid registration data"}), 400

        if username not in challenges:
            logger.error(f"未找到用户 {username} 的挑战值")
            return jsonify({"error": "No challenge found for user"}), 400

        logger.info(f"开始验证用户 {username} 的注册数据")

        # 解码客户端数据
        client_data_json = base64url_decode(credential["response"]["clientDataJSON"])
        client_data = json.loads(client_data_json)

        # 验证挑战值
        received_challenge = base64url_decode(client_data["challenge"])
        if received_challenge != challenges[username]:
            logger.error("挑战值验证失败")
            return jsonify({"error": "Challenge verification failed"}), 400

        # 验证origin
        if client_data["origin"] != ORIGIN:
            logger.error(f"Origin验证失败. 预期: {ORIGIN}, 实际: {client_data['origin']}")
            return jsonify({"error": "Origin verification failed"}), 400

        # 存储凭证信息
        users[username]["credential_id"] = credential["id"]
        users[username]["registered"] = True

        # 清理挑战值
        del challenges[username]
        logger.info(f"用户 {username} 注册成功")

        return jsonify({"message": "Registration successful"})

    except Exception as e:
        logger.error(f"注册完成阶段发生错误: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/authenticate/begin', methods=['POST'])
@log_request_info('认证开始')
def authenticate_begin():
    try:
        data = request.json
        username = data.get("username")

        if not username or username not in users:
            logger.error(f"用户 {username} 未找到")
            return jsonify({"error": "User not found"}), 404

        if not users[username].get("registered"):
            logger.error(f"用户 {username} 未注册")
            return jsonify({"error": "User not registered"}), 400

        logger.info(f"开始为用户 {username} 生成认证参数")

        # 生成新的挑战
        challenge = generate_challenge()
        challenges[username] = challenge

        # 构建认证请求数据
        publicKey = {
            "challenge": base64url_encode(challenge),
            "timeout": 60000,
            "rpId": RP_ID,
            "allowCredentials": [
                {
                    "type": "public-key",
                    "id": users[username]["credential_id"]
                }
            ],
            "userVerification": "preferred"
        }

        logger.info(f"成功生成用户 {username} 的认证参数")
        return jsonify({"publicKey": publicKey})

    except Exception as e:
        logger.error(f"认证开始阶段发生错误: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/authenticate/complete', methods=['POST'])
@log_request_info('认证完成')
def authenticate_complete():
    try:
        data = request.json
        username = data.get("username")
        credential = data.get("credential")

        if not username or not credential:
            logger.error("无效的认证数据")
            return jsonify({"error": "Invalid authentication data"}), 400

        if username not in challenges:
            logger.error(f"未找到用户 {username} 的挑战值")
            return jsonify({"error": "No challenge found for user"}), 400

        logger.info(f"开始验证用户 {username} 的认证数据")

        # 解码并验证客户端数据
        client_data_json = base64url_decode(credential["response"]["clientDataJSON"])
        client_data = json.loads(client_data_json)

        # 验证挑战值
        received_challenge = base64url_decode(client_data["challenge"])
        if received_challenge != challenges[username]:
            logger.error("挑战值验证失败")
            return jsonify({"error": "Challenge verification failed"}), 400

        # 验证origin
        if client_data["origin"] != ORIGIN:
            logger.error(f"Origin验证失败. 预期: {ORIGIN}, 实际: {client_data['origin']}")
            return jsonify({"error": "Origin verification failed"}), 400

        # 验证凭证ID
        if credential["id"] != users[username]["credential_id"]:
            logger.error("无效的凭证ID")
            return jsonify({"error": "Invalid credential"}), 400

        # 清理挑战值
        del challenges[username]
        logger.info(f"用户 {username} 认证成功")

        return jsonify({"message": f"Welcome back, {username}!"})

    except Exception as e:
        logger.error(f"认证完成阶段发生错误: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('.', filename)

if __name__ == "__main__":
    logger.info("WebAuthn Demo 服务器启动")
    logger.info(f"RP_ID: {RP_ID}")
    logger.info(f"RP_NAME: {RP_NAME}")
    logger.info(f"ORIGIN: {ORIGIN}")
    app.run(debug=True, port=8080)