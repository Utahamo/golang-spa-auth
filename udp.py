import socket
import time
import json
import base64
import hmac
import hashlib
import sys

# 配置
SERVER_IP = "192.168.43.90"  # 服务器IP
UDP_PORT = 9000          # UDP敲门端口
CLIENT_KEY = "client_secret_key"  # 客户端密钥

# 准备敲门数据包
timestamp = int(time.time())
data = f"{CLIENT_KEY}|127.0.0.1|{timestamp}"
h = hmac.new(b"server_secret_key", data.encode(), hashlib.sha256)
signature = base64.b64encode(h.digest()).decode()

knock_packet = {
    "client_key": CLIENT_KEY,
    "client_ip": "127.0.0.1", 
    "timestamp": timestamp,
    "signature": signature
}

# 创建UDP套接字
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    # 发送UDP敲门请求
    packet = json.dumps(knock_packet).encode()
    print(f"发送UDP敲门数据包到 {SERVER_IP}:{UDP_PORT}")
    sock.sendto(packet, (SERVER_IP, UDP_PORT))

    # 设置接收超时
    sock.settimeout(5)

    # 接收响应
    data, addr = sock.recvfrom(1024)
    response = json.loads(data.decode())
    print(f"收到响应: {response}")
    print(f"分配的TCP端口: {response['port']}")
    print(f"有效期: {response['expires_in']}秒")

except socket.timeout:
    print("超时: 服务器没有响应")
except Exception as e:
    print(f"错误: {e}")
finally:
    sock.close()