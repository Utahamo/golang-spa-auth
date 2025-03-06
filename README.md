# SPA 单包授权系统

本项目实现了一个基于单包授权(SPA)和 JWT 的分层安全认证系统，使用 Go 语言和 Gin 框架开发。它采用"先认证后连接"的安全模型，结合了网络层的 UDP 敲门机制和应用层的 JWT 令牌验证，为网络服务提供强大的安全保障。

## 项目架构

```
golang-spa-auth/

├── client/
│   ├── css/
│   │   └── style.css           # 样式文件
│   ├── js/
│   │   └── app.js              # 客户端JavaScript逻辑
│   ├── index.html              # JWT认证演示页面
│   └── spa_client.html         # SPA单包授权演示界面
├── server/
│   ├── auth/
│   │   └── auth.go             # JWT令牌生成和验证
│   ├── handlers/
│   │   └── handlers.go         # HTTP请求处理函数
│   ├── middleware/
│   │   └── middleware.go       # JWT验证中间件
│   ├── spa/
│   │   └── spa_auth.go         # SPA单包授权核心实现
│   └── main.go                 # 服务器入口程序
├── udp.py                      # UDP敲门Python客户端
├── go.mod                      # Go模块文件
├── go.sum                      # Go依赖版本
└── README.md                   # 项目文档
```

## 系统特点

- **双层安全架构**：结合 UDP 敲门授权和 JWT 令牌验证
- **动态端口分配**：每次认证成功分配一个临时随机端口
- **IP 限制**：分配的端口仅对特定 IP 地址开放
- **时效性控制**：端口授权有严格的时间限制
- **签名验证**：使用 HMAC-SHA256 对敲门请求进行签名验证
- **可视化演示**：直观展示完整的授权流程

## 运行环境要求

- Go 语言环境(版本 1.16 或更高)
- 现代 Web 浏览器
- Python 3.x (用于真实 UDP 敲门测试，可选)

## 快速开始

### 启动服务器

```
cd server

go run main.go
```

服务器将在`http://localhost:8080`启动，并监听 UDP 端口 9000 用于 SPA 敲门。

### 访问客户端

1. 打开 JWT 认证演示:
   http://localhost:8080/index.html
2. 打开 SPA 单包授权演示:
   http://localhost:8080/spa_client.html

## 使用说明

### SPA 单包授权流程

1. **第一阶段：UDP 敲门**

   - 配置服务器 IP、UDP 端口(9000)和客户端密钥
   - 发送敲门请求，获取临时 TCP 端口分配

2. **第二阶段：JWT 认证**

   - 连接到分配的临时端口
   - 获取 JWT 访问令牌
   - 使用令牌访问受保护资源

### 真实环境测试

使用 Python 脚本发送真实 UDP 敲门包:

```
python udp.py
```

此脚本将发送包含客户端密钥、时间戳和 HMAC 签名的 UDP 数据包，并接收服务器返回的端口分配信息。

## 许可

本项目采用 MIT 许可协议。详细信息请参阅 LICENSE 文件。
