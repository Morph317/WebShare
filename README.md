# WebShare

基于 SFU 架构的浏览器屏幕共享应用。共享端将屏幕流推送到 mediasoup 服务器，由服务器转发给所有观看端。

- **前端**: Vue 3 + TypeScript + Vite
- **后端**: Node.js + Express + mediasoup
- **信令**: WebSocket

## 开发

```bash
# 终端 1: 信令 + SFU 服务器
cd server && npm run dev

# 终端 2: 前端开发服务器
cd client && npm run dev
```

浏览器打开 `http://localhost:5173`，页面自动连接服务器。

## 生产部署 (Ubuntu 22.04/24.04)

```bash
# 1. 安装 Node.js >= 22
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs

# 2. 安装依赖
npm run install:all

# 3. 构建前端 + 启动服务
ANNOUNCED_IP=你的公网IP npm start
```

访问 `http://<服务器IP>:8080`

## 防火墙

| 端口 | 协议 | 用途 |
|------|------|------|
| 8080 | TCP | HTTP + WebSocket 信令 |
| 40000-49999 | UDP+TCP | mediasoup 媒体传输 |

```bash
sudo ufw allow 8080/tcp
sudo ufw allow 40000:49999/udp
sudo ufw allow 40000:49999/tcp
```

## 使用

1. 打开页面自动连接服务器
2. 点击"共享屏幕"开始共享
3. 其他成员看到缩略图，点击切换观看
