#!/usr/bin/env python3
# 屏幕共享信令服务器（自动打开前端 + 传递设备名/IP）
# 仅使用 Python 标准库，无第三方依赖
# 启动: python server.py

import asyncio
import hashlib
import base64
import struct
import json
import os
import sys
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading

# ---------- 简易 WebSocket 实现 ----------
class SimpleWebSocket:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self._handshake_done = False
        # 获取客户端 IP 地址
        peername = writer.get_extra_info('peername')
        self.client_ip = peername[0] if peername else 'unknown'

    async def handshake(self):
        request = await self.reader.readuntil(b'\r\n\r\n')
        headers = request.decode(errors='ignore')
        if 'Upgrade: websocket' not in headers:
            self.writer.close()
            return False
        key = None
        for line in headers.split('\r\n'):
            if line.lower().startswith('sec-websocket-key:'):
                key = line.split(':', 1)[1].strip()
                break
        if not key:
            self.writer.close()
            return False
        GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        response = (
            'HTTP/1.1 101 Switching Protocols\r\n'
            'Upgrade: websocket\r\n'
            'Connection: Upgrade\r\n'
            f'Sec-WebSocket-Accept: {accept}\r\n\r\n'
        ).encode()
        self.writer.write(response)
        await self.writer.drain()
        self._handshake_done = True
        return True

    async def recv(self):
        try:
            header = await self.reader.readexactly(2)
            byte1, byte2 = header[0], header[1]
            opcode = byte1 & 0x0F
            if opcode == 8:
                return None
            masked = (byte2 & 0x80) != 0
            payload_len = byte2 & 0x7F
            if payload_len == 126:
                ext = await self.reader.readexactly(2)
                payload_len = struct.unpack('!H', ext)[0]
            elif payload_len == 127:
                ext = await self.reader.readexactly(8)
                payload_len = struct.unpack('!Q', ext)[0]
            mask = await self.reader.readexactly(4) if masked else None
            data = await self.reader.readexactly(payload_len)
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            return data.decode('utf-8')
        except (asyncio.IncompleteReadError, ConnectionError):
            return None

    async def send(self, message: str):
        data = message.encode('utf-8')
        frame = bytearray()
        frame.append(0x81)
        length = len(data)
        if length <= 125:
            frame.append(length)
        elif length <= 65535:
            frame.append(126)
            frame.extend(struct.pack('!H', length))
        else:
            frame.append(127)
            frame.extend(struct.pack('!Q', length))
        frame.extend(data)
        self.writer.write(frame)
        await self.writer.drain()

    async def close(self):
        try:
            frame = bytearray([0x88, 0x00])
            self.writer.write(frame)
            await self.writer.drain()
        except Exception:
            pass
        finally:
            self.writer.close()

# ---------- 房间与信令逻辑 ----------
class Room:
    def __init__(self):
        self.sockets = {}

class SignalingServer:
    def __init__(self, host='0.0.0.0', port=3000):
        self.host = host
        self.port = port
        self.rooms = {}
        self.peers = {}
        self._next_peer_id = 1

    async def handle_client(self, reader, writer):
        ws = SimpleWebSocket(reader, writer)
        peer_id = f'peer_{self._next_peer_id}'
        self._next_peer_id += 1
        self.peers[ws] = {'room_id': None, 'peer_id': peer_id, 'is_sharing': False, 'ip': ws.client_ip, 'device_name': peer_id}

        try:
            if not await ws.handshake():
                return
            print(f'[+] {peer_id} 已连接 (IP: {ws.client_ip})')

            while True:
                msg_text = await ws.recv()
                if msg_text is None:
                    break
                try:
                    msg = json.loads(msg_text)
                except Exception:
                    continue
                await self.process_message(ws, msg)

        except Exception as e:
            print(f'[-] {peer_id} 异常断开: {e}')
        finally:
            await self.remove_peer(ws)

    async def process_message(self, ws, msg):
        info = self.peers.get(ws)
        if not info:
            return

        msg_type = msg.get('type')
        if msg_type == 'join':
            room_id = msg.get('room')
            device_name = msg.get('deviceName', info['peer_id'])
            info['device_name'] = device_name
            if not room_id:
                return
            await self.leave_room(ws)
            if room_id not in self.rooms:
                self.rooms[room_id] = Room()
            room = self.rooms[room_id]
            info['room_id'] = room_id
            room.sockets[info['peer_id']] = ws

            # 构建成员列表（包含设备名和IP）
            members = []
            for pid, sock in room.sockets.items():
                if pid != info['peer_id']:
                    pinfo = self.peers[sock]
                    members.append({
                        'peerId': pid,
                        'isSharing': pinfo['is_sharing'],
                        'deviceName': pinfo['device_name'],
                        'ip': pinfo['ip']
                    })
            await self.send_to(ws, {
                'type': 'room-joined',
                'peerId': info['peer_id'],
                'members': members,
                'ownIp': info['ip']
            })

            # 通知其他成员
            await self.broadcast(room_id, ws, {
                'type': 'peer-joined',
                'peerId': info['peer_id'],
                'isSharing': False,
                'deviceName': device_name,
                'ip': info['ip']
            })
            print(f'[→] {info["peer_id"]} 加入房间 {room_id}')

        elif msg_type in ('offer', 'answer', 'ice-candidate'):
            target_id = msg.get('target')
            room_id = info['room_id']
            if not room_id or not target_id:
                return
            room = self.rooms.get(room_id)
            if not room:
                return
            target_ws = room.sockets.get(target_id)
            if target_ws:
                await self.send_to(target_ws, {**msg, 'sender': info['peer_id']})

        elif msg_type == 'share-start':
            info['is_sharing'] = True
            room_id = info['room_id']
            if room_id:
                await self.broadcast(room_id, ws, {
                    'type': 'peer-share-start',
                    'peerId': info['peer_id']
                })
                await self.broadcast(room_id, ws, {
                    'type': 'member-update',
                    'peerId': info['peer_id'],
                    'isSharing': True
                })

        elif msg_type == 'share-stop':
            info['is_sharing'] = False
            room_id = info['room_id']
            if room_id:
                await self.broadcast(room_id, ws, {
                    'type': 'peer-share-stop',
                    'peerId': info['peer_id']
                })
                await self.broadcast(room_id, ws, {
                    'type': 'member-update',
                    'peerId': info['peer_id'],
                    'isSharing': False
                })

    async def leave_room(self, ws):
        info = self.peers.get(ws)
        if not info or not info['room_id']:
            return
        room_id = info['room_id']
        if room_id in self.rooms:
            room = self.rooms[room_id]
            if info['peer_id'] in room.sockets:
                del room.sockets[info['peer_id']]
            if not room.sockets:
                del self.rooms[room_id]
            else:
                await self.broadcast(room_id, ws, {
                    'type': 'peer-left',
                    'peerId': info['peer_id']
                })
        info['room_id'] = None
        info['is_sharing'] = False

    async def remove_peer(self, ws):
        info = self.peers.pop(ws, None)
        if not info:
            return
        await self.leave_room(ws)
        try:
            await ws.close()
        except Exception:
            pass
        print(f'[-] {info["peer_id"]} 已断开')

    async def send_to(self, ws, message):
        try:
            await ws.send(json.dumps(message))
        except Exception:
            pass

    async def broadcast(self, room_id, exclude_ws, message):
        room = self.rooms.get(room_id)
        if not room:
            return
        for sock in room.sockets.values():
            if sock is not exclude_ws:
                await self.send_to(sock, message)

    async def start(self):
        server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        print(f'🚀 信令服务器已启动 -> ws://{self.host}:{self.port}')
        async with server:
            await server.serve_forever()

# ---------- HTTP 静态文件服务器 ----------
def start_http_server(port=8080):
    """启动简单的 HTTP 服务器用于托管前端页面"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    handler = SimpleHTTPRequestHandler
    httpd = HTTPServer(('localhost', port), handler)
    print(f'🌐 静态文件服务已启动 -> http://localhost:{port}/index.html')
    thread = threading.Thread(target=httpd.serve_forever)
    thread.daemon = True
    thread.start()
    return httpd

if __name__ == '__main__':
    # 启动 HTTP 服务器（端口 8080）
    httpd = start_http_server(8080)
    # 自动打开浏览器（自动连接参数 ?auto=1）
    url = 'http://localhost:8080/index.html?auto=1'
    print(f'📂 正在打开浏览器: {url}')
    webbrowser.open(url)
    # 启动信令服务器（端口 3000）
    srv = SignalingServer('0.0.0.0', 3000)
    asyncio.run(srv.start())