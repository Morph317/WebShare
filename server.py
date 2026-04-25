#!/usr/bin/env python3
# 极致轻量化 Radmin 屏幕共享信令服务器
# 仅使用 Python 标准库，无第三方依赖
# 启动: python server.py
# 默认监听 0.0.0.0:3000 (可在 Radmin 局域网内访问)

import asyncio
import hashlib
import base64
import struct
import json
import os

# ---------- WebSocket 简易实现 ----------
# 仅支持文本帧，用于小型信令消息（握手、帧解析）

class SimpleWebSocket:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self._handshake_done = False

    async def handshake(self):
        """处理 HTTP 升级到 WebSocket 的握手"""
        request = await self.reader.readuntil(b'\r\n\r\n')
        headers = request.decode(errors='ignore')
        if 'Upgrade: websocket' not in headers:
            self.writer.close()
            return False

        # 提取 Sec-WebSocket-Key
        key = None
        for line in headers.split('\r\n'):
            if line.lower().startswith('sec-websocket-key:'):
                key = line.split(':', 1)[1].strip()
                break
        if not key:
            self.writer.close()
            return False

        # 计算 Accept
        GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()

        # 回复 101
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
        """接收一帧文本消息，返回字符串；连接关闭返回 None"""
        try:
            # 读取前2字节基本帧头
            header = await self.reader.readexactly(2)
            byte1, byte2 = header[0], header[1]
            opcode = byte1 & 0x0F
            if opcode == 8:  # 关闭帧
                return None
            masked = (byte2 & 0x80) != 0
            payload_len = byte2 & 0x7F

            # 扩展长度
            if payload_len == 126:
                ext = await self.reader.readexactly(2)
                payload_len = struct.unpack('!H', ext)[0]
            elif payload_len == 127:
                ext = await self.reader.readexactly(8)
                payload_len = struct.unpack('!Q', ext)[0]

            # 掩码键
            if masked:
                mask = await self.reader.readexactly(4)
            else:
                mask = None

            # 读取数据
            data = await self.reader.readexactly(payload_len)
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))

            return data.decode('utf-8')
        except (asyncio.IncompleteReadError, ConnectionError):
            return None

    async def send(self, message: str):
        """发送文本帧"""
        data = message.encode('utf-8')
        frame = bytearray()
        frame.append(0x81)  # 文本帧，FIN=1
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
        """发送关闭帧并断开"""
        try:
            frame = bytearray([0x88, 0x00])  # 关闭帧
            self.writer.write(frame)
            await self.writer.drain()
        except Exception:
            pass
        finally:
            self.writer.close()

# ---------- 房间与信令逻辑 ----------
class Room:
    def __init__(self):
        self.sockets = {}  # peer_id -> SimpleWebSocket

class SignalingServer:
    def __init__(self, host='0.0.0.0', port=3000):
        self.host = host
        self.port = port
        self.rooms = {}          # room_id -> Room
        self.peers = {}          # SimpleWebSocket -> {room_id, peer_id, is_sharing}
        self._next_peer_id = 1

    async def handle_client(self, reader, writer):
        ws = SimpleWebSocket(reader, writer)
        peer_id = f'peer_{self._next_peer_id}'
        self._next_peer_id += 1
        self.peers[ws] = {'room_id': None, 'peer_id': peer_id, 'is_sharing': False}

        try:
            if not await ws.handshake():
                return
            print(f'[+] {peer_id} 已连接')

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
            if not room_id:
                return
            # 离开旧房间
            await self.leave_room(ws)
            # 加入新房间
            if room_id not in self.rooms:
                self.rooms[room_id] = Room()
            room = self.rooms[room_id]
            info['room_id'] = room_id
            room.sockets[info['peer_id']] = ws

            # 收集现有成员
            members = []
            for pid, sock in room.sockets.items():
                if pid != info['peer_id']:
                    members.append({
                        'peerId': pid,
                        'isSharing': self.peers[sock]['is_sharing']
                    })
            await self.send_to(ws, {
                'type': 'room-joined',
                'peerId': info['peer_id'],
                'members': members
            })

            # 通知其他人
            await self.broadcast(room_id, ws, {
                'type': 'peer-joined',
                'peerId': info['peer_id'],
                'isSharing': False
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
        print(f'🚀 信令服务器已启动 (纯Python标准库) -> ws://{self.host}:{self.port}')
        async with server:
            await server.serve_forever()

if __name__ == '__main__':
    srv = SignalingServer('0.0.0.0', 3000)
    asyncio.run(srv.start())