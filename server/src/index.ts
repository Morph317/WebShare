import express from 'express';
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { execSync, spawn } from 'node:child_process';
import { WebSocketServer, WebSocket } from 'ws';
import * as mediasoup from 'mediasoup';
import { config } from './config';
import { Peer, Room } from './Room';
import { createWhipHandler, createTrickleHandler } from './Whip';

const LOG_DIR = path.join(__dirname, '..', 'logs');
const MAX_LOG_SIZE = 5 * 1024 * 1024; // 5MB

let logStream: fs.WriteStream | null = null;
let logPath = '';

function setupFileLogging(): void {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
  const date = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  logPath = path.join(LOG_DIR, `server-${date}.log`);
  logStream = fs.createWriteStream(logPath, { flags: 'a' });

  const origLog = console.log.bind(console);
  const origWarn = console.warn.bind(console);
  const origError = console.error.bind(console);

  function writeToFile(level: string, args: unknown[]): void {
    if (!logStream) return;
    const ts = new Date().toISOString();
    const msg = args.map(a => typeof a === 'string' ? a : JSON.stringify(a)).join(' ');
    logStream.write(`[${ts}] ${level} ${msg}\n`);
  }

  console.log = (...args: unknown[]) => {
    origLog(...args);
    writeToFile('INFO', args);
    checkLogSize();
  };
  console.warn = (...args: unknown[]) => {
    origWarn(...args);
    writeToFile('WARN', args);
  };
  console.error = (...args: unknown[]) => {
    origError(...args);
    writeToFile('ERROR', args);
  };
}

function checkLogSize(): void {
  if (!logStream || !logPath) return;
  try {
    const stat = fs.statSync(logPath);
    if (stat.size > MAX_LOG_SIZE) {
      const lines = fs.readFileSync(logPath, 'utf-8').split('\n');
      const trimmed = lines.slice(-Math.floor(lines.length / 2)).join('\n');
      logStream.end();
      logStream = fs.createWriteStream(logPath, { flags: 'w' });
      logStream.write(trimmed + '\n');
    }
  } catch {}
}

function getLogContent(tailLines?: number): string {
  if (!logPath || !fs.existsSync(logPath)) return '';
  const content = fs.readFileSync(logPath, 'utf-8');
  if (tailLines && tailLines > 0) {
    const lines = content.split('\n');
    return lines.slice(-tailLines).join('\n');
  }
  return content;
}

let worker: mediasoup.types.Worker;
const rooms: Map<string, Room> = new Map();
const peerMap: Map<string, Peer> = new Map();
const transportMap: Map<string, mediasoup.types.WebRtcTransport> = new Map();
const nextPeerId = { value: 1 };
let pendingRequestCount = 0;

async function initRoom(roomId: string): Promise<Room> {
  let room = rooms.get(roomId);
  if (!room) {
    const router = await worker.createRouter({
      mediaCodecs: config.mediasoup.router.mediaCodecs,
    });
    room = new Room(roomId, router);
    rooms.set(roomId, room);
  }
  return room;
}

function cleanupPeer(peer: Peer): void {
  const room = peer.room;
  if (room) {
    room.broadcast({ type: 'peer-left', peerId: peer.id }, peer.id);
    room.removePeer(peer.id);
    if (room.peers.size === 0) {
      room.close();
      rooms.delete(room.id);
    }
  }
  peerMap.delete(peer.id);
}

async function handleMessage(peer: Peer, raw: string): Promise<void> {
  let msg: { type: string; [key: string]: unknown };
  try {
    msg = JSON.parse(raw);
  } catch {
    peer.send({ type: 'error', message: 'Invalid JSON' });
    return;
  }

  try {
    switch (msg.type) {
      case 'join': {
        const roomId = (msg.roomId as string) || 'default';
        const displayName = (msg.displayName as string) || 'Unknown';
        peer.displayName = displayName;
        const room = await initRoom(roomId);
        room.addPeer(peer);

        peer.send({
          type: 'room-joined',
          peerId: peer.id,
          members: room.getMembers(),
          routerRtpCapabilities: room.router.rtpCapabilities,
          existingProducers: room.getProducers(),
        });

        room.broadcast(
          {
            type: 'peer-joined',
            peerId: peer.id,
            displayName: peer.displayName,
          },
          peer.id,
        );
        break;
      }

      case 'getRouterRtpCapabilities': {
        if (!peer.room) {
          peer.send({ type: 'error', message: 'Not in a room' });
          return;
        }
        peer.send({
          type: 'router-rtp-capabilities',
          rtpCapabilities: peer.room.router.rtpCapabilities,
        });
        break;
      }

      case 'createProducerTransport': {
        if (!peer.room) {
          peer.send({ type: 'error', message: 'Not in a room' });
          return;
        }

        const transport = await peer.room.router.createWebRtcTransport(
          config.mediasoup.webRtcTransport,
        );
        peer.producerTransport = transport;

        transport.on('@close', () => {
          peer.producerTransport = null;
        });

        transport.on('dtlsstatechange', (dtlsState) => {
          console.log(`[producer-transport dtls] ${transport.id} -> ${dtlsState}`);
        });
        transport.on('icestatechange', (iceState) => {
          console.log(`[producer-transport ice] ${transport.id} -> ${iceState}`);
        });

        peer.send({
          type: 'producer-transport-created',
          id: transport.id,
          iceParameters: transport.iceParameters,
          iceCandidates: transport.iceCandidates,
          dtlsParameters: transport.dtlsParameters,
        });
        break;
      }

      case 'connectProducerTransport': {
        const transport = peer.producerTransport;
        if (!transport) {
          peer.send({ type: 'error', message: 'No producer transport' });
          return;
        }
        await transport.connect({ dtlsParameters: msg.dtlsParameters as mediasoup.types.DtlsParameters });
        peer.send({ type: 'producer-transport-connected' });
        break;
      }

      case 'produce': {
        if (!peer.producerTransport) {
          peer.send({ type: 'error', message: 'No producer transport' });
          return;
        }
        const { kind, rtpParameters, appData } = msg;
        console.log(`[produce] peer=${peer.id} kind=${kind}`);
        const producer = await peer.producerTransport.produce({
          kind: kind as mediasoup.types.MediaKind,
          rtpParameters: rtpParameters as mediasoup.types.RtpParameters,
          appData: appData as mediasoup.types.AppData,
        });
        peer.producers.set(producer.id, producer);
        peer.isSharing = true;

        console.log(`[produce] producer=${producer.id} codec=${producer.rtpParameters.codecs?.[0]?.mimeType}`);

        setTimeout(async () => {
          try {
            if (producer.closed) return;
            const stats = await producer.getStats();
            console.log(`[producer stats @3s] ${producer.id}:`, JSON.stringify(stats));
          } catch {}
        }, 3000);

        setTimeout(async () => {
          try {
            if (producer.closed) return;
            const stats = await producer.getStats();
            console.log(`[producer stats @10s] ${producer.id}:`, JSON.stringify(stats));
          } catch {}
        }, 10000);

        producer.on('@close', () => {
          console.log(`[producer-closed] peer=${peer.id} producer=${producer.id}`);
          peer.producers.delete(producer.id);
          if (peer.producers.size === 0) {
            peer.isSharing = false;
          }
          peer.room?.broadcast(
            { type: 'producer-closed', producerId: producer.id, peerId: peer.id },
            peer.id,
          );
        });

        peer.send({ type: 'producer-created', producerId: producer.id, kind: producer.kind });
        console.log(`[produce] broadcast new-producer to room`);
        peer.room?.broadcast(
          { type: 'new-producer', producerId: producer.id, peerId: peer.id, kind: producer.kind },
          peer.id,
        );
        break;
      }

      case 'createConsumerTransport': {
        if (!peer.room) {
          peer.send({ type: 'error', message: 'Not in a room' });
          return;
        }

        const transport = await peer.room.router.createWebRtcTransport(
          config.mediasoup.webRtcTransport,
        );
        peer.consumerTransport = transport;
        console.log(`[consumer-transport created] peer=${peer.id} transport=${transport.id}`);

        transport.on('@close', () => {
          peer.consumerTransport = null;
        });

        transport.on('dtlsstatechange', (dtlsState) => {
          console.log(`[consumer-transport dtls] ${transport.id} -> ${dtlsState}`);
        });
        transport.on('icestatechange', (iceState) => {
          console.log(`[consumer-transport ice] ${transport.id} -> ${iceState}`);
        });
        transport.on('icestatechange', (iceState) => {
          console.log(`[consumer-transport ice] ${transport.id} -> ${iceState}`);
        });

        peer.send({
          type: 'consumer-transport-created',
          id: transport.id,
          iceParameters: transport.iceParameters,
          iceCandidates: transport.iceCandidates,
          dtlsParameters: transport.dtlsParameters,
        });
        break;
      }

      case 'connectConsumerTransport': {
        const transport = peer.consumerTransport;
        if (!transport) {
          peer.send({ type: 'error', message: 'No consumer transport' });
          return;
        }
        console.log(`[consumer-transport connect] peer=${peer.id} transport=${transport.id}`);
        await transport.connect({ dtlsParameters: msg.dtlsParameters as mediasoup.types.DtlsParameters });
        console.log(`[consumer-transport connected] peer=${peer.id}`);
        peer.send({ type: 'consumer-transport-connected' });
        break;
      }

      case 'consume': {
        console.log(`[consume] peer=${peer.id} producerId=${msg.producerId}`);
        if (!peer.room || !peer.consumerTransport) {
          console.log(`[consume] rejected: not ready`);
          peer.send({ type: 'error', message: 'Not ready to consume' });
          return;
        }

        const producerId = msg.producerId as string;
        const rtpCapabilities = msg.rtpCapabilities as mediasoup.types.RtpCapabilities;

        // Log client's supported video codecs for debugging
        const videoCodecs = rtpCapabilities.codecs?.filter((c: any) => c.kind === 'video') || [];
        console.log(`[consume] client video codecs: ${videoCodecs.map((c: any) => c.mimeType).join(', ') || '(none)'}`);

        if (!peer.room.router.canConsume({ producerId, rtpCapabilities })) {
          console.log(`[consume] rejected: cannot consume (codec mismatch)`);
          peer.send({ type: 'error', message: 'Cannot consume this producer' });
          return;
        }

        const consumer = await peer.consumerTransport.consume({
          producerId,
          rtpCapabilities,
        });
        console.log(`[consume] consumer created: ${consumer.id}, paused: ${consumer.paused}`);
        console.log(`[consume] consumer rtpParams: kind=${consumer.kind}, mid=${consumer.rtpParameters.mid}, encodings=${JSON.stringify(consumer.rtpParameters.encodings)}, codecs=${consumer.rtpParameters.codecs?.map((c: any) => c.mimeType).join(',')}`);

        setTimeout(async () => {
          try {
            if (consumer.closed) return;
            const stats = await consumer.getStats();
            console.log(`[consumer stats @5s] ${consumer.id}:`, JSON.stringify(stats));
          } catch {}
        }, 5000);

        setTimeout(async () => {
          try {
            if (consumer.closed) return;
            const stats = await consumer.getStats();
            console.log(`[consumer stats @12s] ${consumer.id}:`, JSON.stringify(stats));
          } catch {}
        }, 12000);

        peer.consumers.set(consumer.id, consumer);

        consumer.on('@close', () => {
          peer.consumers.delete(consumer.id);
        });

        consumer.on('producerclose', () => {
          peer.consumers.delete(consumer.id);
          peer.send({
            type: 'consumer-closed',
            consumerId: consumer.id,
            producerId: consumer.producerId,
          });
        });

        peer.send({
          type: 'consumer-created',
          id: consumer.id,
          producerId: consumer.producerId,
          kind: consumer.kind,
          rtpParameters: consumer.rtpParameters,
        });
        break;
      }

      case 'resumeConsumer': {
        const consumerId = msg.consumerId as string;
        const consumer = peer.consumers.get(consumerId);
        if (!consumer) {
          peer.send({ type: 'error', message: 'Consumer not found' });
          return;
        }
        await consumer.resume();
        peer.send({ type: 'consumer-resumed', consumerId });
        break;
      }

      case 'stopSharing': {
        peer.producers.forEach((p) => p.close());
        peer.producers.clear();
        peer.isSharing = false;
        peer.producerTransport?.close();
        peer.producerTransport = null;
        peer.room?.broadcast(
          { type: 'peer-stopped-sharing', peerId: peer.id },
          peer.id,
        );
        peer.send({ type: 'sharing-stopped' });
        break;
      }

      default:
        peer.send({ type: 'error', message: `Unknown message type: ${msg.type}` });
    }
  } catch (err) {
    console.error('Error handling message:', err);
    peer.send({ type: 'error', message: (err as Error).message });
  }
}

async function main(): Promise<void> {
  setupFileLogging();

  // Kill orphan mediasoup-worker processes from previous crashes
  try {
    const result = execSync(
      'pgrep -f mediasoup-worker || true',
      { encoding: 'utf8', timeout: 5000 },
    ).trim();
    if (result) {
      const pids = result.split('\n').filter(Boolean);
      console.log(`[startup] Killing ${pids.length} orphan mediasoup-worker(s): ${pids.join(', ')}`);
      for (const pid of pids) {
        try { process.kill(parseInt(pid, 10), 'SIGKILL'); } catch {}
      }
    }
  } catch { /* pgrep not available, skip */ }

  let shuttingDown = false;

  async function gracefulShutdown(): Promise<void> {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log('[shutdown] Gracefully stopping...');
    if (worker && !worker.closed) {
      worker.close();
    }
    process.exit(0);
  }

  process.on('SIGINT', gracefulShutdown);
  process.on('SIGTERM', gracefulShutdown);

  process.on('uncaughtException', (err) => {
    console.error('[FATAL] Uncaught exception:', err);
    setImmediate(() => { process.exit(1); });
  });
  process.on('unhandledRejection', (reason) => {
    console.error('[FATAL] Unhandled rejection:', reason);
    setImmediate(() => { process.exit(1); });
  });

  mediasoup.setLogEventListeners({
    ondebug: (ns, msg) => console.log(`[ms-debug:${ns}] ${msg}`),
    onwarn: (ns, msg) => console.warn(`[ms-warn:${ns}] ${msg}`),
    onerror: (ns, msg, err) => console.error(`[ms-error:${ns}] ${msg}`, err),
  });

  worker = await mediasoup.createWorker({
    logLevel: config.mediasoup.worker.logLevel,
    logTags: config.mediasoup.worker.logTags as mediasoup.types.WorkerLogTag[],
    rtcMinPort: config.mediasoup.worker.rtcMinPort,
    rtcMaxPort: config.mediasoup.worker.rtcMaxPort,
  });

  worker.on('died', () => {
    console.error('mediasoup worker died, exiting');
    process.exit(1);
  });

  console.log(`mediasoup worker started (ports ${config.mediasoup.worker.rtcMinPort}-${config.mediasoup.worker.rtcMaxPort})`);

  const app = express();

  // WHIP endpoint — raw SDP body, before static middleware
  const whipHandler = createWhipHandler(rooms, peerMap, nextPeerId, worker, transportMap);
  app.post('/api/whip', express.text({ type: 'application/sdp', limit: '64kb' }), async (req, res) => {
    pendingRequestCount++;
    const transportCountBefore = transportMap.size;
    console.log(`[whip] incoming request (transports=${transportCountBefore} pending=${pendingRequestCount})`);
    try {
      await whipHandler(req, res);
    } finally {
      pendingRequestCount--;
    }
  });
  app.patch('/api/whip/:id', express.text({ type: 'application/trickle-ice-sdpfrag', limit: '16kb' }), createTrickleHandler(transportMap));
  app.delete('/api/whip/:id', (req, res) => {
    const transportId = req.params.id as string;
    const transport = transportMap.get(transportId);
    if (transport) {
      transport.close();
      transportMap.delete(transportId);
    }
    res.status(200).send('OK');
  });

  // Status endpoint for diagnostics
  app.get('/api/status', (_req, res) => {
    let totalProducers = 0;
    let totalConsumers = 0;
    for (const peer of peerMap.values()) {
      totalProducers += peer.producers.size;
      totalConsumers += peer.consumers.size;
    }
    res.json({
      uptime: process.uptime(),
      rooms: rooms.size,
      peers: peerMap.size,
      transports: transportMap.size,
      producers: totalProducers,
      consumers: totalConsumers,
      pendingRequests: pendingRequestCount,
    });
  });

  app.get('/api/logs', (req, res) => {
    const tail = parseInt(req.query.tail as string) || 0;
    const content = getLogContent(tail || undefined);
    res.type('text/plain').send(content);
  });

  app.post('/api/deploy', (req, res) => {
    const token = (req.query.token as string) || '';
    const deployToken = process.env.DEPLOY_TOKEN;
    if (!deployToken || token !== deployToken) {
      res.status(403).json({ error: 'Invalid deploy token' });
      return;
    }

    res.json({ status: 'deploying' });

    setImmediate(() => {
      doDeploy().catch((err) => {
        console.error('[deploy] Failed:', err);
      });
    });
  });

  async function doDeploy(): Promise<void> {
    const projectRoot = path.resolve(__dirname, '..', '..');

    try {
      const result = execSync('pgrep -f mediasoup-worker || true', { encoding: 'utf8', timeout: 5000 }).trim();
      if (result) {
        const pids = result.split('\n').filter(Boolean);
        console.log(`[deploy] Killing ${pids.length} orphan mediasoup-worker(s): ${pids.join(', ')}`);
        for (const pid of pids) {
          try { process.kill(parseInt(pid, 10), 'SIGKILL'); } catch {}
        }
      }
    } catch { /* pgrep not available, skip */ }

    console.log('[deploy] Running git pull...');
    execSync('git pull', { cwd: projectRoot, stdio: 'inherit', timeout: 30000 });

    console.log('[deploy] Building server...');
    execSync('npm run build', { cwd: path.join(projectRoot, 'server'), stdio: 'inherit', timeout: 60000 });

    console.log('[deploy] Building client...');
    execSync('npm run build', { cwd: path.join(projectRoot, 'client'), stdio: 'inherit', timeout: 60000 });

    console.log('[deploy] Closing HTTP server to release port...');
    server.close();

    console.log('[deploy] Closing mediasoup worker...');
    if (worker && !worker.closed) {
      worker.close();
    }

    console.log('[deploy] Spawning new server process...');
    const deployLog = path.join(projectRoot, 'server', 'logs', 'deploy.log');
    const logDir = path.dirname(deployLog);
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
    const outFd = fs.openSync(deployLog, 'a');
    const child = spawn('node', ['dist/index.js'], {
      cwd: path.join(projectRoot, 'server'),
      detached: true,
      stdio: ['ignore', outFd, outFd],
      env: { ...process.env },
    });
    child.unref();
    fs.closeSync(outFd);

    console.log('[deploy] New process spawned, exiting...');
    process.exit(0);
  }

  const clientDist = path.join(__dirname, '..', '..', 'client', 'dist');
  app.use(express.static(clientDist));
  app.get('*', (_req, res) => {
    res.sendFile(path.join(clientDist, 'index.html'));
  });

  const certPath = process.env.HTTPS_CERT || 'cert.crt';
  const keyPath = process.env.HTTPS_KEY || 'cert.key';
  let server: http.Server | https.Server;
  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    server = https.createServer(
      {
        cert: fs.readFileSync(certPath),
        key: fs.readFileSync(keyPath),
      },
      app,
    );
    console.log('HTTPS enabled');
  } else {
    server = http.createServer(app);
    console.log('HTTP mode (place cert.crt + cert.key in cwd for HTTPS)');
  }

  const wss = new WebSocketServer({ server, path: '/ws' });

  wss.on('connection', (ws: WebSocket) => {
    const peerId = `peer_${nextPeerId.value++}`;
    const peer = new Peer(peerId, '', ws);
    peerMap.set(peerId, peer);

    console.log(`Peer connected: ${peerId}`);

    ws.on('message', (data) => {
      handleMessage(peer, data.toString());
    });

    ws.on('close', () => {
      console.log(`Peer disconnected: ${peerId}`);
      cleanupPeer(peer);
    });

    ws.on('error', (err) => {
      console.error(`Peer ${peerId} error:`, err.message);
    });
  });

  server.listen(config.httpPort, () => {
    console.log(`HTTP + WebSocket server listening on port ${config.httpPort}`);
    if (config.announcedIp) {
      console.log(`Announced IP: ${config.announcedIp}`);
    }
  });

  // Periodic resource status
  setInterval(() => {
    let totalProducers = 0;
    let totalConsumers = 0;
    for (const peer of peerMap.values()) {
      totalProducers += peer.producers.size;
      totalConsumers += peer.consumers.size;
    }
    console.log(`[status @${Math.round(process.uptime())}s] rooms=${rooms.size} peers=${peerMap.size} transports=${transportMap.size} producers=${totalProducers} consumers=${totalConsumers} pending=${pendingRequestCount}`);
  }, 60000);
}

main().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
