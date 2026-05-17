import express from 'express';
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { WebSocketServer, WebSocket } from 'ws';
import * as mediasoup from 'mediasoup';
import { config } from './config';
import { Peer, Room } from './Room';
import { createWhipHandler, createTrickleHandler } from './Whip';

let worker: mediasoup.types.Worker;
const rooms: Map<string, Room> = new Map();
const peerMap: Map<string, Peer> = new Map();
const transportMap: Map<string, mediasoup.types.WebRtcTransport> = new Map();
const nextPeerId = { value: 1 };

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
            const stats = await producer.getStats();
            console.log(`[producer stats @3s] ${producer.id}:`, JSON.stringify(stats));
          } catch {}
        }, 3000);

        setTimeout(async () => {
          try {
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
            const stats = await consumer.getStats();
            console.log(`[consumer stats @5s] ${consumer.id}:`, JSON.stringify(stats));
          } catch {}
        }, 5000);

        setTimeout(async () => {
          try {
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
  app.post('/api/whip', express.text({ type: 'application/sdp', limit: '64kb' }), createWhipHandler(rooms, peerMap, nextPeerId, worker, transportMap));
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
}

main().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
