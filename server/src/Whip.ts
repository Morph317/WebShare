import type { Request, Response } from 'express';
import * as mediasoup from 'mediasoup';
import { config } from './config';
import { Peer, Room } from './Room';

interface ParsedOffer {
  iceUfrag?: string;
  icePwd?: string;
  fingerprint?: { algorithm: string; value: string };
  setup?: string;
  mid?: string;
  codecs: RtpCodecInfo[];
  headerExtensions: RtpHeaderExtInfo[];
  ssrcs: SsrcInfo[];
}

interface RtpCodecInfo {
  payloadType: number;
  mimeType: string;
  clockRate: number;
  parameters: Record<string, string>;
  rtcpFeedback: { type: string; parameter?: string }[];
}

interface RtpHeaderExtInfo {
  id: number;
  uri: string;
}

interface SsrcInfo {
  ssrc: number;
  cname?: string;
  msid?: string;
}

function parseSdp(sdp: string): ParsedOffer {
  const result: ParsedOffer = {
    codecs: [],
    headerExtensions: [],
    ssrcs: [],
  };

  const rawLines = sdp.split(/\r?\n/);
  let mediaSection = false;

  for (const line of rawLines) {
    if (line.startsWith('m=video')) {
      mediaSection = true;
      continue;
    }
    if (!mediaSection) continue;
    if (line.startsWith('m=') && !line.startsWith('m=video')) break;

    if (line.startsWith('a=ice-ufrag:')) {
      result.iceUfrag = line.slice('a=ice-ufrag:'.length);
    } else if (line.startsWith('a=ice-pwd:')) {
      result.icePwd = line.slice('a=ice-pwd:'.length);
    } else if (line.startsWith('a=fingerprint:')) {
      const parts = line.split(' ');
      result.fingerprint = {
        algorithm: parts[0].split(':')[1],
        value: parts[1],
      };
    } else if (line.startsWith('a=setup:')) {
      result.setup = line.slice('a=setup:'.length);
    } else if (line.startsWith('a=mid:')) {
      result.mid = line.slice('a=mid:'.length);
    } else if (line.startsWith('a=rtpmap:')) {
      const m = line.match(/a=rtpmap:(\d+)\s+([\w/]+)\/(\d+)/);
      if (m) {
        result.codecs.push({
          payloadType: parseInt(m[1]),
          mimeType: m[2],
          clockRate: parseInt(m[3]),
          parameters: {},
          rtcpFeedback: [],
        });
      }
    } else if (line.startsWith('a=fmtp:')) {
      const m = line.match(/a=fmtp:(\d+)\s+(.+)/);
      if (m) {
        const pt = parseInt(m[1]);
        const codec = result.codecs.find((c) => c.payloadType === pt);
        if (codec) {
          for (const param of m[2].split(/\s*;\s*/)) {
            const eq = param.indexOf('=');
            if (eq > 0) {
              codec.parameters[param.slice(0, eq)] = param.slice(eq + 1);
            }
          }
        }
      }
    } else if (line.startsWith('a=rtcp-fb:')) {
      const m = line.match(/a=rtcp-fb:(\d+)\s+(\S+)(?:\s+(.+))?/);
      if (m) {
        const pt = parseInt(m[1]);
        const codec = result.codecs.find((c) => c.payloadType === pt);
        if (codec) {
          codec.rtcpFeedback.push({ type: m[2], parameter: m[3] });
        }
      }
    } else if (line.startsWith('a=extmap:')) {
      const m = line.match(/a=extmap:(\d+)(?:\/\S+)?\s+(\S+)/);
      if (m) {
        result.headerExtensions.push({ id: parseInt(m[1]), uri: m[2] });
      }
    } else if (line.startsWith('a=ssrc:')) {
      const m = line.match(/a=ssrc:(\d+)\s+cname:(.+)/);
      if (m) {
        const ssrc = parseInt(m[1]);
        let entry = result.ssrcs.find((s) => s.ssrc === ssrc);
        if (!entry) { entry = { ssrc }; result.ssrcs.push(entry); }
        entry.cname = m[2];
      } else {
        const m2 = line.match(/a=ssrc:(\d+)\s+msid:(.+)/);
        if (m2) {
          const ssrc = parseInt(m2[1]);
          let entry = result.ssrcs.find((s) => s.ssrc === ssrc);
          if (!entry) { entry = { ssrc }; result.ssrcs.push(entry); }
          entry.msid = m2[2];
        }
      }
    }
  }

  return result;
}

function buildAnswer(
  transport: mediasoup.types.WebRtcTransport,
  offer: ParsedOffer,
): string {
  const iceParams = transport.iceParameters;
  const dtlsParams = transport.dtlsParameters;
  const candidates = transport.iceCandidates;

  let sdp = '';
  sdp += 'v=0\r\n';
  sdp += 'o=- 0 0 IN IP4 0.0.0.0\r\n';
  sdp += 's=-\r\n';
  sdp += 't=0 0\r\n';
  if (offer.mid) sdp += `a=group:BUNDLE ${offer.mid}\r\n`;
  sdp += 'a=ice-lite\r\n';

  let codec = offer.codecs.find((c) => c.mimeType.toLowerCase() === 'video/h264');
  if (!codec) codec = offer.codecs[0];
  if (!codec) throw new Error('No video codec in offer');

  const pt = codec.payloadType;
  sdp += `m=video 9 UDP/TLS/RTP/SAVPF ${pt}\r\n`;

  const ip = candidates[0]?.ip || config.announcedIp || '127.0.0.1';
  sdp += `c=IN IP4 ${ip}\r\n`;

  sdp += `a=rtpmap:${pt} ${codec.mimeType}/${codec.clockRate}\r\n`;
  const fmtpKeys = Object.keys(codec.parameters);
  if (fmtpKeys.length > 0) {
    sdp += `a=fmtp:${pt} ${fmtpKeys.map((k) => `${k}=${codec.parameters[k]}`).join(';')}\r\n`;
  }
  for (const fb of codec.rtcpFeedback) {
    sdp += `a=rtcp-fb:${pt} ${fb.type}`;
    if (fb.parameter) sdp += ` ${fb.parameter}`;
    sdp += '\r\n';
  }

  sdp += 'a=rtcp-mux\r\n';
  sdp += `a=ice-ufrag:${iceParams.usernameFragment}\r\n`;
  sdp += `a=ice-pwd:${iceParams.password}\r\n`;

  for (let i = 0; i < candidates.length; i++) {
    const c = candidates[i];
    let cand = `a=candidate:${i + 1} 1 ${c.protocol.toUpperCase()} ${c.priority} ${c.ip} ${c.port} typ ${c.type}`;
    if (c.tcpType) cand += ` tcptype ${c.tcpType}`;
    sdp += cand + '\r\n';
  }

  sdp += `a=fingerprint:${dtlsParams.fingerprints[0].algorithm} ${dtlsParams.fingerprints[0].value}\r\n`;
  sdp += 'a=setup:passive\r\n';
  sdp += `a=mid:${offer.mid || '0'}\r\n`;
  sdp += 'a=recvonly\r\n';

  return sdp;
}

export function createWhipHandler(
  rooms: Map<string, Room>,
  peerMap: Map<string, Peer>,
  nextPeerId: { value: number },
  worker: mediasoup.types.Worker,
) {
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

  function cleanup(peer: Peer): void {
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

  return async function handleWhip(req: Request, res: Response): Promise<void> {
    const roomId = (req.query.roomId as string) || 'default';
    const displayName = (req.query.displayName as string) || 'OBS';

    try {
      const offerSdp = typeof req.body === 'string'
        ? req.body
        : Buffer.isBuffer(req.body)
          ? req.body.toString('utf-8')
          : '';
      if (!offerSdp) { res.status(400).send('Missing SDP offer'); return; }

      const offer = parseSdp(offerSdp);
      if (!offer.mid && !offer.codecs.length) {
        res.status(400).send('Could not parse SDP offer');
        return;
      }

      const room = await initRoom(roomId);

      const peerId = `obs_${nextPeerId.value++}`;
      const peer = new Peer(peerId, displayName, null);
      room.addPeer(peer);
      peerMap.set(peerId, peer);

      const transport = await room.router.createWebRtcTransport(
        config.mediasoup.webRtcTransport,
      );
      peer.producerTransport = transport;

      transport.on('@close', () => cleanup(peer));

      transport.on('dtlsstatechange', async (dtlsState) => {
        console.log(`[whip dtls] peer=${peerId} -> ${dtlsState}`);
        if (dtlsState !== 'connected') return;

        try {
          const codec = offer.codecs.find(
            (c) => c.mimeType.toLowerCase() === 'video/h264',
          ) || offer.codecs[0];
          if (!codec) return;

          const producer = await transport.produce({
            kind: 'video',
            rtpParameters: {
              mid: offer.mid,
              codecs: [{
                mimeType: codec.mimeType,
                payloadType: codec.payloadType,
                clockRate: codec.clockRate,
                parameters: codec.parameters,
                rtcpFeedback: codec.rtcpFeedback,
              }],
              encodings: offer.ssrcs.length > 0
                ? offer.ssrcs.map((s) => ({ ssrc: s.ssrc }))
                : [{}],
              headerExtensions: offer.headerExtensions.map((ext) => ({
                uri: ext.uri as mediasoup.types.RtpHeaderExtensionUri,
                id: ext.id,
                encrypt: false,
              })),
              rtcp: {
                cname: offer.ssrcs[0]?.cname || `obs_${peerId}`,
                reducedSize: true,
              },
            },
            appData: { source: 'obs' },
          });

          peer.producers.set(producer.id, producer);
          peer.isSharing = true;

          console.log(`[whip] producer ${producer.id} (${codec.mimeType}) created for ${peerId}`);

          producer.on('@close', () => {
            console.log(`[whip] producer closed ${producer.id}`);
            peer.producers.delete(producer.id);
            if (peer.producers.size === 0) peer.isSharing = false;
            room.broadcast(
              { type: 'producer-closed', producerId: producer.id, peerId: peer.id },
              peer.id,
            );
          });

          room.broadcast(
            { type: 'new-producer', producerId: producer.id, peerId: peer.id, kind: 'video' },
            peer.id,
          );
        } catch (err) {
          console.error('[whip] producer creation failed:', err);
        }
      });

      transport.on('icestatechange', (iceState) => {
        console.log(`[whip ice] peer=${peerId} -> ${iceState}`);
      });

      if (offer.fingerprint) {
        await transport.connect({
          dtlsParameters: {
            role: 'auto',
            fingerprints: [{
              algorithm: offer.fingerprint.algorithm as 'sha-256' | 'sha-384' | 'sha-512',
              value: offer.fingerprint.value,
            }],
          },
        });
      }

      const answerSdp = buildAnswer(transport, offer);

      res.status(201)
        .set({
          'Content-Type': 'application/sdp',
          'Location': `/api/whip/${transport.id}`,
        })
        .send(answerSdp);
    } catch (err) {
      console.error('[whip] error:', err);
      res.status(500).send((err as Error).message || 'Internal error');
    }
  };
}
