import type { Request, Response } from 'express';
import * as mediasoup from 'mediasoup';
import sdpTransform from 'sdp-transform';
// @ts-ignore - mediasoup-client uses package exports
import * as sdpCommonUtils from 'mediasoup-client/handlers/sdp/commonUtils';
// @ts-ignore - mediasoup-client uses package exports
import * as ortc from 'mediasoup-client/ortc';
// @ts-ignore - mediasoup-client uses package exports
import * as sdpUnifiedPlanUtils from 'mediasoup-client/handlers/sdp/unifiedPlanUtils';
import { config } from './config';
import { Peer, Room } from './Room';

export function createWhipHandler(
  rooms: Map<string, Room>,
  peerMap: Map<string, Peer>,
  nextPeerId: { value: number },
  worker: mediasoup.types.Worker,
  transportMap: Map<string, mediasoup.types.WebRtcTransport>,
) {
  function scheduleStats(producer: mediasoup.types.Producer, kind: string, delayMs: number): void {
    setTimeout(async () => {
      try {
        if (producer.closed) return;
        const stats = await producer.getStats();
        console.log(`[whip producer stats @${delayMs/1000}s] ${kind} ${producer.id}:`, JSON.stringify(stats));
      } catch {}
    }, delayMs);
  }

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
    // Close producers and transport
    for (const p of peer.producers.values()) {
      p.close();
    }
    peer.producers.clear();
    const transport = peer.producerTransport;
    if (transport) {
      peer.producerTransport = null;
      transportMap.delete(transport.id);
      if (!transport.closed) {
        transport.close();
      }
    }
    peerMap.delete(peer.id);
    console.log(`[whip cleanup] peer=${peer.id} fully cleaned`);
  }

  return async function handleWhip(req: Request, res: Response): Promise<void> {
    console.log('[whip] received request');
    const roomId = (req.query.roomId as string) || 'default';
    const displayName = (req.query.displayName as string) || 'OBS';

    try {
      const offerSdp = typeof req.body === 'string'
        ? req.body
        : Buffer.isBuffer(req.body)
          ? req.body.toString('utf-8')
          : '';
      if (!offerSdp) { res.status(400).send('Missing SDP offer'); return; }

      console.log('[whip] raw SDP offer:\n' + offerSdp);

      // Parse offer and extract capabilities
      const offerObject = sdpTransform.parse(offerSdp);

      // OBS sends both a=ssrc:...msid:... AND a=msid:... lines.
      // Remove redundant a=msid lines to prevent duplicate MSID in consumer SDP.
      for (const media of offerObject.media) {
        (media as any).msid = undefined;
      }

      const rtpCapabilities = sdpCommonUtils.extractRtpCapabilities({ sdpObject: offerObject });
      const dtlsParameters = sdpCommonUtils.extractDtlsParameters({ sdpObject: offerObject });

      // WHIP: Following @eyevinn/whip-endpoint, SFU is DTLS client (active).
      // OBS offer has a=setup:actpass, our answer will say a=setup:active.
      // Tell mediasoup the remote (OBS) is DTLS server so we act as client.
      dtlsParameters.role = 'server';

      const room = await initRoom(roomId);
      const routerRtpCapabilities = room.router.rtpCapabilities;
      const extendedRtpCapabilities = ortc.getExtendedRtpCapabilities(
        rtpCapabilities, routerRtpCapabilities, true,
      );

      const sendingRtpParametersByKind: Record<string, any> = {
        audio: ortc.getSendingRtpParameters('audio', extendedRtpCapabilities),
        video: ortc.getSendingRtpParameters('video', extendedRtpCapabilities),
      };

      const peerId = `obs_${nextPeerId.value++}`;
      const peer = new Peer(peerId, displayName, null);
      room.addPeer(peer);
      peerMap.set(peerId, peer);

      room.broadcast(
        { type: 'peer-joined', peerId, displayName },
        peerId,
      );

      const transport = await room.router.createWebRtcTransport({
        ...config.mediasoup.webRtcTransport,
        iceConsentTimeout: 0,
        enableSctp: false,
      }).catch((err) => {
        console.error(`[whip] transport creation failed for ${peerId}:`, err.message);
        cleanup(peer);
        res.status(503).send('Transport creation failed, server busy');
        return null;
      });
      if (!transport) return;
      peer.producerTransport = transport;
      transportMap.set(transport.id, transport);

      transport.on('@close', () => {
        console.log(`[whip transport @close] peer=${peerId} transport=${transport.id}`);
        cleanup(peer);
      });
      transport.on('dtlsstatechange', (dtlsState) => {
        console.log(`[whip dtls] peer=${peerId} -> ${dtlsState}`);
      });
      transport.on('icestatechange', (iceState) => {
        console.log(`[whip ice] peer=${peerId} -> ${iceState}`);
      });
      transport.on('sctpstatechange', (sctpState) => {
        console.log(`[whip sctp] peer=${peerId} -> ${sctpState}`);
      });

      // Connect transport with remote DTLS params from offer
      await transport.connect({ dtlsParameters });

      // Build answer SDP by modifying the offer (following @eyevinn/whip-endpoint SfuWhipResource pattern)
      const answerObject = JSON.parse(JSON.stringify(offerObject));

      // Session-level
      answerObject.origin.sessionVersion++;
      answerObject.msidSemantic = answerObject.msidSemantic || { semantic: 'WMS', token: '' };
      (answerObject as any).extmapAllowMixed = undefined;
      (answerObject as any).iceOptions = undefined;
      answerObject.iceLite = true;
      answerObject.iceUfrag = transport.iceParameters.usernameFragment;
      answerObject.icePwd = transport.iceParameters.password;
      const sha256Fp = transport.dtlsParameters.fingerprints!.find(
        f => f.algorithm === 'sha-256',
      ) || transport.dtlsParameters.fingerprints![transport.dtlsParameters.fingerprints!.length - 1];
      answerObject.fingerprint = {
        type: sha256Fp.algorithm,
        hash: sha256Fp.value,
      };
      answerObject.setup = 'active';

      // Media-level
      let bundleMids = '';
      let candidatesAdded = false;
      const iceCandidates = transport.iceCandidates;

      // Remove non-audio/video media sections (data channels etc.)
      answerObject.media = answerObject.media.filter(
        (m: any) => m.type === 'audio' || m.type === 'video',
      );

      for (let i = 0; i < answerObject.media.length; i++) {
        const media: any = answerObject.media[i];
        const kind = media.type as 'audio' | 'video';

        bundleMids = bundleMids ? `${bundleMids} ${media.mid}` : `${media.mid}`;

        media.iceOptions = undefined;
        media.iceUfrag = transport.iceParameters.usernameFragment;
        media.icePwd = transport.iceParameters.password;
        media.fingerprint = {
          type: sha256Fp.algorithm,
          hash: sha256Fp.value,
        };
        media.ssrcGroups = undefined;
        media.ssrcs = undefined;
        media.msid = undefined;
        media.port = 9;
        media.rtcp = { port: 9, netType: 'IN', ipVer: 4, address: '0.0.0.0' };
        media.direction = 'recvonly';

        // ICE candidates (only add to first media for BUNDLE)
        if (!candidatesAdded && iceCandidates.length > 0) {
          media.candidates = iceCandidates.map((c: any) => ({
            foundation: c.foundation,
            component: 1,
            transport: c.protocol,
            priority: c.priority,
            ip: c.ip,
            port: c.port,
            type: c.type,
            raddr: c.raddr,
            rport: c.rport,
            generation: c.generation ?? 0,
          }));
          media.endOfCandidates = 'end-of-candidates';
          candidatesAdded = true;
        }

        // Filter codecs to only what ORTC negotiated
        const negotiatedCodecs: any[] = sendingRtpParametersByKind[kind].codecs;
        const negotiatedPayloads = new Set<number>();
        const keptRtps: any[] = [];

        for (const rtp of (media.rtp || [])) {
          const matched = negotiatedCodecs.find(
            (c: any) => rtp.codec.toUpperCase() === c.mimeType.split('/')[1]?.toUpperCase(),
          );
          if (matched) {
            negotiatedPayloads.add(rtp.payload);
            keptRtps.push(rtp);
          }
        }
        media.rtp = keptRtps;

        // Filter fmtp to kept payloads
        if (media.fmtp) {
          media.fmtp = media.fmtp.filter((f: any) => negotiatedPayloads.has(f.payload));
        }

        // Set payloads string
        media.payloads = keptRtps.map((r: any) => String(r.payload)).join(' ');

        // Filter RTCP-FB to kept payloads
        if (media.rtcpFb) {
          media.rtcpFb = media.rtcpFb.filter((fb: any) => negotiatedPayloads.has(fb.payload));
        }
      }

      // Set BUNDLE group
      answerObject.groups = [{ type: 'BUNDLE', mids: bundleMids }];

      const answerSdp = sdpTransform.write(answerObject)
        .replace('t=0 0\r\n', 't=0 0\r\na=ice-lite\r\n');
      console.log(`[whip] answer SDP:\n${answerSdp}`);

      // Create producers for each media kind
      for (const mediaSection of offerObject.media) {
        const kind = mediaSection.type as 'audio' | 'video';
        if (kind !== 'audio' && kind !== 'video') continue;

        const sendingRtpParameters = JSON.parse(JSON.stringify(sendingRtpParametersByKind[kind]));
        sendingRtpParameters.mid = String(mediaSection.mid);
        sendingRtpParameters.rtcp.cname =
          sdpCommonUtils.getCname({ offerMediaObject: mediaSection }) || `obs_${peerId}`;
        sendingRtpParameters.encodings =
          sdpUnifiedPlanUtils.getRtpEncodings({
            offerMediaObject: mediaSection,
            codecs: sendingRtpParameters.codecs,
          });
        console.log(`[whip] ${kind} rtpParams: mid=${sendingRtpParameters.mid}, encodings=${JSON.stringify(sendingRtpParameters.encodings)}, codecs=${JSON.stringify(sendingRtpParameters.codecs?.map((c: any) => ({mimeType:c.mimeType,payloadType:c.payloadType,clockRate:c.clockRate,channels:c.channels,parameters:c.parameters}))||[])}, headerExtensions=${JSON.stringify(sendingRtpParameters.headerExtensions?.map((h: any) => ({uri:h.uri,id:h.id,encrypt:h.encrypt}))||[])}`);

        try {
          const producer = await transport.produce({
            kind,
            rtpParameters: sendingRtpParameters,
            appData: { source: 'obs' },
          });

            peer.producers.set(producer.id, producer);
            peer.isSharing = true;
            console.log(`[whip] ${kind} producer ${producer.id} created for ${peerId}, codecs: ${sendingRtpParameters.codecs?.map((c: any) => c.mimeType).join(', ')}`);

          producer.on('@close', () => {
            console.log(`[whip] ${kind} producer closed ${producer.id}`);
            peer.producers.delete(producer.id);
            if (peer.producers.size === 0) peer.isSharing = false;
            room.broadcast(
              { type: 'producer-closed', producerId: producer.id, peerId: peer.id },
              peer.id,
            );
          });

          // Log producer stats to verify RTP flow
          scheduleStats(producer, kind, 3000);
          scheduleStats(producer, kind, 10000);
          scheduleStats(producer, kind, 30000);
          scheduleStats(producer, kind, 60000);

          room.broadcast(
            { type: 'new-producer', producerId: producer.id, peerId: peer.id, kind },
            peer.id,
          );
        } catch (err) {
          console.error(`[whip] ${kind} producer creation failed:`, err);
        }
      }

      const host = req.get('host') || 'localhost';
      const proto = (req.get('x-forwarded-proto') || req.protocol || 'http').split(',')[0].trim();
      const locationUrl = `${proto}://${host}/api/whip/${transport.id}`;
      res.status(201)
        .set({
          'Content-Type': 'application/sdp',
          'Location': locationUrl,
        })
        .send(answerSdp);

      console.log(`[whip] 201 response sent, Location: ${locationUrl}`);

      transport.appData = { peer, room, transport, peerId };
    } catch (err) {
      console.error('[whip] error:', err);
      res.status(500).send((err as Error).message || 'Internal error');
    }
  };
}

export function createTrickleHandler(
  transportMap: Map<string, mediasoup.types.WebRtcTransport>,
) {
  return async function handleTrickle(req: Request, res: Response): Promise<void> {
    const transportId = req.params.id as string;
    const body = typeof req.body === 'string'
      ? req.body
      : Buffer.isBuffer(req.body)
        ? req.body.toString('utf-8')
        : '';

    const transport = transportMap.get(transportId);
    if (!transport) {
      console.warn(`[whip trickle] unknown transport ${transportId}`);
      res.status(204).end();
      return;
    }

    if (body.trim()) {
      console.log(`[whip trickle] transport=${transportId} candidates:\n${body.trim()}`);
      // mediasoup is ICE-lite: remote candidates are discovered via STUN
      // binding requests, not explicitly added. Just acknowledge.
    }
    res.status(204).end();
  };
}
