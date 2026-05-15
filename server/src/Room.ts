import type * as mediasoup from 'mediasoup';
import { WebSocket } from 'ws';

export interface PeerInfo {
  peerId: string;
  displayName: string;
  isSharing: boolean;
}

export class Peer {
  public id: string;
  public displayName: string;
  public ws: WebSocket;
  public room: Room | null = null;
  public producerTransport: mediasoup.types.WebRtcTransport | null = null;
  public consumerTransport: mediasoup.types.WebRtcTransport | null = null;
  public producers: Map<string, mediasoup.types.Producer> = new Map();
  public consumers: Map<string, mediasoup.types.Consumer> = new Map();
  public isSharing: boolean = false;

  constructor(id: string, displayName: string, ws: WebSocket) {
    this.id = id;
    this.displayName = displayName;
    this.ws = ws;
  }

  send(msg: Record<string, unknown>): void {
    if (this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    }
  }

  getInfo(): PeerInfo {
    return {
      peerId: this.id,
      displayName: this.displayName,
      isSharing: this.isSharing,
    };
  }

  close(): void {
    this.producers.forEach((p) => p.close());
    this.consumers.forEach((c) => c.close());
    this.producers.clear();
    this.consumers.clear();
    this.producerTransport?.close();
    this.consumerTransport?.close();
    this.producerTransport = null;
    this.consumerTransport = null;
    this.isSharing = false;
  }
}

export class Room {
  public id: string;
  public router: mediasoup.types.Router;
  public peers: Map<string, Peer> = new Map();

  constructor(id: string, router: mediasoup.types.Router) {
    this.id = id;
    this.router = router;
  }

  addPeer(peer: Peer): void {
    this.peers.set(peer.id, peer);
    peer.room = this;
  }

  removePeer(peerId: string): void {
    const peer = this.peers.get(peerId);
    if (peer) {
      peer.close();
      this.peers.delete(peerId);
    }
  }

  getMembers(): PeerInfo[] {
    return Array.from(this.peers.values()).map((p) => p.getInfo());
  }

  getProducers(): { producerId: string; peerId: string; kind: string }[] {
    const producers: { producerId: string; peerId: string; kind: string }[] = [];
    for (const peer of this.peers.values()) {
      for (const producer of peer.producers.values()) {
        producers.push({
          producerId: producer.id,
          peerId: peer.id,
          kind: producer.kind,
        });
      }
    }
    return producers;
  }

  broadcast(msg: Record<string, unknown>, excludePeerId?: string): void {
    for (const peer of this.peers.values()) {
      if (peer.id !== excludePeerId) {
        peer.send(msg);
      }
    }
  }

  close(): void {
    for (const peer of this.peers.values()) {
      peer.close();
    }
    this.peers.clear();
    this.router.close();
  }
}
