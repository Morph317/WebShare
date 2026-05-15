export interface PeerInfo {
  peerId: string;
  displayName: string;
  isSharing: boolean;
}

export interface ProducerInfo {
  producerId: string;
  peerId: string;
  kind: string;
}

export interface RemoteStream {
  producerId: string;
  peerId: string;
  kind: string;
  stream: MediaStream;
  consumerId: string;
}

export interface ServerMessage {
  type: string;
  [key: string]: unknown;
}
