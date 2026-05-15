import { ref, type Ref } from 'vue';
import type { PeerInfo, ProducerInfo, ServerMessage } from '../types';

type ConnectionState = 'disconnected' | 'connecting' | 'connected';

export function useSignaling() {
  const ws = ref<WebSocket | null>(null) as Ref<WebSocket | null>;
  const state = ref<ConnectionState>('disconnected');
  const peerId = ref('');
  const members = ref<PeerInfo[]>([]);
  const producers = ref<ProducerInfo[]>([]);
  const routerRtpCapabilities = ref<any>(null);

  const handlers = new Map<string, Set<(payload: any) => void>>();
  let onceHandlers: Array<{ type: string; fn: (payload: any) => void }> = [];

  function on(type: string, fn: (payload: any) => void): void {
    if (!handlers.has(type)) {
      handlers.set(type, new Set());
    }
    handlers.get(type)!.add(fn);
  }

  function off(type: string, fn: (payload: any) => void): void {
    handlers.get(type)?.delete(fn);
  }

  function once(type: string, fn: (payload: any) => void): void {
    onceHandlers.push({ type, fn });
  }

  function emit(type: string, payload: any): void {
    handlers.get(type)?.forEach((fn) => fn(payload));
    const filtered = onceHandlers.filter((h) => {
      if (h.type === type) {
        h.fn(payload);
        return false;
      }
      return true;
    });
    onceHandlers = filtered;
  }

  function connect(url: string, roomId: string, displayName: string): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        state.value = 'connecting';
        const socket = new WebSocket(url);
        ws.value = socket;

        socket.onopen = () => {
          console.log('[WS] opened, sending join');
          socket.send(
            JSON.stringify({
              type: 'join',
              roomId,
              displayName,
            }),
          );
        };

        socket.onmessage = (event) => {
          const msg: ServerMessage = JSON.parse(event.data);
          console.log('[WS] received:', msg.type, msg);
          handleMessage(msg);
        };

        socket.onerror = () => {
          state.value = 'disconnected';
          reject(new Error('WebSocket connection failed'));
        };

        socket.onclose = () => {
          state.value = 'disconnected';
          ws.value = null;
          members.value = [];
          producers.value = [];
          peerId.value = '';
        };

        const onRoomJoined = (msg: any) => {
          console.log('[WS] room-joined handler called, setting state to connected');
          off('room-joined', onRoomJoined);
          peerId.value = msg.peerId;
          members.value = msg.members || [];
          producers.value = msg.existingProducers || [];
          routerRtpCapabilities.value = msg.routerRtpCapabilities;
          state.value = 'connected';
          console.log('[WS] state after connect:', state.value);
          resolve();
        };

        once('room-joined', onRoomJoined);
      } catch (err) {
        state.value = 'disconnected';
        reject(err);
      }
    });
  }

  function disconnect(): void {
    ws.value?.close();
    ws.value = null;
    state.value = 'disconnected';
    members.value = [];
    producers.value = [];
    peerId.value = '';
  }

  function send(msg: Record<string, unknown>): void {
    if (ws.value?.readyState === WebSocket.OPEN) {
      ws.value.send(JSON.stringify(msg));
    }
  }

  function handleMessage(msg: ServerMessage): void {
    console.log('[handleMessage] type:', msg.type);
    switch (msg.type) {
      case 'peer-joined':
        members.value = [
          ...members.value,
          {
            peerId: msg.peerId as string,
            displayName: msg.displayName as string,
            isSharing: false,
          },
        ];
        break;

      case 'peer-left':
        members.value = members.value.filter(
          (m) => m.peerId !== (msg.peerId as string),
        );
        producers.value = producers.value.filter(
          (p) => p.peerId !== (msg.peerId as string),
        );
        break;

      case 'new-producer': {
        const newProducer = {
          producerId: msg.producerId as string,
          peerId: msg.peerId as string,
          kind: msg.kind as string,
        };
        producers.value = [...producers.value, newProducer];
        members.value = members.value.map((m) =>
          m.peerId === newProducer.peerId ? { ...m, isSharing: true } : m,
        );
        break;
      }

      case 'producer-closed': {
        const closedPeerId = msg.peerId as string;
        producers.value = producers.value.filter(
          (p) => p.producerId !== (msg.producerId as string),
        );
        const stillHasProducers = producers.value.some(
          (p) => p.peerId === closedPeerId,
        );
        if (!stillHasProducers) {
          members.value = members.value.map((m) =>
            m.peerId === closedPeerId ? { ...m, isSharing: false } : m,
          );
        }
        break;
      }

      case 'peer-stopped-sharing': {
        const stoppedPeerId = msg.peerId as string;
        members.value = members.value.map((m) =>
          m.peerId === stoppedPeerId ? { ...m, isSharing: false } : m,
        );
        producers.value = producers.value.filter(
          (p) => p.peerId !== stoppedPeerId,
        );
        break;
      }
    }

    emit(msg.type, msg);
  }

  function waitFor(type: string, timeoutMs = 10000): Promise<any> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        off(type, handler);
        reject(new Error(`Timeout waiting for ${type}`));
      }, timeoutMs);

      function handler(payload: any) {
        clearTimeout(timer);
        resolve(payload);
      }

      once(type, handler);
    });
  }

  return {
    ws,
    state,
    peerId,
    members,
    producers,
    routerRtpCapabilities,
    connect,
    disconnect,
    send,
    on,
    off,
    once,
    waitFor,
  };
}
