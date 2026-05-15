import { ref, type Ref } from 'vue';
import { Device } from 'mediasoup-client';
import type { RemoteStream } from '../types';
import { useSignaling } from './useSignaling';

export function useMediasoup(signaling: ReturnType<typeof useSignaling>) {
  const device = ref<any>(null);
  const sendTransport = ref<any>(null);
  const recvTransport = ref<any>(null);
  const isSharing = ref(false);
  const localStream: Ref<MediaStream | null> = ref(null);
  const remoteStreams: Ref<Map<string, RemoteStream>> = ref(new Map());
  const activeStreamId = ref<string | null>(null);
  const consumerTransportReady = ref(false);

  const deviceReady = ref(false);

  function setActiveStream(producerId: string | null): void {
    activeStreamId.value = producerId;
  }

  async function initDevice(): Promise<void> {
    if (!signaling.routerRtpCapabilities.value) {
      throw new Error('No router RTP capabilities');
    }
    const d = new Device();
    const plainRtpCapabilities = JSON.parse(
      JSON.stringify(signaling.routerRtpCapabilities.value),
    );
    await d.load({ routerRtpCapabilities: plainRtpCapabilities });
    device.value = d;
    deviceReady.value = true;
  }

  async function createSendTransport(): Promise<any> {
    const d = device.value;
    if (!d) throw new Error('Device not initialized');

    signaling.send({ type: 'createProducerTransport' });
    const resp = await signaling.waitFor('producer-transport-created');

    const transport = d.createSendTransport({
      id: resp.id,
      iceParameters: resp.iceParameters,
      iceCandidates: resp.iceCandidates,
      dtlsParameters: resp.dtlsParameters,
    });

    transport.on('connect', async (
      { dtlsParameters }: { dtlsParameters: any },
      callback: () => void,
      errback: (err: Error) => void,
    ) => {
      console.log('[sendTransport] connect event fired');
      try {
        signaling.send({
          type: 'connectProducerTransport',
          dtlsParameters,
        });
        console.log('[sendTransport] waiting for producer-transport-connected');
        await signaling.waitFor('producer-transport-connected');
        console.log('[sendTransport] got producer-transport-connected, calling callback');
        callback();
      } catch (err) {
        console.error('[sendTransport] connect failed:', err);
        errback(err as Error);
      }
    });

    transport.on('produce', async (
      { kind, rtpParameters, appData }: { kind: string; rtpParameters: any; appData?: any },
      callback: (resp: { id: string }) => void,
      errback: (err: Error) => void,
    ) => {
      try {
        signaling.send({
          type: 'produce',
          kind,
          rtpParameters,
          appData,
        });
        const result = await signaling.waitFor('producer-created');
        callback({ id: result.producerId });
      } catch (err) {
        errback(err as Error);
      }
    });

    transport.on('connectionstatechange', (connectionState: string) => {
      console.log('[sendTransport] connectionState:', connectionState);
    });

    transport.on('icegatheringstatechange', (state: string) => {
      console.log('[sendTransport] iceGatheringState:', state);
    });

    transport.on('icecandidateerror', (event: any) => {
      console.error('[sendTransport] iceCandidateError:', event);
    });

    sendTransport.value = transport;
    console.log('[sendTransport] created, direction:', transport.direction, 'connectionState:', transport.connectionState);
    return transport;
  }

  async function createRecvTransport(): Promise<any> {
    const d = device.value;
    if (!d) throw new Error('Device not initialized');
    if (recvTransport.value) return recvTransport.value;

    signaling.send({ type: 'createConsumerTransport' });
    const resp = await signaling.waitFor('consumer-transport-created');

    const transport = d.createRecvTransport({
      id: resp.id,
      iceParameters: resp.iceParameters,
      iceCandidates: resp.iceCandidates,
      dtlsParameters: resp.dtlsParameters,
    });

    transport.on('connect', async (
      { dtlsParameters }: { dtlsParameters: any },
      callback: () => void,
      errback: (err: Error) => void,
    ) => {
      try {
        signaling.send({
          type: 'connectConsumerTransport',
          dtlsParameters,
        });
        await signaling.waitFor('consumer-transport-connected');
        callback();
      } catch (err) {
        errback(err as Error);
      }
    });

    recvTransport.value = transport;
    consumerTransportReady.value = true;

    transport.on('connectionstatechange', (connectionState: string) => {
      if (connectionState === 'disconnected' || connectionState === 'failed') {
        consumerTransportReady.value = false;
      }
    });

    return transport;
  }

  async function startSharing(): Promise<void> {
    try {
      const stream = await navigator.mediaDevices.getDisplayMedia({
        video: {
          width: { ideal: 1920 },
          height: { ideal: 1080 },
          frameRate: { ideal: 30 },
        },
        audio: true,
      });

      localStream.value = stream;

      const videoTrack = stream.getVideoTracks()[0];
      videoTrack.addEventListener('ended', () => {
        stopSharing();
      });

      const transport = sendTransport.value || (await createSendTransport());

      console.log('[startSharing] transport created, connectionState:', transport.connectionState, 'iceGatheringState:', transport.iceGatheringState);

      for (const track of stream.getTracks()) {
        console.log('[startSharing] producing track:', track.kind);
        await transport.produce({ track });
        console.log('[startSharing] produced, connectionState:', transport.connectionState, 'iceGatheringState:', transport.iceGatheringState);
      }

      isSharing.value = true;
    } catch (err) {
      console.error('Failed to start sharing:', err);
      throw err;
    }
  }

  async function stopSharing(): void {
    if (localStream.value) {
      localStream.value.getTracks().forEach((t) => t.stop());
      localStream.value = null;
    }
    try { sendTransport.value?.close(); } catch { /* already closed */ }
    sendTransport.value = null;
    isSharing.value = false;
    signaling.send({ type: 'stopSharing' });
  }

  async function consumeProducer(producerId: string): Promise<void> {
    if (remoteStreams.value.has(producerId)) return;

    try {
      console.log('[consumeProducer] creating consumer transport for producer:', producerId);
      const transport = recvTransport.value || (await createRecvTransport());

      const plainRtpCaps = JSON.parse(
        JSON.stringify(device.value.rtpCapabilities),
      );

      console.log('[consumeProducer] sending consume request');
      signaling.send({
        type: 'consume',
        producerId,
        rtpCapabilities: plainRtpCaps,
      });

      const resp = await signaling.waitFor('consumer-created');
      console.log('[consumeProducer] consumer created:', resp);

      const consumer = await transport.consume({
        id: resp.id,
        producerId: resp.producerId,
        kind: resp.kind,
        rtpParameters: resp.rtpParameters,
      });

      await consumer.resume();
      console.log('[consumeProducer] consumer paused:', consumer.paused, 'track readyState:', consumer.track.readyState);

      const newStream: RemoteStream = {
        producerId: resp.producerId,
        peerId: '',
        kind: resp.kind,
        stream: new MediaStream([consumer.track]),
        consumerId: consumer.id,
      };

      // Find the peer ID for this producer
      const producer = signaling.producers.value.find((p) => p.producerId === producerId);
      if (producer) {
        newStream.peerId = producer.peerId;
      }

      const updated = new Map(remoteStreams.value);
      updated.set(producerId, newStream);
      remoteStreams.value = updated;

      if (!activeStreamId.value) {
        activeStreamId.value = producerId;
      }

      consumer.on('close', () => {
        const streams = new Map(remoteStreams.value);
        streams.delete(producerId);
        remoteStreams.value = streams;
        if (activeStreamId.value === producerId) {
          const next = streams.keys().next().value;
          activeStreamId.value = next || null;
        }
      });
    } catch (err) {
      console.error('Failed to consume producer:', err);
    }
  }

  function cleanupRemoteStream(producerId: string): void {
    const entry = remoteStreams.value.get(producerId);
    if (entry) {
      entry.stream.getTracks().forEach((t) => t.stop());
      const updated = new Map(remoteStreams.value);
      updated.delete(producerId);
      remoteStreams.value = updated;
      if (activeStreamId.value === producerId) {
        const next = updated.keys().next().value;
        activeStreamId.value = next || null;
      }
    }
  }

  function cleanup(): void {
    stopSharing();
    remoteStreams.value.forEach((rs) => {
      rs.stream.getTracks().forEach((t) => t.stop());
    });
    remoteStreams.value = new Map();
    sendTransport.value?.close();
    recvTransport.value?.close();
    sendTransport.value = null;
    recvTransport.value = null;
    device.value = null;
    deviceReady.value = false;
    isSharing.value = false;
    activeStreamId.value = null;
    consumerTransportReady.value = false;
  }

  return {
    device,
    deviceReady,
    sendTransport,
    recvTransport,
    isSharing,
    localStream,
    remoteStreams,
    activeStreamId,
    consumerTransportReady,
    initDevice,
    createSendTransport,
    createRecvTransport,
    startSharing,
    stopSharing,
    consumeProducer,
    cleanupRemoteStream,
    setActiveStream,
    cleanup,
  };
}
