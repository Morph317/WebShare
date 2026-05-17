<template>
  <div class="app">
    <ConnectionBar
      :state="state"
      :room-id="connectedRoomId"
      @disconnect="handleDisconnect"
    />

    <div class="main-layout" v-if="state === 'connected'">
      <MembersPanel
        :members="members"
        :self-peer-id="peerId"
      />
      <VideoArea
        :remote-streams="remoteStreams"
        :active-stream-id="activeStreamId"
        :is-sharing="isSharing"
        :can-share="state === 'connected'"
        :members="members"
        @start-share="handleStartShare"
        @stop-share="handleStopShare"
        @set-active-stream="setActiveStream"
      />
    </div>

    <div class="disconnected-hint" v-else-if="state === 'disconnected'">
      <p>正在连接服务器...</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, onMounted } from 'vue';
import { useSignaling } from './composables/useSignaling';
import { useMediasoup } from './composables/useMediasoup';
import ConnectionBar from './components/ConnectionBar.vue';
import MembersPanel from './components/MembersPanel.vue';
import VideoArea from './components/VideoArea.vue';

const signaling = useSignaling();
const mediasoup = useMediasoup(signaling);

const {
  state,
  peerId,
  members,
  producers,
} = signaling;

const {
  isSharing,
  remoteStreams,
  activeStreamId,
  deviceReady,
  initDevice,
  startSharing,
  stopSharing,
  consumeProducer,
  cleanupRemoteStream,
  setActiveStream,
  cleanup,
} = mediasoup;

const connectedRoomId = ref('');

function getDeviceName(): string {
  const ua = navigator.userAgent;
  let browser = 'Unknown';
  let os = '';
  if (ua.includes('Firefox')) browser = 'Firefox';
  else if (ua.includes('Edg')) browser = 'Edge';
  else if (ua.includes('Chrome')) browser = 'Chrome';
  else if (ua.includes('Safari')) browser = 'Safari';
  if (ua.includes('Windows')) os = 'Windows';
  else if (ua.includes('Mac')) os = 'Mac';
  else if (ua.includes('Linux')) os = 'Linux';
  return `${browser} on ${os}`;
}

async function autoConnect(): Promise<void> {
  try {
    const wsProtocol = location.protocol === 'https:' ? 'wss' : 'ws';
    const wsUrl = `${wsProtocol}://${location.host || 'localhost:8080'}/ws`;
    const roomId = (new URLSearchParams(location.search).get('roomId')) || 'default';
    await signaling.connect(wsUrl, roomId, getDeviceName());
    connectedRoomId.value = roomId;
    await initDevice();
  } catch (err) {
    console.error('Connection failed:', err);
    setTimeout(autoConnect, 3000);
  }
}

onMounted(autoConnect);

function handleDisconnect(): void {
  cleanup();
  signaling.disconnect();
  connectedRoomId.value = '';
}

async function handleStartShare(): Promise<void> {
  try {
    await startSharing();
  } catch (err) {
    console.error('Failed to start sharing:', err);
  }
}

function handleStopShare(): void {
  stopSharing();
}

// Watch for new producers and auto-consume
watch(
  [() => producers.value, deviceReady],
  () => {
    if (!deviceReady.value) return;
    for (const producer of producers.value) {
      if (!remoteStreams.value.has(producer.producerId)) {
        consumeProducer(producer.producerId).catch((err) => {
          console.error('Failed to consume producer:', err);
        });
      }
    }
  },
  { immediate: true },
);

// Watch for producer closures
signaling.on('producer-closed', (msg: any) => {
  cleanupRemoteStream(msg.producerId as string);
});

signaling.on('consumer-closed', (msg: any) => {
  cleanupRemoteStream(msg.producerId as string);
});

signaling.on('peer-left', (msg: any) => {
  const leftPeerId = msg.peerId as string;
  for (const [producerId, rs] of remoteStreams.value) {
    if (rs.peerId === leftPeerId) {
      cleanupRemoteStream(producerId);
    }
  }
});

signaling.on('peer-stopped-sharing', (msg: any) => {
  const stoppedPeerId = msg.peerId as string;
  for (const [producerId, rs] of remoteStreams.value) {
    if (rs.peerId === stoppedPeerId) {
      cleanupRemoteStream(producerId);
    }
  }
});
</script>

<style scoped>
.app {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}
.main-layout {
  flex: 1;
  display: flex;
  min-height: 0;
}
.disconnected-hint {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #555;
  font-size: 15px;
}
</style>
