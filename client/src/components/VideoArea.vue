<template>
  <div class="video-area">
    <div class="toolbar">
      <div class="share-section">
        <button
          v-if="!isSharing"
          class="btn btn-share"
          :disabled="!canShare"
          @click="$emit('startShare')"
        >
          共享屏幕
        </button>
        <button
          v-else
          class="btn btn-stop"
          @click="$emit('stopShare')"
        >
          停止共享
        </button>
      </div>
      <div class="stream-count" v-if="remoteStreams.size > 0">
        {{ remoteStreams.size }} 个共享
      </div>
    </div>

    <!-- Thumbnails bar -->
    <div class="thumbnails-bar" v-if="remoteStreams.size > 0">
      <div
        v-for="[producerId, rs] in remoteStreams"
        :key="producerId"
        class="thumbnail"
        :class="{ active: activeStreamId === producerId }"
        @click="setActiveStream(producerId)"
      >
        <video
          :ref="(el) => setVideoRef(producerId, el as HTMLVideoElement)"
          autoplay
          muted
          playsinline
          class="thumbnail-video"
        ></video>
        <div class="thumbnail-label">{{ getPeerName(rs.peerId) }}</div>
      </div>
    </div>

    <!-- Main video -->
    <div class="main-video-wrapper">
      <div v-if="activeStream" class="main-video-container">
        <video
          ref="mainVideoRef"
          autoplay
          muted
          playsinline
          controls
          class="main-video"
        ></video>
        <div class="main-video-label">
          {{ getPeerName(activeStream.peerId) }}
        </div>
      </div>
      <div v-else class="no-stream">
        <div class="no-stream-icon">📺</div>
        <div class="no-stream-text">等待屏幕共享...</div>
        <div class="no-stream-hint">点击上方"共享屏幕"开始，或等待其他成员共享</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick } from 'vue';
import type { RemoteStream, PeerInfo } from '../types';

const props = defineProps<{
  remoteStreams: Map<string, RemoteStream>;
  activeStreamId: string | null;
  isSharing: boolean;
  canShare: boolean;
  members: PeerInfo[];
}>();

const emit = defineEmits<{
  startShare: [];
  stopShare: [];
  setActiveStream: [producerId: string];
}>();

const mainVideoRef = ref<HTMLVideoElement | null>(null);
const videoRefs: Map<string, HTMLVideoElement> = new Map();

function setVideoRef(producerId: string, el: HTMLVideoElement | null): void {
  if (el) {
    videoRefs.set(producerId, el);
    const rs = props.remoteStreams.get(producerId);
    if (rs && el.srcObject !== rs.stream) {
      console.log('[VideoArea] setVideoRef srcObject for', producerId, 'tracks:', rs.stream.getTracks().length);
      el.srcObject = rs.stream;
      el.muted = true;
      el.load();
      el.play().catch(() => {});
      el.requestVideoFrameCallback?.((_now, md) => {
        console.log('[VideoArea] thumbnail frame:', md.width, 'x', md.height);
      });
    }
  }
}

const activeStream = computed(() => {
  if (!props.activeStreamId) return null;
  return props.remoteStreams.get(props.activeStreamId) || null;
});

function setActiveStream(producerId: string): void {
  emit('setActiveStream', producerId);
}

function getPeerName(peerId: string): string {
  const member = props.members.find((m) => m.peerId === peerId);
  return member?.displayName || peerId;
}

// Sync video elements with streams
watch(
  () => props.remoteStreams,
  () => {
    for (const [producerId, rs] of props.remoteStreams) {
      const el = videoRefs.get(producerId);
      if (el && el.srcObject !== rs.stream) {
        el.srcObject = rs.stream;
      el.play().catch((e) => {
        console.warn('[VideoArea] thumbnail play failed:', e.name, e.message);
      });
      }
    }
  },
  { deep: true, flush: 'post' },
);

// Sync main video with active stream
watch(activeStream, (stream) => {
  if (mainVideoRef.value && stream) {
    console.log('[VideoArea] setting main video srcObject, tracks:', stream.stream.getTracks().length);
    mainVideoRef.value.srcObject = stream.stream;
    mainVideoRef.value.muted = true;
    mainVideoRef.value.load();
    mainVideoRef.value.play().catch(() => {});
    mainVideoRef.value.requestVideoFrameCallback?.((_now, md) => {
      console.log('[VideoArea] main video frame:', md.width, 'x', md.height);
    });
  } else if (mainVideoRef.value) {
    mainVideoRef.value.srcObject = null;
  }
}, { flush: 'post' });
</script>

<style scoped>
.video-area {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
  background: #12121f;
}
.toolbar {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 10px 18px;
  background: rgba(255, 255, 255, 0.03);
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
}
.btn {
  padding: 7px 20px;
  border: none;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  white-space: nowrap;
}
.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.btn-share {
  background: #7c4dff;
  color: #fff;
}
.btn-share:hover:not(:disabled) {
  background: #651fff;
}
.btn-stop {
  background: rgba(244, 67, 54, 0.2);
  color: #f44336;
}
.btn-stop:hover {
  background: rgba(244, 67, 54, 0.35);
}
.stream-count {
  font-size: 12px;
  color: #888;
}
.thumbnails-bar {
  display: flex;
  gap: 8px;
  padding: 8px 12px;
  overflow-x: auto;
  background: rgba(0, 0, 0, 0.2);
  border-bottom: 1px solid rgba(255, 255, 255, 0.04);
  min-height: 100px;
}
.thumbnails-bar::-webkit-scrollbar {
  height: 4px;
}
.thumbnails-bar::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.1);
  border-radius: 2px;
}
.thumbnail {
  flex-shrink: 0;
  width: 160px;
  height: 90px;
  border-radius: 6px;
  overflow: hidden;
  position: relative;
  cursor: pointer;
  border: 2px solid transparent;
  transition: border-color 0.2s;
  background: #000;
}
.thumbnail:hover {
  border-color: rgba(124, 77, 255, 0.5);
}
.thumbnail.active {
  border-color: #7c4dff;
}
.thumbnail-video {
  width: 100%;
  height: 100%;
  object-fit: cover;
}
.thumbnail-label {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  padding: 3px 6px;
  background: rgba(0, 0, 0, 0.6);
  font-size: 11px;
  color: #ccc;
}
.main-video-wrapper {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 0;
}
.main-video-container {
  position: relative;
  width: 100%;
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #000;
}
.main-video {
  width: 100%;
  height: 100%;
  object-fit: contain;
}
.main-video-label {
  position: absolute;
  bottom: 12px;
  left: 12px;
  padding: 4px 12px;
  background: rgba(0, 0, 0, 0.7);
  font-size: 12px;
  color: #ccc;
  border-radius: 4px;
}
.no-stream {
  text-align: center;
  color: #555;
}
.no-stream-icon {
  font-size: 48px;
  margin-bottom: 12px;
  opacity: 0.5;
}
.no-stream-text {
  font-size: 18px;
  margin-bottom: 6px;
}
.no-stream-hint {
  font-size: 13px;
  color: #444;
}
</style>
