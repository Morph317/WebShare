<template>
  <div class="video-controls" :class="{ visible: showControls }" @mouseenter="onEnter" @mouseleave="onLeave">
    <div class="controls-bar" v-show="showControls">
      <button class="ctrl-btn" @click="togglePlay" :title="paused ? '播放' : '暂停'">
        <svg v-if="paused" width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>
        <svg v-else width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"/></svg>
      </button>

      <div class="volume-group">
        <button class="ctrl-btn" @click="toggleMute" :title="muted ? '取消静音' : '静音'">
          <svg v-if="muted || volume === 0" width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M16.5 12c0-1.77-1.02-3.29-2.5-4.03v2.21l2.45 2.45c.03-.2.05-.41.05-.63zm2.5 0c0 .94-.2 1.82-.54 2.64l1.51 1.51C20.63 14.91 21 13.5 21 12c0-4.28-2.99-7.86-7-8.77v2.06c2.89.86 5 3.54 5 6.71zM4.27 3L3 4.27 7.73 9H3v6h4l5 5v-6.73l4.25 4.25c-.67.52-1.42.93-2.25 1.18v2.06c1.38-.31 2.63-.95 3.69-1.81L19.73 21 21 19.73l-9-9L4.27 3zM12 4L9.91 6.09 12 8.18V4z"/></svg>
          <svg v-else-if="volume < 0.5" width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M18.5 12c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02zM5 9v6h4l5 5V4L9 9H5z"/></svg>
          <svg v-else width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M3 9v6h4l5 5V4L7 9H3zm13.5 3c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02zM14 3.23v2.06c2.89.86 5 3.54 5 6.71s-2.11 5.85-5 6.71v2.06c4.01-.91 7-4.49 7-8.77s-2.99-7.86-7-8.77z"/></svg>
        </button>
        <input
          type="range"
          class="volume-slider"
          min="0"
          max="1"
          step="0.05"
          :value="muted ? 0 : volume"
          @input="setVolume"
          :title="`音量 ${Math.round((muted ? 0 : volume) * 100)}%`"
        />
      </div>

      <span class="time-display">{{ formatTime(currentTime) }} / {{ formatTime(duration) }}</span>

      <div class="spacer"></div>

      <button class="ctrl-btn" @click="toggleFullscreen" :title="isFullscreen ? '退出全屏' : '全屏'">
        <svg v-if="isFullscreen" width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M5 16h3v3h2v-5H5v2zm3-8H5v2h5V5H8v3zm6 11h2v-3h3v-2h-5v5zm2-11V5h-2v5h5V8h-3z"/></svg>
        <svg v-else width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M7 14H5v5h5v-2H7v-3zm-2-4h2V7h3V5H5v5zm12 7h-3v2h5v-5h-2v3zM14 5v2h3v3h2V5h-5z"/></svg>
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, onMounted, onUnmounted } from 'vue';

const props = defineProps<{
  videoEl: HTMLVideoElement | null;
}>();

const paused = ref(true);
const volume = ref(1);
const muted = ref(false);
const currentTime = ref(0);
const duration = ref(0);
const isFullscreen = ref(false);
const showControls = ref(false);

let hideTimer: ReturnType<typeof setTimeout> | null = null;

function onEnter(): void {
  if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; }
  showControls.value = true;
}

function onLeave(): void {
  if (hideTimer) clearTimeout(hideTimer);
  hideTimer = setTimeout(() => {
    showControls.value = false;
  }, 2000);
}

function togglePlay(): void {
  const v = props.videoEl;
  if (!v) return;
  if (v.paused) {
    v.play().catch(() => {});
  } else {
    v.pause();
  }
}

function toggleMute(): void {
  const v = props.videoEl;
  if (!v) return;
  v.muted = !v.muted;
}

function setVolume(e: Event): void {
  const v = props.videoEl;
  if (!v) return;
  const val = parseFloat((e.target as HTMLInputElement).value);
  v.volume = val;
  v.muted = false;
}

function formatTime(s: number): string {
  if (!isFinite(s) || s < 0) return '0:00';
  const m = Math.floor(s / 60);
  const sec = Math.floor(s % 60);
  return `${m}:${sec.toString().padStart(2, '0')}`;
}

function toggleFullscreen(): void {
  const v = props.videoEl;
  if (!v) return;
  if (!document.fullscreenElement) {
    const el = v.parentElement || v;
    el.requestFullscreen?.()
      || (el as any).webkitRequestFullscreen?.()
      || (el as any).mozRequestFullScreen?.();
  } else {
    document.exitFullscreen?.()
      || (document as any).webkitExitFullscreen?.()
      || (document as any).mozCancelFullScreen?.();
  }
}

function syncFromVideo(): void {
  const v = props.videoEl;
  if (!v) return;
  paused.value = v.paused;
  volume.value = v.volume;
  muted.value = v.muted;
  currentTime.value = v.currentTime;
  if (isFinite(v.duration) && v.duration > 0) {
    duration.value = v.duration;
  }
}

function onFullscreenChange(): void {
  isFullscreen.value = !!document.fullscreenElement;
}

watch(() => props.videoEl, (el, oldEl) => {
  if (oldEl) {
    oldEl.removeEventListener('play', syncFromVideo);
    oldEl.removeEventListener('pause', syncFromVideo);
    oldEl.removeEventListener('volumechange', syncFromVideo);
    oldEl.removeEventListener('timeupdate', syncFromVideo);
    oldEl.removeEventListener('loadedmetadata', syncFromVideo);
  }
  if (el) {
    el.addEventListener('play', syncFromVideo);
    el.addEventListener('pause', syncFromVideo);
    el.addEventListener('volumechange', syncFromVideo);
    el.addEventListener('timeupdate', syncFromVideo);
    el.addEventListener('loadedmetadata', syncFromVideo);
    syncFromVideo();
  }
});

onMounted(() => {
  document.addEventListener('fullscreenchange', onFullscreenChange);
  document.addEventListener('webkitfullscreenchange', onFullscreenChange);
});

onUnmounted(() => {
  if (hideTimer) clearTimeout(hideTimer);
  const el = props.videoEl;
  if (el) {
    el.removeEventListener('play', syncFromVideo);
    el.removeEventListener('pause', syncFromVideo);
    el.removeEventListener('volumechange', syncFromVideo);
    el.removeEventListener('timeupdate', syncFromVideo);
    el.removeEventListener('loadedmetadata', syncFromVideo);
  }
  document.removeEventListener('fullscreenchange', onFullscreenChange);
  document.removeEventListener('webkitfullscreenchange', onFullscreenChange);
});
</script>

<style scoped>
.video-controls {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  padding: 24px 12px 8px;
  background: linear-gradient(transparent, rgba(0,0,0,0.7));
  opacity: 0;
  transition: opacity 0.3s;
  z-index: 20;
}
.video-controls.visible {
  opacity: 1;
}
.controls-bar {
  display: flex;
  align-items: center;
  gap: 8px;
}
.ctrl-btn {
  background: none;
  border: none;
  color: #e0e0e0;
  cursor: pointer;
  padding: 4px;
  border-radius: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: color 0.15s, background 0.15s;
}
.ctrl-btn:hover {
  color: #fff;
  background: rgba(255,255,255,0.12);
}
.volume-group {
  display: flex;
  align-items: center;
  gap: 4px;
}
.volume-slider {
  -webkit-appearance: none;
  appearance: none;
  width: 72px;
  height: 4px;
  border-radius: 2px;
  background: rgba(255,255,255,0.3);
  outline: none;
  cursor: pointer;
}
.volume-slider::-webkit-slider-thumb {
  -webkit-appearance: none;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: #fff;
  cursor: pointer;
}
.volume-slider::-moz-range-thumb {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: #fff;
  border: none;
  cursor: pointer;
}
.time-display {
  font-size: 12px;
  color: #ccc;
  font-variant-numeric: tabular-nums;
  margin-left: 4px;
  user-select: none;
}
.spacer {
  flex: 1;
}
</style>
