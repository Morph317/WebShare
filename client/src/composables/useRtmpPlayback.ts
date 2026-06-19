import { ref, onUnmounted, watch, type Ref } from 'vue';
import flvjs from 'flv.js';

export function useRtmpPlayback() {
  const isLive = ref(false);
  let player: flvjs.Player | null = null;
  let videoEl: HTMLVideoElement | null = null;
  let pollTimer: ReturnType<typeof setInterval> | null = null;
  let pendingUrl = '';

  function setup(videoRef: Ref<HTMLVideoElement | null>): void {
    // Watch for video element becoming available in DOM
    watch(videoRef, (el) => {
      if (el && el !== videoEl) {
        videoEl = el;
        startPolling();
      }
    }, { immediate: true });
  }

  function startPolling(): void {
    if (pollTimer) return;
    pollTimer = setInterval(async () => {
      try {
        const resp = await fetch('/api/rtmp-status');
        const status = await resp.json();
        if (status.isPublishing && status.flvUrl) {
          if (!isLive.value) {
            startFlv(status.flvUrl);
          }
        } else if (!status.isPublishing && isLive.value) {
          stopFlv();
        }
      } catch {}
    }, 2000);
  }

  function startFlv(url: string): void {
    if (!videoEl) {
      // Video element not yet in DOM — signal loading and retry on next poll
      console.log('[rtmp] waiting for video element...');
      return;
    }
    if (player) {
      // Already playing same URL
      if (url === pendingUrl) return;
      stopFlv();
    }

    pendingUrl = url;

    if (flvjs.isSupported()) {
      player = flvjs.createPlayer({
        type: 'flv',
        url,
        isLive: true,
        enableWorker: true,
      } as any);
      player.attachMediaElement(videoEl);
      player.load();
      player.play();
      isLive.value = true;
      console.log('[rtmp] FLV playback started:', url);
    } else {
      console.warn('[rtmp] flv.js not supported');
    }
  }

  function stopFlv(): void {
    if (player) {
      try { player.unload(); } catch {}
      try { player.detachMediaElement(); } catch {}
      try { player.destroy(); } catch {}
      player = null;
    }
    if (videoEl) {
      videoEl.src = '';
      videoEl.srcObject = null;
    }
    pendingUrl = '';
    isLive.value = false;
    console.log('[rtmp] FLV playback stopped');
  }

  function detach(): void {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    stopFlv();
    videoEl = null;
  }

  onUnmounted(detach);

  return { isLive, setup, detach };
}
