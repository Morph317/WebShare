import { ref, onUnmounted } from 'vue';
import flvjs from 'flv.js';

export function useRtmpPlayback() {
  const isLive = ref(false);
  let player: flvjs.Player | null = null;
  let videoEl: HTMLVideoElement | null = null;
  let pollTimer: ReturnType<typeof setInterval> | null = null;
  let currentUrl = '';

  function attach(video: HTMLVideoElement): void {
    videoEl = video;

    pollTimer = setInterval(async () => {
      try {
        const resp = await fetch('/api/rtmp-status');
        const status = await resp.json();
        if (status.isPublishing && status.flvUrl && !isLive.value) {
          startFlv(status.flvUrl);
        } else if (!status.isPublishing && isLive.value) {
          stopFlv();
        }
      } catch {}
    }, 2000);
  }

  function startFlv(url: string): void {
    if (!videoEl) return;
    if (url === currentUrl && isLive.value) return;
    currentUrl = url;

    if (flvjs.isSupported()) {
      player = flvjs.createPlayer({
        type: 'flv',
        url,
        isLive: true,
      });
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
      player.unload();
      player.detachMediaElement();
      player.destroy();
      player = null;
    }
    if (videoEl) {
      videoEl.src = '';
      videoEl.srcObject = null;
    }
    currentUrl = '';
    isLive.value = false;
    console.log('[rtmp] FLV playback stopped');
  }

  function detach(): void {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    stopFlv();
    videoEl = null;
  }

  onUnmounted(detach);

  return { isLive, attach, detach };
}
