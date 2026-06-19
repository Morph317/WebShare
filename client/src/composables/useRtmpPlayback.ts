import { ref, onUnmounted } from 'vue';
import Hls from 'hls.js';

export function useRtmpPlayback() {
  const isLive = ref(false);
  let hls: Hls | null = null;
  let videoEl: HTMLVideoElement | null = null;
  let pollTimer: ReturnType<typeof setInterval> | null = null;

  function attach(video: HTMLVideoElement): void {
    videoEl = video;

    pollTimer = setInterval(async () => {
      try {
        const resp = await fetch('/api/rtmp-status');
        const status = await resp.json();
        if (status.isPublishing && !isLive.value) {
          startHls();
        } else if (!status.isPublishing && isLive.value) {
          stopHls();
        }
      } catch {}
    }, 2000);
  }

  function startHls(): void {
    if (!videoEl) return;
    if (Hls.isSupported()) {
      hls = new Hls({ liveDurationInfinity: true, lowLatencyMode: false });
      hls.loadSource('/hls/live/default/index.m3u8');
      hls.attachMedia(videoEl);
      hls.on(Hls.Events.MANIFEST_PARSED, () => {
        videoEl?.play().catch(() => {});
      });
      isLive.value = true;
      console.log('[rtmp] HLS playback started');
    } else if (videoEl.canPlayType('application/vnd.apple.mpegurl')) {
      videoEl.src = '/hls/live/default/index.m3u8';
      isLive.value = true;
    }
  }

  function stopHls(): void {
    if (hls) {
      hls.destroy();
      hls = null;
    }
    if (videoEl) {
      videoEl.src = '';
      videoEl.srcObject = null;
    }
    isLive.value = false;
    console.log('[rtmp] HLS playback stopped');
  }

  function detach(): void {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    stopHls();
    videoEl = null;
  }

  onUnmounted(detach);

  return { isLive, attach, detach };
}
