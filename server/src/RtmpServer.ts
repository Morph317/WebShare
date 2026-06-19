import NodeMediaServer from 'node-media-server';
import path from 'node:path';
import fs from 'node:fs';
import { EventEmitter } from 'node:events';

export interface RtmpStatus {
  isPublishing: boolean;
  streamPath: string;
  startTime: number | null;
  bytesReceived: number;
}

export const rtmpEvents = new EventEmitter();

const HLS_DIR = path.join(__dirname, '..', 'public', 'hls');

export function createRtmpServer(): { nms: any; status: () => RtmpStatus } {
  if (!fs.existsSync(HLS_DIR)) {
    fs.mkdirSync(HLS_DIR, { recursive: true });
  }

  const state: RtmpStatus = {
    isPublishing: false,
    streamPath: '',
    startTime: null,
    bytesReceived: 0,
  };

  const nms = new NodeMediaServer({
    rtmp: {
      port: 1935,
      chunk_size: 60000,
      gop_cache: true,
      ping: 30,
      ping_timeout: 60,
    },
    http: {
      port: 8000,
      mediaroot: HLS_DIR,
      allow_origin: '*',
    },
    trans: {
      ffmpeg: '/usr/bin/ffmpeg',
      tasks: [
        {
          app: 'live',
          hls: true,
          hlsFlags: '[hls_time=2:hls_list_size=10:hls_flags=delete_segments+append_list+omit_endlist]',
          hlsKeep: false,
        },
      ],
    },
  });

  nms.on('preConnect', (_id: string, _args: any) => {
    console.log('[rtmp] incoming connection');
  });

  nms.on('postConnect', (_id: string, _args: any) => {
    console.log('[rtmp] connection established');
  });

  nms.on('doneConnect', (_id: string, _args: any) => {
    console.log('[rtmp] connection closed');
  });

  nms.on('prePublish', (_id: string, streamPath: string, _args: any) => {
    console.log(`[rtmp] prePublish: ${streamPath}`);
    // Allow any stream key under /live/
    if (!streamPath.startsWith('/live/')) {
      const session = (nms as any).getSession(_id);
      if (session) session.reject();
      return;
    }
  });

  nms.on('postPublish', (_id: string, streamPath: string, _args: any) => {
    console.log(`[rtmp] publishing started: ${streamPath}`);
    state.isPublishing = true;
    state.streamPath = streamPath;
    state.startTime = Date.now();
    state.bytesReceived = 0;
    rtmpEvents.emit('publish', { streamPath });
  });

  nms.on('donePublish', (_id: string, streamPath: string, _args: any) => {
    console.log(`[rtmp] publishing stopped: ${streamPath}`);
    state.isPublishing = false;
    state.streamPath = '';
    state.startTime = null;
    state.bytesReceived = 0;
    rtmpEvents.emit('unpublish', { streamPath });
  });

  return {
    nms,
    status: () => ({ ...state }),
  };
}
