import NodeMediaServer from 'node-media-server';
import path from 'node:path';
import fs from 'node:fs';
import { EventEmitter } from 'node:events';

export interface RtmpStatus {
  isPublishing: boolean;
  streamPath: string;
  startTime: number | null;
  hlsUrl: string;
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
    hlsUrl: '',
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
          app: 'live',  // matches /live, /live/xxx etc.
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

  nms.on('prePublish', function(this: any, _id: any, streamPath: any, args: any) {
    console.log(`[rtmp] prePublish id=${_id} path=${streamPath} args=${JSON.stringify(args)}`);
  } as any);

  nms.on('postPublish', function(this: any, _id: any, streamPath: any, args: any) {
    console.log(`[rtmp] postPublish id=${_id} path=${streamPath} args=${JSON.stringify(args)}`);

    // node-media-server v2+ passes streamPath differently.
    // If undefined, reconstruct from known app=live, name=default.
    let path = streamPath;
    if (!path || path === 'undefined') {
      // Reconstruct from args or fallback to /live/default
      const app = (args && args.app) || 'live';
      const name = (args && args.name) || 'default';
      path = `/${app}/${name}`;
      console.log(`[rtmp] reconstructed path: ${path}`);
    }

    const url = `/hls${path}/index.m3u8`;
    console.log(`[rtmp] HLS URL: ${url}`);
    state.isPublishing = true;
    state.streamPath = path;
    state.startTime = Date.now();
    state.hlsUrl = url;
    rtmpEvents.emit('publish', { streamPath: path, hlsUrl: url });
  });

  nms.on('donePublish', (_id: string, streamPath: string, _args: any) => {
    console.log(`[rtmp] publishing stopped: ${streamPath}`);
    state.isPublishing = false;
    state.streamPath = '';
    state.startTime = null;
    state.hlsUrl = '';
    rtmpEvents.emit('unpublish', { streamPath });
  });

  return {
    nms,
    status: () => ({ ...state }),
  };
}
