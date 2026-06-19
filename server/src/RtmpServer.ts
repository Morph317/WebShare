import NodeMediaServer from 'node-media-server';
import fs from 'node:fs';
import { EventEmitter } from 'node:events';

export interface RtmpStatus {
  isPublishing: boolean;
  streamPath: string;
  startTime: number | null;
  flvUrl: string;
}

export const rtmpEvents = new EventEmitter();

const FLV_PORT = 8000;

export function createRtmpServer(): { nms: any; status: () => RtmpStatus } {
  const state: RtmpStatus = {
    isPublishing: false,
    streamPath: '',
    startTime: null,
    flvUrl: '',
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
      port: FLV_PORT,
      allow_origin: '*',
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
    let path = streamPath;
    if (!path || path === 'undefined') {
      const app = (args && args.app) || 'live';
      const name = (args && args.name) || 'default';
      path = `/${app}/${name}`;
    }

    const flvUrl = `http://${process.env.ANNOUNCED_IP || '127.0.0.1'}:${FLV_PORT}${path}.flv`;
    console.log(`[rtmp] publishing: ${path} FLV: ${flvUrl}`);
    state.isPublishing = true;
    state.streamPath = path;
    state.startTime = Date.now();
    state.flvUrl = flvUrl;
    rtmpEvents.emit('publish', { streamPath: path, flvUrl });
  });

  nms.on('donePublish', function(this: any, _id: any, streamPath: any, args: any) {
    console.log(`[rtmp] stopped: ${streamPath}`);
    state.isPublishing = false;
    state.streamPath = '';
    state.startTime = null;
    state.flvUrl = '';
    rtmpEvents.emit('unpublish', { streamPath });
  });

  return {
    nms,
    status: () => ({ ...state }),
  };
}
