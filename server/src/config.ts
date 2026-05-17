export const config = {
  httpPort: parseInt(process.env.HTTP_PORT || '8080', 10),

  announcedIp: process.env.ANNOUNCED_IP || undefined,

  mediasoup: {
    worker: {
      rtcMinPort: parseInt(process.env.RTC_MIN_PORT || '40000', 10),
      rtcMaxPort: parseInt(process.env.RTC_MAX_PORT || '49999', 10),
      logLevel: (process.env.MEDIASOUP_LOG_LEVEL || 'debug') as
        | 'debug'
        | 'warn'
        | 'error'
        | 'none',
      logTags: ['rtp', 'rtcp', 'rtx', 'ice'],
    },

    router: {
      mediaCodecs: [
        {
          kind: 'audio' as const,
          mimeType: 'audio/opus',
          clockRate: 48000,
          channels: 2,
        },
        {
          kind: 'video' as const,
          mimeType: 'video/H264',
          clockRate: 90000,
          parameters: {
            'packetization-mode': 1,
            'profile-level-id': '42e01f',
            'level-asymmetry-allowed': 1,
            'x-google-start-bitrate': 5000,
            'x-google-max-bitrate': 20000,
            'x-google-min-bitrate': 2000,
          },
        },
        {
          kind: 'video' as const,
          mimeType: 'video/VP8',
          clockRate: 90000,
          parameters: {
            'x-google-start-bitrate': 3000,
            'x-google-max-bitrate': 12000,
            'x-google-min-bitrate': 1000,
          },
        },
      ],
    },

    webRtcTransport: {
      listenIps: [
        {
          ip: '0.0.0.0',
          announcedIp: process.env.ANNOUNCED_IP?.trim() || undefined,
        },
      ],
      initialAvailableOutgoingBitrate: 20000000,
      minimumAvailableOutgoingBitrate: 2000000,
      maxSctpMessageSize: 262144,
      enableUdp: true,
      enableTcp: true,
      preferUdp: true,
    },
  },
};
