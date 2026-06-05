import { ref } from 'vue';

const VERTEX_SHADER = `
attribute vec2 a_position;
attribute vec2 a_texCoord;
varying vec2 v_texCoord;
void main() {
    gl_Position = vec4(a_position, 0.0, 1.0);
    v_texCoord = a_texCoord;
}
`;

export interface FilterPreset {
  name: string;
  source: string;
}

export const FILTER_PRESETS: FilterPreset[] = [
  {
    name: '原始',
    source: `void main() {
    vec4 color = texture2D(u_texture, v_texCoord);
    gl_FragColor = color;
}`,
  },
  {
    name: '灰度',
    source: `void main() {
    vec4 color = texture2D(u_texture, v_texCoord);
    float gray = dot(color.rgb, vec3(0.299, 0.587, 0.114));
    gl_FragColor = vec4(vec3(gray), color.a);
}`,
  },
  {
    name: '怀旧',
    source: `void main() {
    vec4 color = texture2D(u_texture, v_texCoord);
    vec3 sepia;
    sepia.r = dot(color.rgb, vec3(0.393, 0.769, 0.189));
    sepia.g = dot(color.rgb, vec3(0.349, 0.686, 0.168));
    sepia.b = dot(color.rgb, vec3(0.272, 0.534, 0.131));
    gl_FragColor = vec4(sepia, color.a);
}`,
  },
  {
    name: '边缘检测',
    source: `void main() {
    vec2 texel = vec2(1.0) / u_resolution;
    vec4 tl = texture2D(u_texture, v_texCoord + vec2(-texel.x, texel.y));
    vec4 t  = texture2D(u_texture, v_texCoord + vec2(0.0, texel.y));
    vec4 tr = texture2D(u_texture, v_texCoord + vec2(texel.x, texel.y));
    vec4 l  = texture2D(u_texture, v_texCoord + vec2(-texel.x, 0.0));
    vec4 r  = texture2D(u_texture, v_texCoord + vec2(texel.x, 0.0));
    vec4 bl = texture2D(u_texture, v_texCoord + vec2(-texel.x, -texel.y));
    vec4 b  = texture2D(u_texture, v_texCoord + vec2(0.0, -texel.y));
    vec4 br = texture2D(u_texture, v_texCoord + vec2(texel.x, -texel.y));
    float gx = dot(vec4(-1.0, 0.0, 1.0, -2.0), vec4(tl.r, t.r, tr.r, l.r)) +
               dot(vec4(0.0, 2.0, -1.0, 0.0), vec4(r.r, bl.r, b.r, br.r));
    float gy = dot(vec4(-1.0, -2.0, -1.0, 0.0), vec4(tl.r, t.r, tr.r, l.r)) +
               dot(vec4(0.0, 1.0, 2.0, 1.0), vec4(r.r, bl.r, b.r, br.r));
    float edge = sqrt(gx * gx + gy * gy);
    gl_FragColor = vec4(vec3(1.0 - edge), 1.0);
}`,
  },
  {
    name: '反色',
    source: `void main() {
    vec4 color = texture2D(u_texture, v_texCoord);
    gl_FragColor = vec4(1.0 - color.rgb, color.a);
}`,
  },
  {
    name: 'CRT 复古',
    source: `void main() {
    vec2 uv = v_texCoord;
    vec4 color = texture2D(u_texture, uv);
    float scanline = sin(uv.y * u_resolution.y * 1.5) * 0.1;
    color.rgb *= 0.9 + scanline;
    float vignette = smoothstep(0.8, 0.2, length(uv - 0.5) * 1.4);
    color.rgb *= vignette;
    gl_FragColor = color;
}`,
  },
  {
    name: 'ASCII 艺术',
    source: `bool A[64] = bool[64](false,false,false,false,false,false,false,false,false,false,false,true,true,false,false,false,false,false,true,false,false,true,false,false,false,true,false,false,false,false,true,false,false,true,true,true,true,true,true,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,false,false,false,false,false,false,false);
bool B[64] = bool[64](false,false,false,false,false,false,false,false,false,true,true,true,true,true,false,false,false,true,false,false,false,false,true,false,false,true,true,true,true,true,false,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,true,true,true,true,true,false,false,false,false,false,false,false,false,false,false);
bool C[64] = bool[64](false,false,false,false,false,false,false,false,false,false,true,true,true,true,false,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,false,false,false,true,false,false,false,false,false,false,false,true,false,false,false,false,true,false,false,false,true,true,true,true,false,false,false,false,false,false,false,false,false,false);
bool D[64] = bool[64](false,false,false,false,false,false,false,false,false,true,true,true,true,false,false,false,false,true,false,false,false,true,false,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,true,false,false,false,true,false,false,false,true,true,true,true,false,false,false,false,false,false,false,false,false,false,false);
bool E[64] = bool[64](false,false,false,false,false,false,false,false,false,true,true,true,true,true,true,false,false,true,false,false,false,false,false,false,false,true,true,true,true,true,false,false,false,true,false,false,false,false,false,false,false,true,false,false,false,false,false,false,false,true,true,true,true,true,true,false,false,false,false,false,false,false,false,false);
bool F[64] = bool[64](false,false,false,false,false,false,false,false,false,true,true,true,true,true,true,false,false,true,false,false,false,false,false,false,false,true,true,true,true,true,false,false,false,true,false,false,false,false,false,false,false,true,false,false,false,false,false,false,false,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false);
bool G[64] = bool[64](false,false,false,false,false,false,false,false,false,false,true,true,true,true,false,false,false,true,false,false,false,false,false,false,false,true,false,false,false,false,false,false,false,true,false,false,true,true,true,false,false,true,false,false,false,false,true,false,false,false,true,true,true,true,false,false,false,false,false,false,false,false,false,false);
bool H[64] = bool[64](false,false,false,false,false,false,false,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,true,true,true,true,true,true,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,false,false,false,false,false,false,false);
bool I[64] = bool[64](false,false,false,false,false,false,false,false,false,true,true,true,true,true,true,false,false,false,false,true,true,false,false,false,false,false,false,true,true,false,false,false,false,false,false,true,true,false,false,false,false,false,false,true,true,false,false,false,false,true,true,true,true,true,true,false,false,false,false,false,false,false,false,false);
bool J[64] = bool[64](false,false,false,false,false,false,false,false,false,false,false,false,true,true,true,false,false,false,false,false,false,true,false,false,false,false,false,false,false,true,false,false,false,false,false,false,false,true,false,false,false,true,false,false,false,true,false,false,false,false,true,true,true,false,false,false,false,false,false,false,false,false,false,false);
bool K[64] = bool[64](false,false,false,false,false,false,false,false,false,true,false,false,false,true,false,false,false,true,false,false,true,false,false,false,false,true,false,true,false,false,false,false,false,true,true,true,false,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,false,true,false,false,false,false,false,false,false,false,false,false);
bool L[64] = bool[64](false,false,false,false,false,false,false,false,false,true,false,false,false,false,false,false,false,true,false,false,false,false,false,false,false,true,false,false,false,false,false,false,false,true,false,false,false,false,false,false,false,true,false,false,false,false,false,false,false,true,true,true,true,true,true,false,false,false,false,false,false,false,false,false);
bool M[64] = bool[64](false,false,false,false,false,false,false,false,false,true,false,false,false,false,true,false,false,true,true,false,false,true,true,false,false,true,false,true,true,false,true,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,false,false,false,false,false,false,false);
bool N[64] = bool[64](false,false,false,false,false,false,false,false,false,true,false,false,false,false,true,false,false,true,true,false,false,false,true,false,false,true,false,true,false,false,true,false,false,true,false,false,true,false,true,false,false,true,false,false,false,true,true,false,false,true,false,false,false,false,true,false,false,false,false,false,false,false,false,false);
bool O[64] = bool[64](false,false,false,false,false,false,false,false,false,false,true,true,true,true,false,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,false,true,true,true,true,false,false,false,false,false,false,false,false,false,false);
bool P[64] = bool[64](false,false,false,false,false,false,false,false,false,true,true,true,true,true,false,false,false,true,false,false,false,false,true,false,false,true,true,true,true,true,false,false,false,true,false,false,false,false,false,false,false,true,false,false,false,false,false,false,false,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false);
bool Q[64] = bool[64](false,false,false,false,false,false,false,false,false,false,true,true,true,true,false,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,true,false,false,true,false,true,false,false,true,false,false,false,true,false,false,false,false,true,true,true,true,false,false,false,false,false,false,false,false,false,false);
bool R[64] = bool[64](false,false,false,false,false,false,false,false,false,true,true,true,true,true,false,false,false,true,false,false,false,false,true,false,false,true,true,true,true,true,false,false,false,true,false,false,true,false,false,false,false,true,false,false,false,true,false,false,false,true,false,false,false,false,true,false,false,false,false,false,false,false,false,false);
bool S[64] = bool[64](false,false,false,false,false,false,false,false,false,false,true,true,true,true,false,false,false,true,false,false,false,false,false,false,false,false,true,true,true,false,false,false,false,false,false,false,false,true,false,false,false,true,false,false,false,false,true,false,false,false,true,true,true,true,false,false,false,false,false,false,false,false,false,false);
bool T[64] = bool[64](false,false,false,false,false,false,false,false,false,true,true,true,true,true,true,false,false,false,false,true,true,false,false,false,false,false,false,true,true,false,false,false,false,false,false,true,true,false,false,false,false,false,false,true,true,false,false,false,false,false,false,true,true,false,false,false,false,false,false,false,false,false,false,false);
bool U[64] = bool[64](false,false,false,false,false,false,false,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,false,true,true,true,true,false,false,false,false,false,false,false,false,false,false);
bool V[64] = bool[64](false,false,false,false,false,false,false,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,false,true,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,false,true,true,false,false,false,false,false,false,true,true,false,false,false,false,false,false,false,false,false,false,false);
bool W[64] = bool[64](false,false,false,false,false,false,false,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,true,false,false,false,false,true,false,false,true,false,true,true,false,true,false,false,true,true,false,false,true,true,false,false,true,false,false,false,false,true,false,false,false,false,false,false,false,false,false);
bool X[64] = bool[64](false,false,false,false,false,false,false,false,false,true,false,false,false,false,true,false,false,false,true,false,false,true,false,false,false,false,false,true,true,false,false,false,false,false,false,true,true,false,false,false,false,false,true,false,false,true,false,false,false,true,false,false,false,false,true,false,false,false,false,false,false,false,false,false);
bool Y[64] = bool[64](false,false,false,false,false,false,false,false,false,true,false,false,false,false,true,false,false,false,true,false,false,true,false,false,false,false,false,true,true,false,false,false,false,false,false,true,true,false,false,false,false,false,false,true,true,false,false,false,false,false,false,true,true,false,false,false,false,false,false,false,false,false,false,false);
bool Z[64] = bool[64](false,false,false,false,false,false,false,false,false,true,true,true,true,true,true,false,false,false,false,false,false,true,false,false,false,false,false,false,true,false,false,false,false,false,false,true,false,false,false,false,false,false,true,false,false,false,false,false,false,true,true,true,true,true,true,false,false,false,false,false,false,false,false,false);

bool getGrid(int c, int idx) {
    if (c == 0) return A[idx]; if (c == 1) return B[idx]; if (c == 2) return C[idx];
    if (c == 3) return D[idx]; if (c == 4) return E[idx]; if (c == 5) return F[idx];
    if (c == 6) return G[idx]; if (c == 7) return H[idx]; if (c == 8) return I[idx];
    if (c == 9) return J[idx]; if (c == 10) return K[idx]; if (c == 11) return L[idx];
    if (c == 12) return M[idx]; if (c == 13) return N[idx]; if (c == 14) return O[idx];
    if (c == 15) return P[idx]; if (c == 16) return Q[idx]; if (c == 17) return R[idx];
    if (c == 18) return S[idx]; if (c == 19) return T[idx]; if (c == 20) return U[idx];
    if (c == 21) return V[idx]; if (c == 22) return W[idx]; if (c == 23) return X[idx];
    if (c == 24) return Y[idx];
    return Z[idx];
}

float testScore(bool store[64], int ci) {
    float score = 0.0;
    for (int x = 0; x < 8; x++) {
        for (int y = 0; y < 8; y++) {
            int idx = x + y * 8;
            if (store[idx] == getGrid(ci, idx)) score += 1.0; else score -= 1.0;
        }
    }
    return score;
}

int bestChar(bool store[64]) {
    int best = 0;
    float bestScore = -9999.0;
    for (int c = 0; c < 26; c++) {
        float s = testScore(store, c);
        if (s > bestScore) { bestScore = s; best = c; }
    }
    return best;
}

void main() {
    vec2 blockCoord = floor(gl_FragCoord.xy / 8.0) * 8.0;
    vec2 uv = blockCoord / u_resolution;
    vec2 f = floor(mod(gl_FragCoord.xy, 8.0));

    vec4 og = texture2D(u_texture, uv);
    float ref = length(og.rgb) / 1.1 + 0.1;

    bool stored[64];
    for (float y = 0.0; y < 8.0; y++) {
        for (float x = 0.0; x < 8.0; x++) {
            float bright = length(texture2D(u_texture, uv + vec2(x, y) / u_resolution).rgb);
            stored[int(x + y * 8.0)] = bright > ref;
        }
    }

    int c = bestChar(stored);
    bool on = getGrid(c, int(f.x) + int(f.y) * 8);
    gl_FragColor = on ? vec4(0.0, 1.8, 0.0, 1.0) : vec4(0.0, 0.0, 0.0, 1.0);
}`,
  },
];

export const DEFAULT_FILTER = FILTER_PRESETS[0].source;

function buildShader(src: string): string {
  return `
    precision mediump float;
    uniform sampler2D u_texture;
    uniform float u_time;
    uniform vec2 u_resolution;
    varying vec2 v_texCoord;
    ${src}
  `;
}

export function useWebGLFilter() {
  const compileError = ref('');
  const isActive = ref(false);
  let canvasEl: HTMLCanvasElement | null = null;
  let gl: WebGLRenderingContext | null = null;
  let program: WebGLProgram | null = null;
  let videoEl: HTMLVideoElement | null = null;
  let videoCbId = 0;
  let startTime = 0;
  let texture: WebGLTexture | null = null;
  let positionBuf: WebGLBuffer | null = null;
  let texCoordBuf: WebGLBuffer | null = null;
  let uTimeLoc: WebGLUniformLocation | null = null;
  let uResLoc: WebGLUniformLocation | null = null;

  function compileOne(type: number, src: string): WebGLShader | null {
    if (!gl) return null;
    const s = gl.createShader(type);
    if (!s) return null;
    gl.shaderSource(s, src);
    gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
      compileError.value = gl.getShaderInfoLog(s) || 'Compile error';
      gl.deleteShader(s);
      return null;
    }
    return s;
  }

  function compile(src: string): boolean {
    if (!gl) return false;
    const vs = compileOne(gl.VERTEX_SHADER, VERTEX_SHADER);
    const fs = compileOne(gl.FRAGMENT_SHADER, buildShader(src));
    if (!vs || !fs) return false;

    const prog = gl.createProgram();
    if (!prog) { compileError.value = 'Failed to create program'; return false; }

    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);

    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
      compileError.value = gl.getProgramInfoLog(prog) || 'Link failed';
      gl.deleteProgram(prog);
      return false;
    }

    if (program) gl.deleteProgram(program);
    program = prog;
    gl.useProgram(program);

    uTimeLoc = gl.getUniformLocation(program, 'u_time');
    uResLoc = gl.getUniformLocation(program, 'u_resolution');
    compileError.value = '';
    return true;
  }

  function setupGeometry(): void {
    if (!gl) return;
    positionBuf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, positionBuf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([
      -1, -1,  1, -1,  -1,  1,
      -1,  1,  1, -1,   1,  1,
    ]), gl.STATIC_DRAW);

    texCoordBuf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, texCoordBuf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([
      0, 1,  1, 1,  0, 0,
      0, 0,  1, 1,  1, 0,
    ]), gl.STATIC_DRAW);
  }

  function render(now: number, _md: VideoFrameCallbackMetadata): void {
    if (!gl || !program || !videoEl || !canvasEl) return;

    const vw = videoEl.videoWidth;
    const vh = videoEl.videoHeight;
    if (vw === 0 || vh === 0) {
      videoCbId = videoEl.requestVideoFrameCallback(render);
      return;
    }

    if (canvasEl.width !== vw || canvasEl.height !== vh) {
      canvasEl.width = vw;
      canvasEl.height = vh;
    }

    gl.viewport(0, 0, vw, vh);
    gl.clear(gl.COLOR_BUFFER_BIT);

    if (!texture) {
      texture = gl.createTexture();
      gl.bindTexture(gl.TEXTURE_2D, texture);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    }

    gl.bindTexture(gl.TEXTURE_2D, texture);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, videoEl);

    const posLoc = gl.getAttribLocation(program, 'a_position');
    const texLoc = gl.getAttribLocation(program, 'a_texCoord');

    gl.bindBuffer(gl.ARRAY_BUFFER, positionBuf);
    gl.enableVertexAttribArray(posLoc);
    gl.vertexAttribPointer(posLoc, 2, gl.FLOAT, false, 0, 0);

    gl.bindBuffer(gl.ARRAY_BUFFER, texCoordBuf);
    gl.enableVertexAttribArray(texLoc);
    gl.vertexAttribPointer(texLoc, 2, gl.FLOAT, false, 0, 0);

    if (uTimeLoc) gl.uniform1f(uTimeLoc, (now - startTime) / 1000);
    if (uResLoc) gl.uniform2f(uResLoc, vw, vh);

    gl.drawArrays(gl.TRIANGLES, 0, 6);

    videoCbId = videoEl.requestVideoFrameCallback(render);
  }

  function setShader(src: string): boolean {
    return compile(src);
  }

  function start(video: HTMLVideoElement): HTMLCanvasElement | null {
    canvasEl = document.createElement('canvas');
    canvasEl.style.cssText = 'position:absolute;top:0;left:0;width:100%;height:100%;object-fit:contain;';

    gl = canvasEl.getContext('webgl', { premultipliedAlpha: false });
    if (!gl) {
      compileError.value = 'WebGL not supported';
      return null;
    }

    videoEl = video;
    startTime = performance.now();
    isActive.value = true;

    setupGeometry();
    compile(DEFAULT_FILTER);

    videoCbId = video.requestVideoFrameCallback(render);
    return canvasEl;
  }

  function stop(): void {
    if (videoEl && videoCbId) {
      videoEl.cancelVideoFrameCallback(videoCbId);
    }

    if (gl) {
      if (program) gl.deleteProgram(program);
      if (texture) gl.deleteTexture(texture);
      gl = null;
    }
    program = null;
    texture = null;
    positionBuf = null;
    texCoordBuf = null;
    videoEl = null;
    canvasEl = null;
    isActive.value = false;
    compileError.value = '';
  }

  return {
    compileError,
    isActive,
    setShader,
    start,
    stop,
  };
}
