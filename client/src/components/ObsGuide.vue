<template>
  <div class="modal-overlay" @click.self="$emit('close')">
    <div class="modal-content obs-guide">
      <div class="modal-header">
        <h2>OBS 推流指南</h2>
        <button class="btn-close" @click="$emit('close')">✕</button>
      </div>

      <div class="tab-bar">
        <button :class="{ active: tab === 'rtmp' }" @click="tab = 'rtmp'">RTMP 模式（推荐）</button>
        <button :class="{ active: tab === 'whip' }" @click="tab = 'whip'">WHIP 模式</button>
      </div>

      <!-- RTMP tab -->
      <div v-if="tab === 'rtmp'" class="tab-content">
        <div class="step">
          <div class="step-num">1</div>
          <div class="step-body">
            <strong>打开 OBS 设置 → 推流</strong>
            <p>服务：自定义</p>
            <p>服务器：<code class="url-box" @click="copyText(rtmpServer)" :title="copied === rtmpServer ? '已复制!' : '点击复制'">{{ rtmpServer }}</code></p>
            <p>串流密钥：<code class="url-box" @click="copyText('default')" :title="copied === 'default' ? '已复制!' : '点击复制'">default</code></p>
          </div>
        </div>
        <div class="step">
          <div class="step-num">2</div>
          <div class="step-body">
            <strong>设置视频编码器</strong>
            <p>输出 → 编码器：x264（软件）或 NVENC/AMF/QSV（硬件）</p>
            <p>速率控制：CBR，码率 5000-10000 Kbps</p>
            <p>关键帧间隔：2 秒</p>
          </div>
        </div>
        <div class="step">
          <div class="step-num">3</div>
          <div class="step-body">
            <strong>设置音频编码器</strong>
            <p>编码器：FFmpeg AAC 或 libopus</p>
            <p>比特率：128-192 Kbps，声道：立体声</p>
          </div>
        </div>
        <div class="step">
          <div class="step-num">4</div>
          <div class="step-body">
            <strong>高级设置</strong>
            <p>bframes = 0（必须关闭 B 帧，RTMP 不支持）</p>
            <p>tune = zerolatency（降低延迟）</p>
            <p>profile = baseline 或 main</p>
            <p>点击 "开始推流"</p>
          </div>
        </div>
        <div class="note">
          ✅ RTMP 延迟约 2-5 秒，稳定可靠 | 需要开放端口 1935
        </div>
      </div>

      <!-- WHIP tab -->
      <div v-if="tab === 'whip'" class="tab-content">
        <div class="step">
          <div class="step-num">1</div>
          <div class="step-body">
            <strong>打开 OBS 设置 → 推流</strong>
            <p>服务：WHIP</p>
            <p>WHIP 服务器 URL：<code class="url-box" @click="copyText(whipUrl)" :title="copied === whipUrl ? '已复制!' : '点击复制'">{{ whipUrl }}</code></p>
            <p>不填 Bearer Token</p>
          </div>
        </div>
        <div class="step">
          <div class="step-num">2</div>
          <div class="step-body">
            <strong>设置视频编码器</strong>
            <p>编码器：x264 或 NVENC/AMF/QSV（H.264）</p>
            <p>速率控制：CBR，码率 5000-10000 Kbps</p>
            <p>关键帧间隔：2 秒，bframes = 0</p>
            <p>tune = zerolatency</p>
          </div>
        </div>
        <div class="step">
          <div class="step-num">3</div>
          <div class="step-body">
            <strong>设置音频编码器</strong>
            <p>编码器：FFmpeg libopus（WHIP 仅支持 Opus）</p>
            <p>比特率：128 Kbps，声道：立体声</p>
          </div>
        </div>
        <div class="step">
          <div class="step-num">4</div>
          <div class="step-body">
            <strong>点击 "开始推流"</strong>
          </div>
        </div>
        <div class="note">
          ⚠ WHIP 延迟 &lt;1 秒，但 OBS 32.x 兼容性不稳定（可能弹编码错误）<br>
          ⚠ 需确保服务器安全组开放 UDP 40000-49999
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';

defineEmits<{ close: [] }>();

const tab = ref<'rtmp' | 'whip'>('rtmp');
const copied = ref('');
const host = window.location.hostname;
const rtmpServer = `rtmp://${host}:1935/live`;
const whipUrl = `http://${host}:8080/api/whip?roomId=default`;

async function copyText(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  }
  copied.value = text;
  setTimeout(() => { copied.value = ''; }, 1500);
}
</script>

<style scoped>
.obs-guide {
  max-width: 560px;
  max-height: 80vh;
  overflow-y: auto;
}
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.6);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}
.modal-content {
  background: #1e1e2e;
  border: 1px solid #333;
  border-radius: 10px;
  padding: 0;
  color: #e0e0e0;
}
.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 20px;
  border-bottom: 1px solid #333;
}
.modal-header h2 { margin: 0; font-size: 18px; }
.btn-close {
  background: none;
  border: none;
  color: #888;
  font-size: 20px;
  cursor: pointer;
  padding: 4px 8px;
}
.btn-close:hover { color: #fff; }

.tab-bar {
  display: flex;
  border-bottom: 1px solid #333;
}
.tab-bar button {
  flex: 1;
  background: none;
  border: none;
  color: #888;
  padding: 10px 16px;
  cursor: pointer;
  font-size: 14px;
  border-bottom: 2px solid transparent;
}
.tab-bar button.active {
  color: #4fc3f7;
  border-bottom-color: #4fc3f7;
}

.tab-content { padding: 16px 20px; }
.step {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
}
.step-num {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  background: #4fc3f7;
  color: #1e1e2e;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: bold;
  font-size: 14px;
  flex-shrink: 0;
}
.step-body strong { display: block; margin-bottom: 4px; }
.step-body p { margin: 2px 0; font-size: 13px; color: #aaa; }
.url-box {
  display: inline-block;
  background: #111;
  color: #4fc3f7;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 12px;
  word-break: break-all;
  cursor: pointer;
  transition: background 0.15s;
}
.url-box:hover {
  background: #2a2a4e;
}
.note {
  background: #2a2a3e;
  border-radius: 6px;
  padding: 10px 14px;
  font-size: 13px;
  color: #aaa;
  margin-top: 12px;
  line-height: 1.6;
}
</style>
