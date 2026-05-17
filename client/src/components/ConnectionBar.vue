<template>
  <div class="connection-bar">
    <div class="status-indicator">
      <span class="dot" :class="statusClass"></span>
      <span class="status-text">{{ statusText }}</span>
    </div>
    <div class="connection-info" v-if="state === 'connected'">
      <span class="room-badge">{{ roomId }}</span>
      <button class="btn btn-copy-whip" @click="copyWhipUrl" :title="whipUrl">
        {{ copied ? '已复制!' : '复制 WHIP 地址' }}
      </button>
      <button class="btn btn-disconnect" @click="$emit('disconnect')">断开</button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue';

const props = defineProps<{
  state: 'disconnected' | 'connecting' | 'connected';
  roomId: string;
}>();

defineEmits<{
  disconnect: [];
}>();

const copied = ref(false);

const whipUrl = computed(() => {
  const host = window.location.hostname;
  return `http://${host}:8080/api/whip?roomId=${props.roomId}`;
});

async function copyWhipUrl(): Promise<void> {
  try {
    await navigator.clipboard.writeText(whipUrl.value);
    copied.value = true;
    setTimeout(() => { copied.value = false; }, 2000);
  } catch {
    // Fallback for non-HTTPS
    const ta = document.createElement('textarea');
    ta.value = whipUrl.value;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    copied.value = true;
    setTimeout(() => { copied.value = false; }, 2000);
  }
}

const statusClass = computed(() => {
  if (props.state === 'connected') return 'connected';
  if (props.state === 'connecting') return 'connecting';
  return 'disconnected';
});

const statusText = computed(() => {
  if (props.state === 'connected') return '已连接';
  if (props.state === 'connecting') return '连接中...';
  return '未连接';
});
</script>

<style scoped>
.connection-bar {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 10px 18px;
  background: rgba(255, 255, 255, 0.04);
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
}
.status-indicator {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 100px;
}
.dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  flex-shrink: 0;
}
.dot.disconnected { background: #f44336; }
.dot.connecting { background: #ff9800; animation: pulse 1s infinite; }
.dot.connected { background: #4caf50; }
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}
.status-text {
  font-size: 13px;
  color: #aaa;
}
.connection-inputs {
  display: flex;
  gap: 8px;
  align-items: center;
}
.connection-info {
  display: flex;
  gap: 8px;
  align-items: center;
}
input {
  padding: 6px 12px;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 6px;
  background: rgba(255, 255, 255, 0.06);
  color: #e0e0e0;
  font-size: 13px;
  outline: none;
  min-width: 180px;
}
input:focus {
  border-color: #7c4dff;
}
input::placeholder {
  color: #666;
}
.btn {
  padding: 6px 16px;
  border: none;
  border-radius: 6px;
  font-size: 13px;
  cursor: pointer;
  font-weight: 500;
  white-space: nowrap;
}
.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.btn-connect {
  background: #7c4dff;
  color: #fff;
}
.btn-connect:hover:not(:disabled) {
  background: #651fff;
}
.btn-disconnect {
  background: rgba(244, 67, 54, 0.2);
  color: #f44336;
}
.btn-disconnect:hover {
  background: rgba(244, 67, 54, 0.35);
}
.btn-copy-whip {
  background: rgba(76, 175, 80, 0.2);
  color: #81c784;
  font-size: 12px;
}
.btn-copy-whip:hover {
  background: rgba(76, 175, 80, 0.35);
}
.room-badge {
  font-size: 12px;
  padding: 3px 10px;
  background: rgba(124, 77, 255, 0.2);
  color: #b388ff;
  border-radius: 4px;
}
</style>
