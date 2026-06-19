<template>
  <div class="connection-bar">
    <div class="status-indicator">
      <span class="dot" :class="statusClass"></span>
      <span class="status-text">{{ statusText }}</span>
    </div>
    <div class="connection-info" v-if="state === 'connected'">
      <span class="room-badge">{{ roomId }}</span>
      <div class="spacer"></div>
      <div class="settings-wrapper">
        <button class="btn btn-settings" @click="showSettings = !showSettings" title="设置">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="3"/>
            <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/>
          </svg>
        </button>
        <div class="settings-dropdown" v-if="showSettings">
          <label class="settings-label">展示名</label>
          <input
            class="settings-input"
            v-model="editName"
            placeholder="输入展示名..."
            @keyup.enter="saveDisplayName"
          />
          <div class="settings-actions">
            <button class="btn btn-save" @click="saveDisplayName">保存</button>
            <button class="btn btn-cancel" @click="cancelEdit">取消</button>
          </div>
          <div class="settings-divider"></div>
          <!-- WebGL filter temporarily disabled -->
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue';

const props = defineProps<{
  state: 'disconnected' | 'connecting' | 'connected';
  roomId: string;
  displayName: string;
  filterEnabled: boolean;
  filterEditorVisible: boolean;
}>();

const emit = defineEmits<{
  'update-display-name': [name: string];
  'toggle-filter': [];
  'toggle-filter-editor': [];
}>();

const showSettings = ref(false);
const editName = ref(props.displayName);

function saveDisplayName(): void {
  const name = editName.value.trim();
  if (name) {
    emit('update-display-name', name);
    showSettings.value = false;
  }
}

function cancelEdit(): void {
  editName.value = props.displayName;
  showSettings.value = false;
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
  flex: 1;
}
.spacer {
  flex: 1;
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
.room-badge {
  font-size: 12px;
  padding: 3px 10px;
  background: rgba(124, 77, 255, 0.2);
  color: #b388ff;
  border-radius: 4px;
}
.settings-wrapper {
  position: relative;
}
.btn-settings {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  padding: 0;
  background: rgba(255, 255, 255, 0.06);
  color: #aaa;
  border-radius: 6px;
}
.btn-settings:hover {
  background: rgba(255, 255, 255, 0.12);
  color: #e0e0e0;
}
.settings-dropdown {
  position: absolute;
  top: calc(100% + 8px);
  right: 0;
  min-width: 220px;
  background: #1e1e32;
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 8px;
  padding: 14px;
  z-index: 100;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
}
.settings-label {
  display: block;
  font-size: 12px;
  color: #888;
  margin-bottom: 6px;
}
.settings-input {
  width: 100%;
  box-sizing: border-box;
  padding: 6px 10px;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 6px;
  background: rgba(255, 255, 255, 0.06);
  color: #e0e0e0;
  font-size: 13px;
  outline: none;
  margin-bottom: 10px;
}
.settings-input:focus {
  border-color: #7c4dff;
}
.settings-input::placeholder {
  color: #555;
}
.settings-divider {
  height: 1px;
  background: rgba(255, 255, 255, 0.08);
  margin: 10px 0;
}
.settings-toggle {
  display: flex;
  align-items: center;
  justify-content: space-between;
  cursor: pointer;
  padding: 4px 0;
}
.toggle-label {
  font-size: 12px;
  color: #aaa;
}
.toggle-switch {
  width: 36px;
  height: 20px;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.12);
  position: relative;
  transition: background 0.2s;
  flex-shrink: 0;
}
.toggle-switch.on {
  background: #7c4dff;
}
.toggle-knob {
  position: absolute;
  top: 2px;
  left: 2px;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  background: #fff;
  transition: transform 0.2s;
}
.toggle-switch.on .toggle-knob {
  transform: translateX(16px);
}
.btn-edit-filter {
  display: block;
  width: 100%;
  margin-top: 8px;
  padding: 5px 0;
  background: rgba(124, 77, 255, 0.15);
  color: #b388ff;
  border: none;
  border-radius: 6px;
  font-size: 12px;
  cursor: pointer;
}
.btn-edit-filter:hover {
  background: rgba(124, 77, 255, 0.3);
}
.settings-actions {
  display: flex;
  gap: 8px;
  justify-content: flex-end;
}
.btn-save {
  padding: 5px 14px;
  background: #7c4dff;
  color: #fff;
  border: none;
  border-radius: 6px;
  font-size: 12px;
  cursor: pointer;
}
.btn-save:hover {
  background: #651fff;
}
.btn-cancel {
  padding: 5px 14px;
  background: rgba(255, 255, 255, 0.06);
  color: #aaa;
  border: none;
  border-radius: 6px;
  font-size: 12px;
  cursor: pointer;
}
.btn-cancel:hover {
  background: rgba(255, 255, 255, 0.12);
  color: #e0e0e0;
}
</style>
