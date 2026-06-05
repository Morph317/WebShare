<template>
  <div class="filter-editor">
    <div class="filter-header">
      <span class="filter-title">滤镜编辑器</span>
      <button class="btn-close" @click="$emit('close')" title="关闭滤镜">×</button>
    </div>

    <div class="filter-presets">
      <label class="filter-label">预设</label>
      <select class="preset-select" @change="onPresetChange($event)">
        <option value="">选择预设...</option>
        <option v-for="p in presets" :key="p.name" :value="p.name">{{ p.name }}</option>
      </select>
    </div>

    <div class="filter-code-section">
      <label class="filter-label">GLSL 代码</label>
      <textarea
        class="filter-textarea"
        :value="code"
        @input="onCodeChange($event)"
        placeholder="void main() { ... }"
        spellcheck="false"
      ></textarea>
    </div>

    <div class="filter-error" v-if="error">
      {{ error }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { FILTER_PRESETS, type FilterPreset } from '../composables/useWebGLFilter';

const props = defineProps<{
  code: string;
  error: string;
}>();

const emit = defineEmits<{
  'update:code': [code: string];
  'close': [];
}>();

const presets: FilterPreset[] = FILTER_PRESETS;

function onPresetChange(event: Event): void {
  const select = event.target as HTMLSelectElement;
  const name = select.value;
  if (!name) return;
  const preset = presets.find((p) => p.name === name);
  if (preset) {
    emit('update:code', preset.source);
  }
  select.value = '';
}

function onCodeChange(event: Event): void {
  const textarea = event.target as HTMLTextAreaElement;
  emit('update:code', textarea.value);
}
</script>

<style scoped>
.filter-editor {
  width: 280px;
  display: flex;
  flex-direction: column;
  background: #141425;
  border-left: 1px solid rgba(255, 255, 255, 0.06);
  overflow-y: auto;
}
.filter-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 14px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
}
.filter-title {
  font-size: 13px;
  font-weight: 500;
  color: #ccc;
}
.btn-close {
  padding: 2px 8px;
  border: none;
  background: none;
  color: #888;
  font-size: 18px;
  cursor: pointer;
  line-height: 1;
}
.btn-close:hover {
  color: #f44336;
}
.filter-presets {
  padding: 10px 14px 6px;
}
.filter-label {
  display: block;
  font-size: 11px;
  color: #777;
  margin-bottom: 4px;
}
.preset-select {
  width: 100%;
  padding: 6px 8px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 4px;
  background: rgba(255, 255, 255, 0.05);
  color: #ccc;
  font-size: 12px;
  outline: none;
}
.preset-select:focus {
  border-color: #7c4dff;
}
.preset-select option {
  background: #1e1e32;
  color: #ccc;
}
.filter-code-section {
  flex: 1;
  padding: 10px 14px;
  display: flex;
  flex-direction: column;
  min-height: 0;
}
.filter-textarea {
  flex: 1;
  min-height: 200px;
  padding: 10px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 6px;
  background: rgba(0, 0, 0, 0.3);
  color: #a0d0a0;
  font-size: 12px;
  font-family: 'Consolas', 'Courier New', monospace;
  line-height: 1.5;
  outline: none;
  resize: none;
  tab-size: 2;
}
.filter-textarea:focus {
  border-color: #7c4dff;
}
.filter-textarea::placeholder {
  color: #444;
}
.filter-error {
  padding: 8px 14px;
  margin: 0 14px 10px;
  background: rgba(244, 67, 54, 0.12);
  border: 1px solid rgba(244, 67, 54, 0.3);
  border-radius: 6px;
  font-size: 11px;
  color: #ef9a9a;
  font-family: 'Consolas', 'Courier New', monospace;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
