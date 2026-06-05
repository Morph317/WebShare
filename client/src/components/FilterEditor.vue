<template>
  <div class="filter-editor">
    <div class="filter-header">
      <span class="filter-title">滤镜编辑器</span>
      <button class="btn-close" @click="$emit('close')" title="隐藏面板">×</button>
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
      <div class="code-editor">
        <div class="line-numbers" ref="lineNumbersRef">
          <div v-for="n in lineCount" :key="n">{{ n }}</div>
        </div>
        <textarea
          ref="textareaRef"
          class="code-textarea"
          :value="code"
          @input="onCodeChange($event)"
          @keydown="onKeyDown($event)"
          @scroll="syncScroll"
          placeholder="void main() { ... }"
          spellcheck="false"
          autocomplete="off"
          autocorrect="off"
          autocapitalize="off"
          wrap="off"
        ></textarea>
      </div>
    </div>

    <div class="filter-error" v-if="error">
      {{ error }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
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
const textareaRef = ref<HTMLTextAreaElement | null>(null);
const lineNumbersRef = ref<HTMLDivElement | null>(null);

const lineCount = computed(() => props.code.split('\n').length);

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

function onKeyDown(event: KeyboardEvent): void {
  if (event.key === 'Tab') {
    event.preventDefault();
    const textarea = event.target as HTMLTextAreaElement;
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const before = textarea.value.substring(0, start);
    const after = textarea.value.substring(end);

    if (event.shiftKey) {
      const lineStart = before.lastIndexOf('\n', start - 1) + 1;
      const lineContent = before.substring(lineStart, start);
      const remove = Math.min(2, lineContent.length);
      if (remove > 0 && lineContent.startsWith('  ')) {
        textarea.value = before.substring(0, lineStart) + before.substring(lineStart + remove) + after;
        textarea.selectionStart = textarea.selectionEnd = start - remove;
        textarea.dispatchEvent(new Event('input', { bubbles: true }));
      }
    } else {
      textarea.value = before + '  ' + after;
      textarea.selectionStart = textarea.selectionEnd = start + 2;
      textarea.dispatchEvent(new Event('input', { bubbles: true }));
    }
  }
}

function syncScroll(): void {
  if (textareaRef.value && lineNumbersRef.value) {
    lineNumbersRef.value.scrollTop = textareaRef.value.scrollTop;
  }
}
</script>

<style scoped>
.filter-editor {
  width: 320px;
  display: flex;
  flex-direction: column;
  background: #0d0d1a;
  border-left: 1px solid rgba(255, 255, 255, 0.06);
}
.filter-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 14px;
  background: rgba(255, 255, 255, 0.02);
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
}
.filter-title {
  font-size: 13px;
  font-weight: 600;
  color: #ccc;
}
.btn-close {
  padding: 4px 10px;
  border: none;
  border-radius: 4px;
  background: none;
  color: #888;
  font-size: 18px;
  cursor: pointer;
  line-height: 1;
}
.btn-close:hover {
  color: #f44336;
  background: rgba(244, 67, 54, 0.1);
}
.filter-presets {
  padding: 10px 14px 6px;
}
.filter-label {
  display: block;
  font-size: 10px;
  color: #666;
  margin-bottom: 4px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.preset-select {
  width: 100%;
  padding: 6px 8px;
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 4px;
  background: rgba(255, 255, 255, 0.04);
  color: #ccc;
  font-size: 12px;
  outline: none;
}
.preset-select:focus {
  border-color: #7c4dff;
}
.preset-select option {
  background: #141425;
  color: #ccc;
}
.filter-code-section {
  flex: 1;
  padding: 10px 14px;
  display: flex;
  flex-direction: column;
  min-height: 0;
}
.code-editor {
  flex: 1;
  display: flex;
  min-height: 0;
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 6px;
  overflow: hidden;
  background: #080812;
}
.code-editor:focus-within {
  border-color: #7c4dff;
}
.line-numbers {
  flex-shrink: 0;
  padding: 10px 0;
  overflow: hidden;
  color: #3a3a4a;
  font-size: 12px;
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', 'Courier New', monospace;
  line-height: 1.6;
  text-align: right;
  user-select: none;
  background: rgba(0, 0, 0, 0.2);
  border-right: 1px solid rgba(255, 255, 255, 0.05);
}
.line-numbers div {
  padding: 0 10px 0 4px;
  min-width: 30px;
}
.code-textarea {
  flex: 1;
  padding: 10px 12px;
  border: none;
  outline: none;
  resize: none;
  background: transparent;
  color: #a0c8a0;
  font-size: 12px;
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', 'Courier New', monospace;
  line-height: 1.6;
  tab-size: 2;
  -moz-tab-size: 2;
  overflow: auto;
  white-space: pre;
}
.code-textarea::placeholder {
  color: #333;
}
.code-textarea::selection {
  background: rgba(124, 77, 255, 0.3);
}
.code-textarea::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}
.code-textarea::-webkit-scrollbar-track {
  background: transparent;
}
.code-textarea::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.08);
  border-radius: 3px;
}
.filter-error {
  padding: 8px 14px;
  margin: 0 14px 10px;
  background: rgba(244, 67, 54, 0.12);
  border: 1px solid rgba(244, 67, 54, 0.3);
  border-radius: 6px;
  font-size: 11px;
  color: #ef9a9a;
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', 'Courier New', monospace;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
