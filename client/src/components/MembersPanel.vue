<template>
  <div class="members-panel">
    <div class="panel-header">
      <span class="panel-title">成员 · {{ members.length }}</span>
    </div>
    <div class="member-list">
      <div
        v-for="member in members"
        :key="member.peerId"
        class="member-item"
        :class="{ 'is-self': member.peerId === selfPeerId }"
      >
        <div class="member-avatar" :class="member.peerId === selfPeerId ? 'self' : 'other'">
          {{ getInitial(member.displayName) }}
        </div>
        <div class="member-info">
          <div class="member-name">
            {{ member.displayName }}
            <span v-if="member.isSharing" class="sharing-dot" title="正在共享">●</span>
          </div>
          <div class="member-peerid">{{ member.peerId }}</div>
        </div>
      </div>
      <div v-if="members.length === 0" class="empty-members">
        暂无成员
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import type { PeerInfo } from '../types';

defineProps<{
  members: PeerInfo[];
  selfPeerId: string;
}>();

function getInitial(name: string): string {
  // Extract meaningful initial: e.g. "Chrome on Windows" -> "C"
  const parts = name.split(' ');
  for (const part of parts) {
    if (part.length > 0 && part[0].toUpperCase() !== part[0].toLowerCase()) {
      return part[0].toUpperCase();
    }
  }
  return name.charAt(0).toUpperCase();
}
</script>

<style scoped>
.members-panel {
  width: 240px;
  background: rgba(255, 255, 255, 0.03);
  border-right: 1px solid rgba(255, 255, 255, 0.06);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
}
.panel-header {
  padding: 12px 14px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
}
.panel-title {
  font-size: 14px;
  font-weight: 600;
  color: #ccc;
}
.member-list {
  flex: 1;
  overflow-y: auto;
  padding: 6px 0;
}
.member-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 14px;
  transition: background 0.15s;
}
.member-item:hover {
  background: rgba(255, 255, 255, 0.04);
}
.member-avatar {
  width: 34px;
  height: 34px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 14px;
  font-weight: 600;
  flex-shrink: 0;
}
.member-avatar.self {
  background: #7c4dff;
  color: #fff;
}
.member-avatar.other {
  background: #4caf50;
  color: #fff;
}
.member-info {
  min-width: 0;
}
.member-name {
  font-size: 13px;
  color: #e0e0e0;
  display: flex;
  align-items: center;
  gap: 6px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.sharing-dot {
  color: #4caf50;
  font-size: 10px;
  flex-shrink: 0;
}
.member-peerid {
  font-size: 11px;
  color: #666;
  margin-top: 1px;
}
.empty-members {
  padding: 20px 14px;
  font-size: 13px;
  color: #555;
  text-align: center;
}
</style>
