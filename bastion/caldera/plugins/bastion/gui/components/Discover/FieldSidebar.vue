<!-- FieldSidebar.vue: 필드 목록 사이드바 (토글 열림/닫힘) -->
<template>
  <div class="field-sidebar" :class="{ collapsed: !open }">
    <button class="toggle" type="button" @click="$emit('toggle')">
      <span v-if="open">◀ 필드</span>
      <span v-else>필드 ▶</span>
    </button>

    <div v-if="open" class="content">
      <div class="search">
        <input
          class="search-input"
          type="text"
          v-model="keyword"
          placeholder="필드 이름 검색"
        >
        <span class="count">{{ filteredFields.length }}</span>
      </div>

      <div class="section">
        <p class="section-title">Available fields</p>

        <!-- 전체 로그(Document) 토글 -->
        <button
          type="button"
          class="field-item all-doc"
          :class="{ selected: showDocument }"
          @click="emit('toggle-document')"
          title="전체 로그(Document) 보기"
        >
          <span class="pill">∑</span>
          <span class="name">모든 필드(전체 로그)</span>
          <span class="action">{{ showDocument ? '✓' : '+' }}</span>
        </button>

        <div class="field-list">
          <button
            v-for="name in filteredFields"
            :key="name"
            type="button"
            class="field-item"
            :class="{ selected: isSelected(name) }"
            @click="onToggle(name)"
            :title="name"
          >
            <span class="pill">k</span>
            <span class="name">{{ name }}</span>
            <span class="action">{{ isSelected(name) ? '✓' : '+' }}</span>
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue';

const props = defineProps({
  fields: { type: Array, default: () => [] },
  selected: { type: Array, default: () => [] },
  open: { type: Boolean, default: true },
  showDocument: { type: Boolean, default: true }
});

const emit = defineEmits(['toggle', 'toggle-field', 'toggle-document']);

const keyword = ref('');

const filteredFields = computed(() => {
  const k = keyword.value.trim().toLowerCase();
  const list = (props.fields || []).filter(Boolean);
  if (!k) return list;
  return list.filter((f) => f.toLowerCase().includes(k));
});

const isSelected = (name) => (props.selected || []).includes(name);
const onToggle = (name) => emit('toggle-field', name);
</script>

<style scoped>
.field-sidebar {
  position: relative;
  background: #0b1221;
  border: 1px solid #1f2937;
  border-radius: 10px;
  padding: 0.65rem;
  width: 100%;
  min-width: 0;
  transition: padding 0.2s ease;
}

.field-sidebar.collapsed {
  padding: 0.35rem;
}

.toggle {
  width: 100%;
  background: #111827;
  border: 1px solid #1f2937;
  color: #cbd5e1;
  border-radius: 8px;
  padding: 0.4rem 0.55rem;
  cursor: pointer;
  font-size: 0.9rem;
}

.toggle:hover {
  border-color: #3273dc;
  color: #bfdbfe;
}

.content {
  margin-top: 0.5rem;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  min-height: 0;
}

.search {
  display: flex;
  align-items: center;
  gap: 0.4rem;
}

.search-input {
  flex: 1;
  background: #0f172a;
  color: #e5e7eb;
  border: 1px solid #1f2937;
  border-radius: 8px;
  padding: 0.45rem 0.55rem;
  min-width: 0;
}

.count {
  background: #1f2937;
  color: #e5e7eb;
  border: 1px solid #334155;
  border-radius: 8px;
  padding: 0.35rem 0.6rem;
  font-size: 0.85rem;
}

.section-title {
  margin: 0;
  color: #cbd5e1;
  font-weight: 600;
  font-size: 0.9rem;
}

.field-list {
  max-height: 420px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  padding-right: 0.15rem;
  min-height: 0;
}

.all-doc {
  margin-bottom: 0.35rem;
}

.field-item {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.35rem 0.4rem;
  border-radius: 8px;
  background: #0f172a;
  border: 1px solid #1f2937;
  width: 100%;
  cursor: pointer;
  text-align: left;
}

.field-item:hover {
  border-color: #3273dc;
  color: #bfdbfe;
  background: #0f172a;
}

.field-item.selected {
  border-color: #60a5fa;
  background: rgba(37, 99, 235, 0.12);
}

.pill {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 18px;
  height: 18px;
  border-radius: 6px;
  background: #1f2937;
  color: #cbd5e1;
  font-size: 0.75rem;
  font-weight: 700;
}

.name {
  color: #e5e7eb;
  font-size: 0.9rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  min-width: 0;
  flex: 1;
}

.action {
  color: #94a3b8;
  font-weight: 800;
}
</style>