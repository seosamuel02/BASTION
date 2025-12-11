<!-- FieldSidebar.vue: 필드 목록 사이드바 (토글 열림/닫힘) -->
<template>
  <div class="field-sidebar" :class="{ collapsed: !open }">
    <button class="toggle" @click="$emit('toggle')">
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
        <div class="field-list">
          <div v-for="name in filteredFields" :key="name" class="field-item">
            <span class="pill">k</span>
            <span class="name">{{ name }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue';

// ❖ 필드 목록: Discover 결과 columns 기반으로 표시, 키워드 필터 지원
const props = defineProps({
  fields: {
    type: Array,
    default: () => []
  },
  open: {
    type: Boolean,
    default: true
  }
});

defineEmits(['toggle']);

const keyword = ref('');

const filteredFields = computed(() => {
  const k = keyword.value.trim().toLowerCase();
  if (!k) return props.fields;
  return props.fields.filter((f) => f && f.toLowerCase().includes(k));
});
</script>

<style scoped>
.field-sidebar {
  position: relative;
  background: #0b1221;
  border: 1px solid #1f2937;
  border-radius: 10px;
  padding: 0.65rem;
  width: 260px;
  transition: width 0.2s ease, padding 0.2s ease;
}

.field-sidebar.collapsed {
  width: 64px;
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
}

.field-item {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.35rem 0.4rem;
  border-radius: 8px;
  background: #0f172a;
  border: 1px solid #1f2937;
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
  word-break: break-all;
}
</style>
