<!-- FieldFilter.vue: 필드 필터 목록을 표시·추가·수정·삭제 -->
<template>
  <div class="field-filter">
    <div class="heading-row">
      <div>
        <p class="label">필드 필터</p>
        <p class="hint">필터 추가/수정은 상위 state로 emit</p>
      </div>
      <span class="badge">{{ filters.length }}</span>
    </div>

    <div v-if="filters.length === 0" class="empty">
      아직 추가된 필터가 없습니다.
    </div>
    <div v-else class="filter-list">
      <div
        v-for="filter in filters"
        :key="filter.id"
        class="filter-row"
      >
        <input
          class="input"
          type="text"
          :value="filter.field"
          placeholder="field 예) host.name"
          @input="update(filter.id, 'field', $event.target.value)"
        >
        <select
          class="select"
          :value="filter.operator"
          @change="update(filter.id, 'operator', $event.target.value)"
        >
          <option value="is">is</option>
          <option value="is not">is not</option>
          <option value="contains">contains</option>
        </select>
        <input
          class="input"
          type="text"
          :value="filter.value"
          placeholder="value"
          @input="update(filter.id, 'value', $event.target.value)"
        >
        <button class="ghost-btn" @click="remove(filter.id)">삭제</button>
      </div>
    </div>

    <div class="new-filter">
      <input
        class="input"
        type="text"
        v-model="newFilter.field"
        placeholder="새 필터 field"
      >
      <select class="select" v-model="newFilter.operator">
        <option value="is">is</option>
        <option value="is not">is not</option>
        <option value="contains">contains</option>
      </select>
      <input
        class="input"
        type="text"
        v-model="newFilter.value"
        placeholder="value"
      >
      <button class="add-btn" @click="add">추가</button>
    </div>
  </div>
</template>

<script setup>
import { reactive } from 'vue';

// ❖ FieldFilter: 리스트를 표시하고 수정/삭제/추가 이벤트를 emit
const props = defineProps({
  filters: {
    type: Array,
    default: () => []
  }
});

const emit = defineEmits(['add-filter', 'update-filter', 'remove-filter']);

const newFilter = reactive({
  field: '',
  operator: 'is',
  value: ''
});

const update = (id, key, value) => {
  emit('update-filter', { id, [key]: value });
};

const remove = (id) => {
  emit('remove-filter', id);
};

const add = () => {
  if (!newFilter.field || !newFilter.value) {
    return;
  }
  emit('add-filter', { ...newFilter });
  newFilter.field = '';
  newFilter.value = '';
  newFilter.operator = 'is';
};
</script>

<style scoped>
.field-filter {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  height: 100%;
}

.heading-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.label {
  color: #cbd5e1;
  font-weight: 600;
  margin: 0;
}

.hint {
  color: #94a3b8;
  font-size: 0.8rem;
  margin: 0.1rem 0 0;
}

.badge {
  background: #1f2937;
  border: 1px solid #334155;
  color: #e5e7eb;
  border-radius: 12px;
  padding: 0.2rem 0.55rem;
  font-size: 0.85rem;
}

.empty {
  padding: 0.75rem;
  background: #0b1221;
  border: 1px dashed #1f2937;
  border-radius: 6px;
  color: #94a3b8;
  font-size: 0.9rem;
}

.filter-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.filter-row {
  display: grid;
  grid-template-columns: 1fr 0.9fr 1fr auto;
  gap: 0.45rem;
  align-items: center;
}

.input,
.select {
  background: #0b1221;
  color: #e5e7eb;
  border: 1px solid #1f2937;
  border-radius: 8px;
  padding: 0.5rem 0.65rem;
  font-size: 0.9rem;
  min-height: 40px;
}

.new-filter {
  display: grid;
  grid-template-columns: 1fr 0.9fr 1fr auto;
  gap: 0.45rem;
  align-items: center;
  padding-top: 0.35rem;
  border-top: 1px solid #1f2937;
}

.ghost-btn {
  background: transparent;
  color: #f87171;
  border: 1px solid #334155;
  padding: 0.45rem 0.65rem;
  border-radius: 8px;
  cursor: pointer;
  min-height: 40px;
}

.add-btn {
  background: linear-gradient(135deg, #3273dc, #285bb5);
  color: #e5e7eb;
  border: 1px solid #285bb5;
  padding: 0.5rem 0.9rem;
  border-radius: 8px;
  cursor: pointer;
  font-weight: 600;
}

.add-btn:hover {
  filter: brightness(1.05);
}

.ghost-btn:hover {
  border-color: #f87171;
}

@media (max-width: 640px) {
  .filter-row,
  .new-filter {
    grid-template-columns: 1fr;
  }
}
</style>
