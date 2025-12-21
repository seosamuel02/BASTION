<!-- FieldFilter.vue: Field filters list with add/update/remove -->
<template>
  <div class="field-filter">
    <div class="heading-row">
      <div>
        <p class="label">Field filters</p>
        <p class="hint">Add, edit, and remove filters; emits to parent</p>
      </div>
      <span class="badge">{{ filters.length }}</span>
    </div>

    <div v-if="filters.length === 0" class="empty">
      No filters added yet.
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
          placeholder="Field e.g. host.name"
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
          placeholder="Value"
          @input="update(filter.id, 'value', $event.target.value)"
        >
        <button class="ghost-btn" @click="remove(filter.id)">Remove</button>
      </div>
    </div>

    <div class="new-filter">
      <input
        class="input"
        type="text"
        v-model="newFilter.field"
        placeholder="New filter field"
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
        placeholder="Value"
      >
      <button class="add-btn" @click="add">Add</button>
    </div>
  </div>
</template>

<script setup>
import { reactive } from 'vue';

// FieldFilter: renders list and emits add/update/remove events
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
  color: var(--text-primary, #e0e6ed);
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
  border-radius: 8px;
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
  background: #0f1419;
  color: #e5e7eb;
  border: 1px solid #1f2937;
  border-radius: 8px;
  padding: 0.55rem 0.7rem;
  font-size: 0.9rem;
  min-height: 40px;
  box-shadow: inset 0 0 0 1px rgba(0, 255, 136, 0.02);
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
  transition: all 0.15s ease;
}

.add-btn {
  background: linear-gradient(135deg, var(--cyber-green, #00ff88), #00b46b);
  color: #0a0e12;
  border: 1px solid #00b46b;
  padding: 0.55rem 0.9rem;
  border-radius: 8px;
  cursor: pointer;
  font-weight: 600;
  letter-spacing: 0.02em;
  box-shadow: 0 6px 18px rgba(0, 255, 136, 0.25);
  transition: transform 0.15s ease, box-shadow 0.2s ease;
}

.add-btn:hover {
  filter: brightness(1.05);
  transform: translateY(-1px);
  box-shadow: 0 10px 24px rgba(0, 255, 136, 0.3);
}

.ghost-btn:hover {
  border-color: #f87171;
  box-shadow: 0 6px 18px rgba(248, 113, 113, 0.15);
}

@media (max-width: 640px) {
  .filter-row,
  .new-filter {
    grid-template-columns: 1fr;
  }
}
</style>
