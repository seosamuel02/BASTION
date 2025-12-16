<!-- SearchBar.vue: KQL input and search trigger -->
<template>
  <div class="search-bar">
    <div class="input-wrapper">
      <input
        class="kql-input"
        type="text"
        :value="valueProp"
        placeholder="Enter KQL. Example: event.module:wazuh AND host.name:web-01"
        @input="onInput"
        @keydown.enter.prevent="onSubmit"
      >
    </div>
    <button class="search-button" :disabled="loading" @click="onSubmit">
      <span v-if="loading">Searching...</span>
      <span v-else>Search</span>
    </button>
  </div>
</template>

<script setup>
import { computed } from 'vue';

// SearchBar: KQL input only, emits updates and submit to parent
const props = defineProps({
  kql: { type: String, default: '' },   // compatibility prop
  value: { type: String, default: '' }, // preferred prop
  loading: { type: Boolean, default: false }
});

const emit = defineEmits(['update:kql', 'update:value', 'search', 'submit']);

const valueProp = computed(() => props.value || props.kql || '');

const onInput = (event) => {
  const val = event.target.value;
  emit('update:kql', val);
  emit('update:value', val);
};

const onSubmit = () => {
  emit('search');
  emit('submit');
};
</script>

<style scoped>
.search-bar {
  display: flex;
  gap: 0.6rem;
  align-items: center;
  background: linear-gradient(135deg, rgba(0, 255, 136, 0.04), rgba(0, 0, 0, 0.08));
  border: 1px solid var(--border-color, #2a3a4a);
  border-radius: 10px;
  padding: 0.4rem;
  box-shadow: inset 0 0 0 1px rgba(0, 255, 136, 0.02);
}

.input-wrapper {
  flex: 1;
}

.kql-input {
  width: 100%;
  background: var(--bg-primary, #0f1419);
  color: var(--text-primary, #e0e6ed);
  border: 1px solid var(--border-color, #2a3a4a);
  border-radius: 8px;
  padding: 0.75rem 0.85rem;
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  min-height: 42px;
  box-shadow: 0 0 0 1px rgba(0, 255, 136, 0.02);
}

.kql-input:focus {
  outline: 1px solid var(--cyber-green, #00ff88);
  border-color: var(--cyber-green, #00ff88);
  box-shadow: 0 0 10px rgba(0, 255, 136, 0.25);
}

.search-button {
  background: linear-gradient(135deg, var(--cyber-green, #00ff88), #00b46b);
  color: #0a0e12;
  border: 1px solid #00b46b;
  border-radius: 8px;
  padding: 0.7rem 1.05rem;
  cursor: pointer;
  min-width: 98px;
  min-height: 42px;
  font-weight: 600;
  letter-spacing: 0.04em;
  box-shadow: 0 6px 18px rgba(0, 255, 136, 0.25);
  transition: transform 0.15s ease, box-shadow 0.2s ease;
}

.search-button:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.search-button:not(:disabled):hover {
  transform: translateY(-1px);
  box-shadow: 0 10px 28px rgba(0, 255, 136, 0.3);
}
</style>
