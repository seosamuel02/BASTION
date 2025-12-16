<!-- IndexSelector.vue: Index dropdown selector -->
<template>
  <div class="index-selector">
    <label class="label">INDEX</label>
    <div
      class="trigger"
      :class="{ disabled }"
      @click="toggle"
    >
      <span class="value">{{ displayValue }}</span>
      <span class="chevron" :class="{ open: isOpen && !disabled }">▼</span>
    </div>
    <div v-if="isOpen && !disabled" class="dropdown">
      <button
        v-for="opt in normalized"
        :key="opt.value"
        class="dropdown-item"
        :class="{ selected: opt.value === props.selected }"
        @click="selectIndex(opt.value)"
        :title="opt.value"
      >
        <span class="check">{{ opt.value === props.selected ? '✓' : '' }}</span>
        <span class="label-text">{{ opt.label }}</span>
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onBeforeUnmount, computed } from 'vue';

// IndexSelector: displays indices as dropdown and emits selection
const props = defineProps({
  indices: {
    type: Array,
    default: () => []
  },
  selected: {
    type: String,
    default: ''
  },
  disabled: {
    type: Boolean,
    default: false
  }
});

const emit = defineEmits(['update:selected']);
const isOpen = ref(false);

const displayValue = computed(() => {
  if (props.selected) return props.selected;
  if (!props.indices.length) return 'No indices';
  return 'Select index';
});

const normalized = computed(() => {
  const list = props.indices || [];
  return list
    .map((x) => {
      if (typeof x === 'string') return { label: x, value: x };
      if (x && typeof x === 'object') {
        const value = x.value ?? x.label;
        const label = x.label ?? x.value;
        if (!value) return null;
        return { label: String(label), value: String(value) };
      }
      return null;
    })
    .filter(Boolean);
});

const toggle = () => {
  if (props.disabled) return;
  isOpen.value = !isOpen.value;
};

const selectIndex = (idx) => {
  emit('update:selected', idx);
  isOpen.value = false;
};

const handleClickOutside = (event) => {
  if (!event.target.closest('.index-selector')) {
    isOpen.value = false;
  }
};

onMounted(() => {
  window.addEventListener('click', handleClickOutside);
});

onBeforeUnmount(() => {
  window.removeEventListener('click', handleClickOutside);
});
</script>

<style scoped>
.index-selector {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  min-width: 200px;
}

.label {
  color: #cbd5e1;
  font-size: 0.85rem;
}

.trigger {
  background: #0b1221;
  color: #e5e7eb;
  border: 1px solid #1f2937;
  border-radius: 8px;
  padding: 0.55rem 0.65rem;
  min-height: 42px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  cursor: pointer;
  box-shadow: inset 0 0 0 1px rgba(0, 255, 136, 0.02);
}

.trigger.disabled {
  cursor: not-allowed;
  opacity: 0.6;
}

.trigger:hover {
  border-color: var(--cyber-green, #00ff88);
  box-shadow: 0 0 12px rgba(0, 255, 136, 0.2);
}

.chevron {
  transition: transform 0.15s ease;
  font-size: 0.8rem;
}

.chevron.open {
  transform: rotate(180deg);
}

.dropdown {
  position: absolute;
  top: 100%;
  left: 0;
  right: 0;
  background: #0b1221;
  border: 1px solid #1f2937;
  border-radius: 10px;
  margin-top: 0.3rem;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
  z-index: 10;
  overflow: hidden;
  backdrop-filter: blur(4px);
}

.dropdown-item {
  width: 100%;
  text-align: left;
  padding: 0.55rem 0.7rem;
  background: transparent;
  border: none;
  color: #e5e7eb;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.45rem;
}

.check {
  width: 18px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: #93c5fd;
  font-weight: 800;
}

.label-text {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.dropdown-item.selected {
  background: rgba(37, 99, 235, 0.12);
  color: #bfdbfe;
}

.dropdown-item:hover {
  background: #0f172a;
  color: #bfdbfe;
}
</style>
