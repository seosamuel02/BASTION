<!-- IndexSelector.vue: 인덱스 선택 토글 드롭다운 (키바나 Data View 느낌) -->
<template>
  <div class="index-selector">
    <label class="label">Index</label>
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
        v-for="idx in indices"
        :key="idx"
        class="dropdown-item"
        @click="selectIndex(idx)"
      >
        {{ idx }}
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onBeforeUnmount, computed } from 'vue';

// ❖ IndexSelector: 인덱스 목록을 토글 드롭다운으로 표시, 선택 시 상위로 emit
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
  if (!props.indices.length) return '인덱스 없음';
  return '선택 없음';
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
}

.trigger.disabled {
  cursor: not-allowed;
  opacity: 0.6;
}

.trigger:hover {
  border-color: #3273dc;
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
}

.dropdown-item {
  width: 100%;
  text-align: left;
  padding: 0.55rem 0.7rem;
  background: transparent;
  border: none;
  color: #e5e7eb;
  cursor: pointer;
}

.dropdown-item:hover {
  background: #0f172a;
  color: #bfdbfe;
}
</style>
