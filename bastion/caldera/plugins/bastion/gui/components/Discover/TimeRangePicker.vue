<!-- TimeRangePicker.vue: 시간 범위 입력/빠른 선택 컴포넌트 (키바나식 Quick Select 느낌) -->
<template>
  <div class="time-range-picker">
    <div class="label-row">
      <label class="label">시간 범위</label>
      <span class="caption">키바나 Quick Select 스타일</span>
    </div>

    <div class="trigger-wrap">
      <button class="range-trigger" @click="toggleOpen">
        <span class="value">{{ summary }}</span>
        <span class="chevron" :class="{ open: isOpen }">▼</span>
      </button>

      <div v-if="isOpen" class="popover">
        <div class="inputs">
          <input
            class="time-input"
            type="text"
            :value="timeRange.from"
            placeholder="from 예) now-24h"
            @input="updateField('from', $event.target.value)"
          >
          <span class="sep">→</span>
          <input
            class="time-input"
            type="text"
            :value="timeRange.to"
            placeholder="to 예) now"
            @input="updateField('to', $event.target.value)"
          >
        </div>

        <div class="quick-panel">
          <div class="quick-row">
            <span class="quick-label">Quick select</span>
            <div class="quick-inline">
              <select v-model.number="quick.count" class="quick-input">
                <option v-for="n in quickNumbers" :key="n" :value="n">{{ n }}</option>
              </select>
              <select v-model="quick.unit" class="quick-input">
                <option value="m">Minutes</option>
                <option value="h">Hours</option>
                <option value="d">Days</option>
              </select>
              <button class="apply-btn" @click="applyQuick">Apply</button>
            </div>
          </div>

          <div class="quick-grid">
            <div class="quick-column">
              <p class="quick-head">자주 쓰는 범위</p>
              <button
                v-for="preset in presetCommon"
                :key="preset.label"
                class="chip"
                @click="setRange(preset.from, preset.to)"
              >
                {{ preset.label }}
              </button>
            </div>
            <div class="quick-column">
              <p class="quick-head">최근 사용</p>
              <button
                v-for="preset in presetRecent"
                :key="preset.label"
                class="chip"
                @click="setRange(preset.from, preset.to)"
              >
                {{ preset.label }}
              </button>
            </div>
          </div>
        </div>
        <div class="popover-actions">
          <button class="ghost" @click="close">닫기</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { reactive, ref, computed, onMounted, onBeforeUnmount } from 'vue';

// ❖ TimeRangePicker: 키바나 Quick Select 스타일. 상대시간 프리셋과 입력값을 모두 emit
const props = defineProps({
  timeRange: {
    type: Object,
    default: () => ({ from: '', to: '' })
  }
});

const emit = defineEmits(['update:time-range']);

const quick = reactive({
  count: 15,
  unit: 'm'
});

const isOpen = ref(false);

const quickNumbers = [1, 5, 10, 15, 30, 60, 90, 120, 180, 360, 720, 1440];

const presetCommon = [
  { label: 'Today', from: 'now/d', to: 'now' },
  { label: 'This week', from: 'now/w', to: 'now' },
  { label: 'Last 15 minutes', from: 'now-15m', to: 'now' },
  { label: 'Last 24 hours', from: 'now-24h', to: 'now' },
  { label: 'Last 7 days', from: 'now-7d', to: 'now' },
  { label: 'Last 30 days', from: 'now-30d', to: 'now' },
  { label: 'Last 90 days', from: 'now-90d', to: 'now' },
  { label: 'Last 1 year', from: 'now-1y', to: 'now' }
];

const presetRecent = [
  { label: 'Last 15 minutes', from: 'now-15m', to: 'now' },
  { label: 'Today', from: 'now/d', to: 'now' },
  { label: 'Last 1 hour', from: 'now-1h', to: 'now' }
];

const summary = computed(() => {
  const from = props.timeRange.from || 'from';
  const to = props.timeRange.to || 'to';
  return `${from} → ${to}`;
});

const updateField = (key, value) => {
  emit('update:time-range', { ...props.timeRange, [key]: value });
};

const setRange = (from, to) => {
  emit('update:time-range', { from, to });
};

const applyQuick = () => {
  const from = `now-${quick.count}${quick.unit}`;
  const to = 'now';
  setRange(from, to);
  isOpen.value = false;
};

const toggleOpen = () => {
  isOpen.value = !isOpen.value;
};

const close = () => {
  isOpen.value = false;
};

const onOutside = (e) => {
  if (!e.target.closest('.time-range-picker')) {
    isOpen.value = false;
  }
};

onMounted(() => {
  window.addEventListener('click', onOutside);
});

onBeforeUnmount(() => {
  window.removeEventListener('click', onOutside);
});
</script>

<style scoped>
.time-range-picker {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  min-width: 320px;
}

.label-row {
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
}

.label {
  color: #cbd5e1;
  font-size: 0.9rem;
  font-weight: 700;
  margin: 0;
}

.caption {
  color: #94a3b8;
  font-size: 0.8rem;
}

.trigger-wrap {
  position: relative;
}

.range-trigger {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  background: #0b1221;
  border: 1px solid #1f2937;
  color: #e5e7eb;
  border-radius: 8px;
  padding: 0.65rem 0.75rem;
  cursor: pointer;
  min-height: 44px;
}

.range-trigger:hover {
  border-color: #3273dc;
}

.value {
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  font-size: 0.95rem;
}

.chevron {
  transition: transform 0.15s ease;
  font-size: 0.85rem;
}

.chevron.open {
  transform: rotate(180deg);
}

.popover {
  position: absolute;
  top: calc(100% + 6px);
  right: 0;
  width: 420px;
  max-width: 90vw;
  background: #0b1221;
  border: 1px solid #1f2937;
  border-radius: 10px;
  padding: 0.65rem 0.7rem 0.5rem;
  box-shadow: 0 12px 30px rgba(0, 0, 0, 0.35);
  z-index: 20;
}

.inputs {
  display: flex;
  align-items: center;
  gap: 0.35rem;
}

.time-input {
  flex: 1;
  background: #0b1221;
  color: #e5e7eb;
  border: 1px solid #1f2937;
  border-radius: 8px;
  padding: 0.55rem 0.65rem;
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  min-height: 42px;
}

.time-input:focus {
  outline: 1px solid #3273dc;
  border-color: #3273dc;
}

.sep {
  color: #6b7280;
  font-size: 0.9rem;
  padding: 0 0.2rem;
}

.quick-panel {
  background: #0b1221;
  border: 1px solid #1f2937;
  border-radius: 10px;
  padding: 0.6rem 0.65rem 0.8rem;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.quick-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.quick-label {
  color: #cbd5e1;
  font-weight: 600;
}

.quick-inline {
  display: flex;
  gap: 0.4rem;
  flex-wrap: wrap;
  align-items: center;
}

.quick-input {
  background: #111827;
  color: #e5e7eb;
  border: 1px solid #1f2937;
  border-radius: 8px;
  padding: 0.5rem 0.6rem;
  min-width: 90px;
  min-height: 40px;
}

.apply-btn {
  background: linear-gradient(135deg, #3273dc, #285bb5);
  color: #e5e7eb;
  border: 1px solid #285bb5;
  border-radius: 8px;
  padding: 0.55rem 0.8rem;
  cursor: pointer;
  font-weight: 600;
  min-height: 40px;
}

.apply-btn:hover {
  filter: brightness(1.05);
}

.quick-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.5rem;
}

.quick-column {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

.quick-head {
  color: #94a3b8;
  font-size: 0.85rem;
  margin: 0;
}

.chip {
  background: #111827;
  color: #e5e7eb;
  border: 1px solid #1f2937;
  border-radius: 8px;
  padding: 0.48rem 0.65rem;
  font-size: 0.9rem;
  text-align: left;
  cursor: pointer;
  transition: all 0.15s ease;
}

.chip:hover {
  border-color: #3273dc;
  color: #bfdbfe;
  background: #0f172a;
}

.popover-actions {
  display: flex;
  justify-content: flex-end;
  margin-top: 0.4rem;
}

.ghost {
  background: transparent;
  border: 1px solid #1f2937;
  color: #cbd5e1;
  border-radius: 8px;
  padding: 0.45rem 0.8rem;
  cursor: pointer;
}

.ghost:hover {
  border-color: #3273dc;
  color: #bfdbfe;
}

@media (max-width: 640px) {
  .quick-grid {
    grid-template-columns: 1fr;
  }
}
</style>
