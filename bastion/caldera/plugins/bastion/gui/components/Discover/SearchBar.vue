<!-- SearchBar.vue: KQL 입력 및 검색 트리거 컴포넌트 -->
<template>
  <div class="search-bar">
    <div class="input-wrapper">
      <input
        class="kql-input"
        type="text"
        :value="kql"
        placeholder="KQL을 입력하세요. 예) event.module:wazuh AND host.name:web-01"
        @input="onInput"
        @keydown.enter.prevent="onSubmit"
      >
    </div>
    <button class="search-button" :disabled="loading" @click="onSubmit">
      <span v-if="loading">검색 중...</span>
      <span v-else>검색</span>
    </button>
  </div>
</template>

<script setup>
// ❖ SearchBar: KQL 입력만 담당, 값 변경과 submit 이벤트를 상위로 전달
const props = defineProps({
  kql: {
    type: String,
    default: ''
  },
  loading: {
    type: Boolean,
    default: false
  }
});

const emit = defineEmits(['update:kql', 'search']);

const onInput = (event) => {
  emit('update:kql', event.target.value);
};

const onSubmit = () => {
  emit('search');
};
</script>

<style scoped>
.search-bar {
  display: flex;
  gap: 0.6rem;
  align-items: center;
}

.input-wrapper {
  flex: 1;
}

.kql-input {
  width: 100%;
  background: #0b1221;
  color: #e5e7eb;
  border: 1px solid #1f2937;
  border-radius: 8px;
  padding: 0.7rem 0.75rem;
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  min-height: 42px;
}

.kql-input:focus {
  outline: 1px solid #3273dc;
  border-color: #3273dc;
}

.search-button {
  background: linear-gradient(135deg, #3273dc, #285bb5);
  color: #e5e7eb;
  border: 1px solid #285bb5;
  border-radius: 8px;
  padding: 0.7rem 1.05rem;
  cursor: pointer;
  min-width: 98px;
  min-height: 42px;
  font-weight: 600;
  box-shadow: 0 2px 6px rgba(50, 115, 220, 0.2);
}

.search-button:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
</style>
