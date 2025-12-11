<!-- ResultTable.vue: 검색 결과 테이블 + 페이지네이션 -->
<template>
  <div class="result-table">
    <div class="table-header">
      <div>
        <p class="label">결과</p>
        <p class="hint">Index: {{ currentIndex || '-' }} · 총 {{ total }}건</p>
      </div>
      <span v-if="loading" class="loading">검색 중...</span>
    </div>

    <div v-if="!results.rows || results.rows.length === 0" class="empty">
      검색 결과가 없습니다. 조건을 변경해 보세요.
    </div>

    <div v-else class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th v-for="col in results.columns" :key="col">{{ col }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in results.rows" :key="row.id">
            <td v-for="col in results.columns" :key="col">
              <span class="mono">{{ formatValue(row[col]) }}</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="total > 0" class="pager">
      <div class="page-size">
        <span>Rows per page:</span>
        <select :value="pageSize" @change="onPageSize($event.target.value)">
          <option v-for="opt in pageSizeOptions" :key="opt" :value="opt">
            {{ opt }}
          </option>
        </select>
      </div>
      <div class="page-info">
        <button class="nav" :disabled="page <= 1" @click="$emit('update:page', page - 1)">‹</button>
        <span>{{ page }} / {{ totalPages }}</span>
        <button class="nav" :disabled="page >= totalPages" @click="$emit('update:page', page + 1)">›</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue';

// ❖ ResultTable: 결과 테이블 UI, 데이터는 상위에서 주입
const props = defineProps({
  results: {
    type: Object,
    default: () => ({
      total: 0,
      columns: [],
      rows: []
    })
  },
  loading: {
    type: Boolean,
    default: false
  },
  currentIndex: {
    type: String,
    default: ''
  },
  page: {
    type: Number,
    default: 1
  },
  pageSize: {
    type: Number,
    default: 25
  },
  pageSizeOptions: {
    type: Array,
    default: () => [10, 25, 50, 100]
  },
  total: {
    type: Number,
    default: 0
  }
});

const emit = defineEmits(['update:page', 'update:page-size']);

const formatValue = (value) => {
  if (value === undefined || value === null || value === '') return '—';
  return value;
};

const totalPages = computed(() => {
  if (props.total === 0 || !props.pageSize) return 1;
  return Math.max(1, Math.ceil(props.total / props.pageSize));
});

const onPageSize = (val) => {
  const num = Number(val) || props.pageSize;
  emit('update:page-size', num);
  emit('update:page', 1); // 페이지 리셋
};
</script>

<style scoped>
.result-table {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.table-header {
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
  font-size: 0.85rem;
  margin: 0.1rem 0 0;
}

.loading {
  color: #bfdbfe;
  font-size: 0.9rem;
}

.empty {
  padding: 0.85rem;
  background: #0b1221;
  border: 1px dashed #1f2937;
  border-radius: 6px;
  color: #94a3b8;
  font-size: 0.9rem;
}

.table-wrapper {
  overflow: auto;
  border: 1px solid #1f2937;
  border-radius: 8px;
  background: #0b1221;
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9rem;
}

thead tr {
  background: #0f172a;
}

th,
td {
  border-bottom: 1px solid #1f2937;
  padding: 0.6rem 0.75rem;
  text-align: left;
  color: #e5e7eb;
}

th {
  color: #cbd5e1;
  font-weight: 600;
  white-space: nowrap;
}

tbody tr:nth-child(even) {
  background: #111827;
}

tbody tr:hover {
  background: rgba(37, 99, 235, 0.08);
}

.mono {
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  white-space: nowrap;
}

.pager {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1rem;
  margin-top: 0.5rem;
  color: #cbd5e1;
  font-size: 0.9rem;
}

.page-size select {
  margin-left: 0.4rem;
  background: #0b1221;
  color: #e5e7eb;
  border: 1px solid #1f2937;
  border-radius: 8px;
  padding: 0.35rem 0.5rem;
}

.page-info {
  display: flex;
  align-items: center;
  gap: 0.45rem;
}

.nav {
  background: #111827;
  border: 1px solid #1f2937;
  color: #e5e7eb;
  border-radius: 6px;
  padding: 0.35rem 0.55rem;
  cursor: pointer;
}

.nav:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}
</style>
