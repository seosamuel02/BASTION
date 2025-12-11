<!-- DiscoverPanel.vue: Kibana Discover 레이아웃과 중앙 상태 관리 컴포넌트 -->
<template>
  <section class="discover-panel">
    <header class="discover-header">
      <div class="title-group">
        <p class="eyebrow">Bastion Discover</p>
        <h2 class="title">로그 탐색</h2>
        <p class="subtitle">인덱스, 시간, KQL을 통합해서 빠르게 조회</p>
      </div>
    </header>

    <div class="control-bar">
      <IndexSelector
        class="control-item index"
        :indices="indices"
        :selected="selectedIndex"
        :disabled="!indices.length"
        @update:selected="handleIndexChange"
      />
      <SearchBar
        class="control-item search"
        :kql="kql"
        :loading="isSearching"
        @update:kql="handleKqlChange"
        @search="handleSubmit"
      />
      <TimeRangePicker
        class="control-item time"
        :time-range="timeRange"
        @update:time-range="handleTimeRangeChange"
      />
    </div>

    <div class="discover-body">
      <aside :class="['sidebar', { collapsed: !showSidebar }]">
        <FieldSidebar
          :fields="results.columns"
          :open="showSidebar"
          @toggle="toggleSidebar"
        />
        <div v-if="showSidebar" class="sidebar-inner">
          <div class="sidebar-header">
            <h4 class="section-title">필드 필터</h4>
            <button class="ghost-toggle" @click="toggleFilters">
              {{ showFilters ? '접기' : '펼치기' }}
            </button>
          </div>
          <FieldFilter
            v-if="showFilters"
            :filters="fieldFilters"
            @add-filter="handleAddFilter"
            @update-filter="handleUpdateFilter"
            @remove-filter="handleRemoveFilter"
          />
          <div v-else class="collapsed-note">필터 패널이 접혀있습니다.</div>
        </div>
      </aside>
      <main class="results">
        <ResultTable
          :results="pagedResults"
          :total="totalRows"
          :loading="isSearching"
          :current-index="selectedIndex"
          :page="page"
          :page-size="pageSize"
          :page-size-options="pageSizeOptions"
          @update:page="handlePage"
          @update:page-size="handlePageSize"
        />
      </main>
    </div>
  </section>
</template>

<script setup>
import { ref, reactive, onMounted, inject, computed } from 'vue';
import IndexSelector from './IndexSelector.vue';
import SearchBar from './SearchBar.vue';
import TimeRangePicker from './TimeRangePicker.vue';
import FieldFilter from './FieldFilter.vue';
import ResultTable from './ResultTable.vue';
import FieldSidebar from './FieldSidebar.vue';

// ❖ DiscoverPanel: 검색 조건을 중앙에서 관리하고 하위 컴포넌트는 props/emit으로만 통신
const $api = inject('$api');

const indices = ref([]);
const selectedIndex = ref('');
const kql = ref('');
const timeRange = reactive({
  from: 'now-24h',
  to: 'now'
});
const fieldFilters = ref([
  { id: 1, field: 'host.name', operator: 'is', value: 'web-01' },
  { id: 2, field: 'event.module', operator: 'is', value: 'wazuh' }
]);
const showFilters = ref(true);

// 샘플 더미 데이터: 실제 연동 시 searchLogs 반환 형태만 맞추면 됨
const sampleRows = [
  {
    id: '1',
    '@timestamp': '2024-05-01T10:00:00Z',
    message: 'Wazuh alert: Suspicious process tree detected',
    'host.name': 'web-01',
    'event.module': 'wazuh'
  },
  {
    id: '2',
    '@timestamp': '2024-05-01T10:05:00Z',
    message: 'Filebeat: nginx access 200 from 10.0.0.12',
    'host.name': 'web-02',
    'event.module': 'filebeat'
  },
  {
    id: '3',
    '@timestamp': '2024-05-01T10:10:00Z',
    message: 'Auditbeat: sudo command executed by ubuntu',
    'host.name': 'jump-host',
    'event.module': 'auditbeat'
  }
];

const results = ref({
  total: sampleRows.length,
  columns: ['@timestamp', 'message', 'host.name', 'event.module'],
  rows: sampleRows
});
const page = ref(1);
const pageSize = ref(25);
const pageSizeOptions = [10, 25, 50, 100];

const totalRows = computed(() => {
  const explicitTotal = results.value.total;
  if (explicitTotal !== undefined && explicitTotal !== null) {
    return explicitTotal;
  }
  return results.value.rows?.length ?? 0;
});

const pagedResults = computed(() => {
  const start = (page.value - 1) * pageSize.value;
  const end = start + pageSize.value;
  const rows = results.value.rows || [];
  return {
    total: totalRows.value,
    columns: results.value.columns,
    rows: rows.slice(start, end)
  };
});

const isSearching = ref(false);
const showSidebar = ref(true);

// Elasticsearch Discover 형태의 검색 인터페이스 정의 (프록시 연동)
async function searchLogs({ index, kql, timeRange, filters }) {
  if (!$api) {
    console.warn('[Discover] $api 주입 실패, 더미 데이터 사용');
    return {
      total: sampleRows.length,
      columns: ['@timestamp', 'message', 'host.name', 'event.module'],
      rows: sampleRows
    };
  }

  const { data } = await $api.post('/plugin/bastion/es/search', {
    index,
    kql,
    timeRange,
    filters
  });
  return data;
}

const runSearch = async () => {
  isSearching.value = true;
  try {
    const data = await searchLogs({
      index: selectedIndex.value,
      kql: kql.value,
      timeRange: { ...timeRange },
      filters: fieldFilters.value
    });
    results.value = data;
    page.value = 1;
  } finally {
    isSearching.value = false;
  }
};

const loadIndices = async () => {
  if (!$api) return;
  try {
    const { data } = await $api.get('/plugin/bastion/es/indices');
    indices.value = data || [];
    if (!selectedIndex.value && indices.value.length > 0) {
      selectedIndex.value = indices.value[0];
    }
  } catch (e) {
    console.error('[Discover] 인덱스 로드 실패', e);
  }
};

// ─ 이벤트 핸들러 (하위 → 상위)
const handleIndexChange = (value) => {
  selectedIndex.value = value;
  runSearch();
};

const handleKqlChange = (value) => {
  kql.value = value;
};

const handleSubmit = () => {
  runSearch();
};

const handleTimeRangeChange = (value) => {
  timeRange.from = value.from;
  timeRange.to = value.to;
};

const handleAddFilter = (filter) => {
  fieldFilters.value = [
    ...fieldFilters.value,
    { ...filter, id: Date.now() }
  ];
};

const handleUpdateFilter = (updated) => {
  const idx = fieldFilters.value.findIndex((f) => f.id === updated.id);
  if (idx !== -1) {
    fieldFilters.value[idx] = { ...fieldFilters.value[idx], ...updated };
  }
};

const handleRemoveFilter = (id) => {
  fieldFilters.value = fieldFilters.value.filter((f) => f.id !== id);
};

const toggleFilters = () => {
  showFilters.value = !showFilters.value;
};

const toggleSidebar = () => {
  showSidebar.value = !showSidebar.value;
};

const handlePage = (val) => {
  page.value = val;
};

const handlePageSize = (val) => {
  pageSize.value = val;
  page.value = 1;
};

onMounted(() => {
  loadIndices().finally(() => {
    runSearch();
  });
});
</script>

<style scoped>
.discover-panel {
  background: #0f172a;
  border: 1px solid #1f2937;
  border-radius: 10px;
  padding: 18px;
  color: #e5e7eb;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
}

.discover-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1.25rem;
  border-bottom: 1px solid #1f2937;
  padding-bottom: 0.85rem;
  margin-bottom: 0.5rem;
}

.title-group .eyebrow {
  font-size: 0.75rem;
  letter-spacing: 0.1em;
  color: #94a3b8;
  text-transform: uppercase;
  margin-bottom: 0.25rem;
}

.title-group .title {
  font-size: 1.35rem;
  font-weight: 700;
  margin: 0;
}

.title-group .subtitle {
  margin: 0.15rem 0 0;
  color: #cbd5e1;
  font-size: 0.95rem;
}

.control-bar {
  display: flex;
  gap: 0.6rem;
  align-items: stretch;
  justify-content: flex-start;
  margin-bottom: 0.75rem;
  flex-wrap: wrap;
}

.control-item.index {
  min-width: 220px;
}

.control-item.search {
  flex: 1;
  min-width: 320px;
}

.control-item.time {
  min-width: 260px;
}

.discover-body {
  display: grid;
  grid-template-columns: minmax(80px, 280px) 1fr;
  gap: 1rem;
}

.sidebar {
  background: #111827;
  border: 1px solid #1f2937;
  border-radius: 8px;
  padding: 0.85rem;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  transition: width 0.2s ease;
}

.sidebar.collapsed {
  width: 80px;
  min-width: 80px;
}

.sidebar-inner {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.sidebar-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.4rem;
}

.section-title {
  margin: 0;
  color: #cbd5e1;
  font-size: 0.95rem;
  font-weight: 700;
}

.ghost-toggle {
  background: transparent;
  border: 1px solid #1f2937;
  color: #cbd5e1;
  border-radius: 8px;
  padding: 0.35rem 0.65rem;
  font-size: 0.85rem;
  cursor: pointer;
}

.ghost-toggle:hover {
  border-color: #3273dc;
  color: #bfdbfe;
}

.collapsed-note {
  color: #94a3b8;
  font-size: 0.9rem;
  padding: 0.5rem;
  border: 1px dashed #1f2937;
  border-radius: 8px;
  background: #0b1221;
}

.results {
  background: #111827;
  border: 1px solid #1f2937;
  border-radius: 8px;
  padding: 0.85rem;
  min-height: 360px;
}

@media (max-width: 960px) {
  .discover-header {
    flex-direction: column;
    align-items: flex-start;
  }

  .discover-body {
    grid-template-columns: 1fr;
  }
}
</style>
