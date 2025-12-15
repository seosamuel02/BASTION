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
        :indices="indexOptions"
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
          :fields="availableFields"
          :selected="visibleColumns"
          :show-document="showDocument"
          :open="showSidebar"
          @toggle="toggleSidebar"
          @toggle-field="toggleFieldColumn"
          @toggle-document="toggleDocument"
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
          :results="tableResults"
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
// ✅ Kibana Discover의 Data View처럼 패턴 옵션을 최상단에 노출
const indexOptions = computed(() => {
  const list = indices.value || [];
  const hasWazuhAlerts = list.some((i) => typeof i === 'string' && i.startsWith('wazuh-alerts-'));
  const opts = [];
  if (hasWazuhAlerts) {
    opts.push({ label: 'wazuh-alerts-*', value: 'wazuh-alerts-*' });
  }
  for (const idx of list) {
    if (!idx) continue;
    // pattern이 들어가면 중복 제거
    if (idx === 'wazuh-alerts-*') continue;
    opts.push({ label: idx, value: idx });
  }
  return opts;
});
const kql = ref('');
const timeRange = reactive({
  // ✅ 초기 기본값: 최근 15분
  from: 'now-15m',
  to: 'now'
});
const fieldFilters = ref([]);
const showFilters = ref(true);
const visibleColumns = ref([]);

// ✅ "모든 필드(전체 로그)"(Document) 기본 ON
const showDocument = ref(true);

const results = ref({
  total: 0,
  columns: [],
  rows: []
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

const availableFields = computed(() => {
  const cols = results.value.columns || [];
  return [...new Set(cols.filter(Boolean))];
});

// ✅ Kibana Discover처럼: "@timestamp" + (선택 컬럼) + (Document)
const tableColumns = computed(() => {
  const cols = [];

  // 1) 타임스탬프는 가능하면 항상 앞에
  if (availableFields.value.includes('@timestamp')) {
    cols.push('@timestamp');
  }

  // 2) 선택한 필드 컬럼
  for (const c of visibleColumns.value) {
    if (!c) continue;
    if (c === '@timestamp') continue;
    if (!cols.includes(c)) cols.push(c);
  }

  // 3) 전체 로그(Document) 컬럼
  if (showDocument.value) {
    cols.push('__document__');
  }

  // fallback: 아무것도 없으면 첫 컬럼
  if (cols.length === 0 && availableFields.value.length) {
    cols.push(availableFields.value[0]);
  }
  return cols;
});

const tableResults = computed(() => ({
  total: totalRows.value,
  columns: tableColumns.value,
  rows: results.value.rows || []
}));

// 필드 클릭 시 컬럼 토글 (최소 1개 유지)
const toggleFieldColumn = (field) => {
  if (!availableFields.value.includes(field)) return;
  const cur = visibleColumns.value.slice();
  const idx = cur.indexOf(field);
  if (idx >= 0) cur.splice(idx, 1);
  else cur.push(field);

  // ✅ Document OFF 상태에서는 최소 1개 컬럼 유지
  if (!showDocument.value && cur.length === 0 && availableFields.value.length) {
    cur.push(availableFields.value[0]);
  }
  visibleColumns.value = cur;
};

// ✅ "모든 필드(전체 로그)" 토글
const toggleDocument = () => {
  showDocument.value = !showDocument.value;
  // Document를 끄고 선택된 컬럼이 없다면 최소 1개 보장
  if (!showDocument.value && visibleColumns.value.length === 0 && availableFields.value.length) {
    visibleColumns.value = [availableFields.value[0]];
  }
};

const isSearching = ref(false);
const showSidebar = ref(true);

// Elasticsearch Discover 형태의 검색 인터페이스 정의 (프록시 연동)
async function searchLogs({ index, kql, timeRange, filters }) {
  if (!$api) {
    console.warn('[Discover] $api 주입 실패');
    return { total: 0, columns: [], rows: [] };
  }

  try {
      const { data } = await $api.post('/api/discover/search', {
        index,
        from: timeRange.from,
        to: timeRange.to,
        query: kql || '*',

        // ✅ 서버 페이징: 프론트에서 rows를 다시 slice 하지 않음
        size: pageSize.value,
        offset: (page.value - 1) * pageSize.value
      });
      return data;
    } catch (e) {
      console.error('[Discover] 검색 실패', e);
      return { total: 0, columns: [], rows: [] };
    }
}

const runSearch = async ({ resetPage = false } = {}) => {
  if (!selectedIndex.value) {
    results.value = { total: 0, columns: [], rows: [] };
    return;
  }
  if (resetPage) page.value = 1;
  isSearching.value = true;
  try {
    const data = await searchLogs({
      index: selectedIndex.value,
      kql: kql.value,
      timeRange: { ...timeRange },
      filters: fieldFilters.value
    });
    results.value = data;
    // ✅ Document OFF일 때만 "최소 1개 컬럼" 보장
    if (!showDocument.value && visibleColumns.value.length === 0 && availableFields.value.length) {
      visibleColumns.value = [availableFields.value[0]];
    }
  } finally {
    isSearching.value = false;
  }
};

const loadIndices = async () => {
  if (!$api) return;
  try {
    const { data } = await $api.get('/api/discover/indices');
    const list = (data || []).filter(Boolean);
    // 시스템 인덱스(.)보다 사용자 인덱스를 우선하도록 정렬
    const userIndices = list.filter((i) => i && !i.startsWith('.'));
    const systemIndices = list.filter((i) => i && i.startsWith('.'));
    indices.value = [...userIndices, ...systemIndices];

    // ✅ wazuh-alerts-* (Data View 느낌) 우선 노출/기본 선택
    const hasWazuhAlerts = indices.value.some((i) => typeof i === 'string' && i.startsWith('wazuh-alerts-'));
    const defaultIndex = hasWazuhAlerts ? 'wazuh-alerts-*' : (indices.value[0] || '');
    if (!selectedIndex.value && defaultIndex) selectedIndex.value = defaultIndex;

    if (selectedIndex.value) {
      await runSearch({ resetPage: true });
    }
  } catch (e) {
    console.error('[Discover] 인덱스 로드 실패', e);
  }
};

// ─ 이벤트 핸들러 (하위 → 상위)
const handleIndexChange = (value) => {
  selectedIndex.value = value;
  runSearch({ resetPage: true });
};

const handleKqlChange = (value) => {
  kql.value = value;
};

const handleSubmit = () => {
  runSearch({ resetPage: true });
};

const handleTimeRangeChange = (value) => {
  timeRange.from = value.from;
  timeRange.to = value.to;
  runSearch({ resetPage: true });
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
  runSearch({ resetPage: false });
};

const handlePageSize = (val) => {
  pageSize.value = val;
  page.value = 1;
  runSearch({ resetPage: false });
};

onMounted(() => {
  loadIndices();
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
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
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
  display: flex;
  gap: 1rem;
  flex: 1;
  min-height: 0;
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
  flex: 0 0 320px;
  min-width: 260px;
  min-height: 0;
}

.sidebar.collapsed {
  flex: 0 0 80px;
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
  flex: 1;
  min-width: 0;
  min-height: 0;
  display: flex;
  flex-direction: column;
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