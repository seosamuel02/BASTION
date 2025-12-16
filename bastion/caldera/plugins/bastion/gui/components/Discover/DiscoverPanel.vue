<!-- DiscoverPanel.vue: Centralized Discover layout + state manager -->
<template>
  <section class="discover-panel">
    <header class="discover-header">
      <div class="title-group">
        <p class="eyebrow">BASTION DISCOVER</p>
        <h2 class="title">Log Explorer</h2>
        <p class="subtitle">Search indices with KQL and time range filters</p>
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
            <h4 class="section-title">Field Filters</h4>
            <button class="ghost-toggle" @click="toggleFilters">
              {{ showFilters ? 'Hide' : 'Show' }}
            </button>
          </div>
          <FieldFilter
            v-if="showFilters"
            :filters="fieldFilters"
            @add-filter="handleAddFilter"
            @update-filter="handleUpdateFilter"
            @remove-filter="handleRemoveFilter"
          />
          <div v-else class="collapsed-note">Filter panel is hidden.</div>
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

// DiscoverPanel keeps discover state centralized and fans out via props/emits
const $api = inject('$api');

const indices = ref([]);
const selectedIndex = ref('');
const indexOptions = computed(() => {
  const list = indices.value || [];
  const hasWazuhAlerts = list.some((i) => typeof i === 'string' && i.startsWith('wazuh-alerts-'));
  const opts = [];
  if (hasWazuhAlerts) {
    opts.push({ label: 'wazuh-alerts-*', value: 'wazuh-alerts-*' });
  }
  for (const idx of list) {
    if (!idx) continue;
    // Skip duplicates when pattern already exists
    if (idx === 'wazuh-alerts-*') continue;
    opts.push({ label: idx, value: idx });
  }
  return opts;
});
const kql = ref('');
const timeRange = reactive({
  from: 'now-15m',
  to: 'now'
});
const fieldFilters = ref([]);
const showFilters = ref(true);
const visibleColumns = ref([]);
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

// Order columns like Kibana: @timestamp + selected fields + document
const tableColumns = computed(() => {
  const cols = [];

  if (availableFields.value.includes('@timestamp')) {
    cols.push('@timestamp');
  }

  for (const c of visibleColumns.value) {
    if (!c) continue;
    if (c === '@timestamp') continue;
    if (!cols.includes(c)) cols.push(c);
  }

  if (showDocument.value) {
    cols.push('__document__');
  }

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

// Toggle field as a column while ensuring at least one column is shown
const toggleFieldColumn = (field) => {
  if (!availableFields.value.includes(field)) return;
  const cur = visibleColumns.value.slice();
  const idx = cur.indexOf(field);
  if (idx >= 0) cur.splice(idx, 1);
  else cur.push(field);

  if (!showDocument.value && cur.length === 0 && availableFields.value.length) {
    cur.push(availableFields.value[0]);
  }
  visibleColumns.value = cur;
};

const toggleDocument = () => {
  showDocument.value = !showDocument.value;
  if (!showDocument.value && visibleColumns.value.length === 0 && availableFields.value.length) {
    visibleColumns.value = [availableFields.value[0]];
  }
};

const isSearching = ref(false);
const showSidebar = ref(true);

async function searchLogs({ index, kql, timeRange, filters }) {
  if (!$api) {
    console.warn('[Discover] $api injection failed');
    return { total: 0, columns: [], rows: [] };
  }

  try {
      const { data } = await $api.post('/api/discover/search', {
        index,
        from: timeRange.from,
        to: timeRange.to,
        query: kql || '*',

        // Server-side paging: do not slice rows again on the client
        size: pageSize.value,
        offset: (page.value - 1) * pageSize.value
      });
      return data;
    } catch (e) {
      console.error('[Discover] search failed', e);
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
    const userIndices = list.filter((i) => i && !i.startsWith('.'));
    const systemIndices = list.filter((i) => i && i.startsWith('.'));
    indices.value = [...userIndices, ...systemIndices];

    const hasWazuhAlerts = indices.value.some((i) => typeof i === 'string' && i.startsWith('wazuh-alerts-'));
    const defaultIndex = hasWazuhAlerts ? 'wazuh-alerts-*' : (indices.value[0] || '');
    if (!selectedIndex.value && defaultIndex) selectedIndex.value = defaultIndex;

    if (selectedIndex.value) {
      await runSearch({ resetPage: true });
    }
  } catch (e) {
    console.error('[Discover] failed to load indices', e);
  }
};

// Event handlers (child → parent)
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
  --bg-primary: var(--bg-secondary, #0f1419);
  --bg-elevated: var(--bg-card, #1a222d);
  --border: var(--border-color, #2a3a4a);
  --text: var(--text-primary, #e0e6ed);
  --muted: var(--text-muted, #5a6a7a);
  --accent: var(--cyber-green, #00ff88);
  --accent-soft: var(--cyber-green-dim, rgba(0, 255, 136, 0.18));
  --accent-contrast: #0a0e12;
  font-family: 'IBM Plex Sans', 'JetBrains Mono', monospace;
  background: linear-gradient(135deg, rgba(0, 0, 0, 0.25), rgba(0, 255, 136, 0.04)) var(--bg-primary);
  border: 1px solid var(--border);
  border-left: 3px solid var(--accent);
  border-radius: 12px;
  padding: 18px;
  color: var(--text);
  box-shadow: 0 18px 40px rgba(0, 0, 0, 0.4);
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  position: relative;
  overflow: hidden;
}

.discover-panel::after {
  content: '';
  position: absolute;
  inset: 0;
  pointer-events: none;
  background: radial-gradient(circle at 20% 20%, rgba(0, 255, 136, 0.08), transparent 35%),
    radial-gradient(circle at 80% 0%, rgba(0, 212, 255, 0.05), transparent 32%);
  mix-blend-mode: screen;
}

.discover-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1.25rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.85rem;
  margin-bottom: 0.5rem;
  position: relative;
}

.title-group .eyebrow {
  font-size: 0.75rem;
  letter-spacing: 0.1em;
  color: var(--accent);
  text-transform: uppercase;
  margin-bottom: 0.25rem;
  font-family: 'JetBrains Mono', monospace;
}

.title-group .title {
  font-size: 1.35rem;
  font-weight: 700;
  margin: 0;
  letter-spacing: 0.08em;
}

.title-group .subtitle {
  margin: 0.15rem 0 0;
  color: var(--muted);
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
  background: linear-gradient(135deg, rgba(0, 255, 136, 0.05), rgba(0, 0, 0, 0.1)) var(--bg-primary);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 0.9rem;
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
  color: var(--text);
  font-size: 0.95rem;
  font-weight: 700;
}

.ghost-toggle {
  background: rgba(0, 0, 0, 0.35);
  border: 1px solid var(--border);
  color: var(--text);
  border-radius: 8px;
  padding: 0.35rem 0.7rem;
  font-size: 0.85rem;
  cursor: pointer;
  letter-spacing: 0.05em;
  transition: all 0.2s ease;
}

.ghost-toggle:hover {
  border-color: var(--accent);
  color: var(--accent);
  box-shadow: 0 0 16px rgba(0, 255, 136, 0.25);
}

.collapsed-note {
  color: var(--muted);
  font-size: 0.9rem;
  padding: 0.5rem;
  border: 1px dashed var(--border);
  border-radius: 8px;
  background: rgba(0, 255, 136, 0.03);
}

.results {
  background: linear-gradient(135deg, rgba(0, 255, 136, 0.04), rgba(0, 0, 0, 0.08)) var(--bg-primary);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 0.95rem;
  min-height: 360px;
  flex: 1;
  min-width: 0;
  min-height: 0;
  display: flex;
  flex-direction: column;
  box-shadow: inset 0 0 0 1px rgba(0, 255, 136, 0.02);
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
