<!-- ResultTable.vue: Results table with pagination and document modal -->
<template>
  <div class="result-table">
    <div class="table-header">
      <div>
        <p class="label">Results</p>
        <p class="hint">Index: {{ currentIndex || '-' }} · Total {{ total }}</p>
      </div>
      <span v-if="loading" class="loading">Searching...</span>
    </div>

    <div v-if="!results.rows || results.rows.length === 0" class="empty">
      No results found. Try adjusting the query.
    </div>

    <div v-else class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th class="col-actions" aria-label="actions"></th>
            <th v-for="col in results.columns" :key="col" :class="colClass(col)">
              {{ colLabel(col) }}
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in results.rows" :key="rowKey(row)">
            <td class="col-actions">
              <button
                type="button"
                class="icon-btn"
                title="View full document"
                @click="openDoc(row)"
              >
                ⤢
              </button>
            </td>

            <td v-for="col in results.columns" :key="col" :class="colClass(col)">
              <template v-if="col === '__document__'">
                <div class="doc-summary" :title="docSummaryTitle(row)">
                  <span
                    v-for="pair in docSummaryPairs(row)"
                    :key="pair.k"
                    class="doc-pair"
                  >
                    <span class="doc-k">{{ pair.k }}</span>
                    <span class="doc-v">{{ pair.v }}</span>
                  </span>
                </div>
              </template>
              <template v-else>
                <span class="mono cell" :title="toCellTitle(row?.[col])">{{ formatCell(row?.[col]) }}</span>
              </template>
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

    <!-- Document modal -->
    <div v-if="docOpen" class="modal-backdrop" @click.self="closeDoc">
      <div class="modal" role="dialog" aria-modal="true">
        <div class="modal-head">
          <div class="modal-title">
            <p class="modal-eyebrow">Document</p>
            <p class="modal-sub">Full field/value view of the selected log</p>
          </div>
          <button type="button" class="close-btn" @click="closeDoc">✕</button>
        </div>

        <div class="modal-tabs">
          <button
            type="button"
            class="tab"
            :class="{ active: docTab === 'table' }"
            @click="docTab = 'table'"
          >
            Table
          </button>
          <button
            type="button"
            class="tab"
            :class="{ active: docTab === 'json' }"
            @click="docTab = 'json'"
          >
            JSON
          </button>
        </div>

        <div class="modal-body">
          <div v-if="docTab === 'table'" class="doc-table">
            <input
              v-model="docFilter"
              class="doc-search"
              type="text"
              placeholder="Search field names"
            >

            <div class="doc-grid">
              <div class="doc-row doc-head">
                <div class="doc-col field">Field</div>
                <div class="doc-col value">Value</div>
              </div>

              <div
                v-for="pair in filteredDocPairs"
                :key="pair.k"
                class="doc-row"
              >
                <div class="doc-col field">
                  <span class="doc-pill">k</span>
                  <span class="doc-field">{{ pair.k }}</span>
                </div>
                <div class="doc-col value">
                  <span class="doc-value">{{ pair.v }}</span>
                </div>
              </div>
            </div>
          </div>

          <div v-else class="doc-json">
            <pre class="json-pre">{{ docJson }}</pre>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, onMounted, onBeforeUnmount } from 'vue';

const props = defineProps({
  results: { type: Object, default: () => ({ total: 0, columns: [], rows: [] }) },
  loading: { type: Boolean, default: false },
  currentIndex: { type: String, default: '' },
  page: { type: Number, default: 1 },
  pageSize: { type: Number, default: 25 },
  pageSizeOptions: { type: Array, default: () => [10, 25, 50, 100] },
  total: { type: Number, default: 0 }
});

const emit = defineEmits(['update:page', 'update:page-size']);

// Pagination
const totalPages = computed(() => {
  if (props.total === 0 || !props.pageSize) return 1;
  return Math.max(1, Math.ceil(props.total / props.pageSize));
});
const onPageSize = (val) => {
  const num = Number(val) || props.pageSize;
  emit('update:page-size', num);
  emit('update:page', 1);
};

// Document modal
const docOpen = ref(false);
const docRow = ref(null);
const docTab = ref('table');
const docFilter = ref('');

const openDoc = (row) => {
  docRow.value = row || null;
  docTab.value = 'table';
  docFilter.value = '';
  docOpen.value = true;
};
const closeDoc = () => { docOpen.value = false; };
const onKeyDown = (e) => { if (e.key === 'Escape' && docOpen.value) closeDoc(); };
onMounted(() => window.addEventListener('keydown', onKeyDown));
onBeforeUnmount(() => window.removeEventListener('keydown', onKeyDown));

const isPlainObject = (v) => Object.prototype.toString.call(v) === '[object Object]';

// Flatten row into dot notation pairs
const flattenRow = (obj, { maxDepth = 4, maxPairs = 600 } = {}) => {
  const out = [];
  const walk = (cur, prefix, depth) => {
    if (out.length >= maxPairs) return;
    if (cur === null || cur === undefined) {
      out.push({ k: prefix || '(root)', v: '—' });
      return;
    }
    if (depth >= maxDepth || typeof cur !== 'object') {
      out.push({ k: prefix || '(root)', v: toDisplay(cur) });
      return;
    }
    if (Array.isArray(cur)) {
      out.push({ k: prefix || '(root)', v: toDisplay(cur) });
      return;
    }
    if (isPlainObject(cur)) {
      const keys = Object.keys(cur);
      if (keys.length === 0) {
        out.push({ k: prefix || '(root)', v: '{}' });
        return;
      }
      for (const key of keys) {
        if (out.length >= maxPairs) break;
        const next = cur[key];
        const nextPrefix = prefix ? `${prefix}.${key}` : key;
        if (next !== null && typeof next === 'object' && isPlainObject(next)) {
          walk(next, nextPrefix, depth + 1);
        } else if (Array.isArray(next)) {
          out.push({ k: nextPrefix, v: toDisplay(next) });
        } else {
          out.push({ k: nextPrefix, v: toDisplay(next) });
        }
      }
      return;
    }
    out.push({ k: prefix || '(root)', v: toDisplay(cur) });
  };
  walk(obj, '', 0);
  const weight = (k) => {
    const top = String(k || '');
    if (top === '@timestamp') return 0;
    if (top === '_id') return 1;
    if (top === '_index') return 2;
    if (top === '_score') return 3;
    return 10;
  };
  return out
    .filter((p) => p && p.k)
    .sort((a, b) => {
      const wa = weight(a.k);
      const wb = weight(b.k);
      if (wa !== wb) return wa - wb;
      return a.k.localeCompare(b.k);
    });
};

const toDisplay = (value) => {
  if (value === undefined || value === null || value === '') return '—';
  if (typeof value === 'string') return value;
  try { return JSON.stringify(value); } catch { return String(value); }
};
const toSingleLine = (s) => String(s ?? '').replace(/\s+/g, ' ').trim();
const truncate = (s, maxLen) => {
  const str = String(s ?? '');
  return str.length <= maxLen ? str : str.slice(0, maxLen) + '…';
};

// Document summary
const docSummaryPairs = (row) => {
  const pairs = flattenRow(row, { maxDepth: 4, maxPairs: 300 });
  return pairs.slice(0, 24).map((p) => ({
    k: p.k,
    v: truncate(toSingleLine(p.v), 80)
  }));
};
const docSummaryTitle = (row) => {
  const pairs = flattenRow(row, { maxDepth: 4, maxPairs: 120 }).slice(0, 60);
  return pairs.map((p) => `${p.k}: ${truncate(toSingleLine(p.v), 120)}`).join(' · ');
};

const formatCell = (value) => truncate(toSingleLine(toDisplay(value)), 160);
const toCellTitle = (value) => {
  const v = toSingleLine(toDisplay(value));
  return v.length > 0 ? v : '—';
};

const filteredDocPairs = computed(() => {
  const row = docRow.value;
  if (!row) return [];
  const q = docFilter.value.trim().toLowerCase();
  const pairs = flattenRow(row, { maxDepth: 6, maxPairs: 800 });
  if (!q) return pairs;
  return pairs.filter((p) => {
    const k = (p.k || '').toLowerCase();
    const v = (p.v || '').toLowerCase();
    return k.includes(q) || v.includes(q);
  });
});

const docJson = computed(() => {
  if (!docRow.value) return '';
  try { return JSON.stringify(docRow.value, null, 2); }
  catch { return String(docRow.value); }
});

// UI helper
const rowKey = (row) => row?.id || row?._id || row?._source_id || `${row?.['@timestamp'] ?? ''}-${row?._index ?? ''}-${row?.message ?? ''}`;
const colLabel = (col) => (col === '__document__' ? 'Document' : col);
const colClass = (col) => (col === '__document__' ? 'col-doc' : '');
</script>

<style scoped>
.result-table {
  --border: var(--border-color, #2a3a4a);
  --bg: var(--bg-primary, #0f1419);
  --panel: var(--bg-card, #1a222d);
  --muted: var(--text-muted, #5a6a7a);
  --text: var(--text-primary, #e0e6ed);
  --accent: var(--cyber-green, #00ff88);
  --accent-soft: var(--cyber-green-dim, rgba(0, 255, 136, 0.16));
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  flex: 1;
  min-height: 0;
  color: var(--text);
}

.table-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.label { color: var(--text); font-weight: 700; margin: 0; letter-spacing: 0.05em; }
.hint { color: var(--muted); font-size: 0.85rem; margin: 0.1rem 0 0; }
.loading { color: var(--accent); font-size: 0.9rem; letter-spacing: 0.04em; }

.empty {
  padding: 0.85rem;
  background: rgba(0, 255, 136, 0.03);
  border: 1px dashed var(--border);
  border-radius: 10px;
  color: var(--muted);
  font-size: 0.92rem;
}

.table-wrapper {
  flex: 1;
  min-height: 0;
  overflow: auto;
  border: 1px solid var(--border);
  border-radius: 10px;
  background: linear-gradient(135deg, rgba(0, 255, 136, 0.03), rgba(0, 0, 0, 0.08)) var(--bg);
  box-shadow: inset 0 0 0 1px rgba(0, 255, 136, 0.02);
}

table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
thead tr { background: rgba(0, 255, 136, 0.05); }

th, td {
  border-bottom: 1px solid var(--border);
  padding: 0.55rem 0.75rem;
  text-align: left;
  color: var(--text);
  vertical-align: top;
}

th { color: var(--text); font-weight: 700; white-space: nowrap; letter-spacing: 0.03em; }
tbody tr:nth-child(even) { background: rgba(255, 255, 255, 0.02); }
tbody tr:hover { background: rgba(0, 255, 136, 0.05); }

.col-actions { width: 44px; padding-left: 0.5rem; padding-right: 0.5rem; }

.icon-btn {
  width: 28px;
  height: 28px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text);
  border-radius: 8px;
  cursor: pointer;
  font-size: 0.9rem;
  transition: all 0.15s ease;
}
.icon-btn:hover { border-color: var(--accent); color: var(--accent); box-shadow: 0 0 12px rgba(0, 255, 136, 0.25); }

.mono { font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; }
.cell { display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 100%; }

.col-doc { min-width: 360px; }
.doc-summary { height: 74px; overflow: hidden; display: block; line-height: 1.25; }
.doc-pair { display: inline; margin-right: 0.65rem; white-space: normal; }
.doc-k { color: var(--text); font-weight: 700; margin-right: 0.25rem; }
.doc-v { color: var(--muted); }

.modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.55);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 18px;
  z-index: 9999;
}
.modal {
  width: 900px;
  max-width: 95vw;
  max-height: 88vh;
  background: linear-gradient(145deg, rgba(0, 255, 136, 0.05), rgba(0, 0, 0, 0.35)) #0b1221;
  border: 1px solid var(--border);
  border-radius: 12px;
  box-shadow: 0 18px 45px rgba(0, 0, 0, 0.45);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.modal-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.75rem 0.85rem;
  border-bottom: 1px solid var(--border);
  background: rgba(0, 0, 0, 0.35);
}
.modal-title { display: flex; flex-direction: column; gap: 0.1rem; }
.modal-eyebrow { margin: 0; color: var(--accent); font-weight: 800; letter-spacing: 0.04em; }
.modal-sub { margin: 0; color: var(--muted); font-size: 0.85rem; }
.close-btn {
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text);
  border-radius: 10px;
  width: 34px;
  height: 34px;
  cursor: pointer;
  transition: all 0.15s ease;
}
.close-btn:hover { border-color: var(--accent); color: var(--accent); box-shadow: 0 0 10px rgba(0, 255, 136, 0.25); }

.modal-tabs { display: flex; gap: 0.35rem; padding: 0.6rem 0.85rem; border-bottom: 1px solid var(--border); }
.tab {
  background: #111827;
  border: 1px solid var(--border);
  color: var(--text);
  border-radius: 10px;
  padding: 0.35rem 0.65rem;
  cursor: pointer;
  transition: all 0.15s ease;
}
.tab.active { border-color: var(--accent); color: var(--accent); background: rgba(0, 255, 136, 0.1); box-shadow: 0 0 12px rgba(0, 255, 136, 0.2); }

.modal-body { padding: 0.75rem 0.85rem; overflow: auto; }
.doc-search {
  width: 100%;
  background: #0f172a;
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 0.55rem 0.65rem;
  margin-bottom: 0.65rem;
  box-shadow: inset 0 0 0 1px rgba(0, 255, 136, 0.02);
}
.doc-grid { border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
.doc-row { display: grid; grid-template-columns: 320px 1fr; gap: 0; border-bottom: 1px solid #1f2937; }
.doc-row:last-child { border-bottom: none; }
.doc-row.doc-head { background: rgba(0, 255, 136, 0.05); font-weight: 800; color: var(--text); }
.doc-col { padding: 0.55rem 0.65rem; min-width: 0; }
.doc-col.value { border-left: 1px solid #1f2937; }
.doc-pill {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 18px;
  height: 18px;
  border-radius: 6px;
  background: #1f2937;
  color: var(--text);
  font-size: 0.75rem;
  font-weight: 800;
  margin-right: 0.45rem;
}
.doc-field { font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; color: var(--text); }
.doc-value { font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; color: var(--muted); white-space: pre-wrap; word-break: break-word; }
.json-pre { background: #0f172a; border: 1px solid var(--border); border-radius: 12px; padding: 0.75rem; color: var(--text); overflow: auto; box-shadow: inset 0 0 0 1px rgba(0, 255, 136, 0.02); }

.doc-cell {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 0.15rem 0.35rem;
}

.doc-key {
  color: #bfdbfe;
  font-weight: 600;
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
}

.doc-val {
  color: #e5e7eb;
  border-radius: 10px;
  width: 34px;
  height: 34px;
  cursor: pointer;
}
.close-btn:hover { border-color: #3273dc; color: #bfdbfe; }

.modal-tabs { display: flex; gap: 0.35rem; padding: 0.6rem 0.85rem; border-bottom: 1px solid #1f2937; }
.tab {
  background: #111827;
  border: 1px solid #1f2937;
  color: #cbd5e1;
  border-radius: 10px;
  padding: 0.35rem 0.65rem;
  cursor: pointer;
}
.tab.active { border-color: #60a5fa; color: #bfdbfe; background: rgba(37, 99, 235, 0.12); }

.modal-body { padding: 0.75rem 0.85rem; overflow: auto; }
.doc-search {
  width: 100%;
  background: #0f172a;
  color: #e5e7eb;
  border: 1px solid #1f2937;
  border-radius: 10px;
  padding: 0.55rem 0.65rem;
  margin-bottom: 0.65rem;
}
.doc-grid { border: 1px solid #1f2937; border-radius: 12px; overflow: hidden; }
.doc-row { display: grid; grid-template-columns: 320px 1fr; gap: 0; border-bottom: 1px solid #1f2937; }
.doc-row:last-child { border-bottom: none; }
.doc-row.doc-head { background: #0f172a; font-weight: 800; color: #cbd5e1; }
.doc-col { padding: 0.55rem 0.65rem; min-width: 0; }
.doc-col.value { border-left: 1px solid #1f2937; }
.doc-pill {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 18px;
  height: 18px;
  border-radius: 6px;
  background: #1f2937;
  color: #cbd5e1;
  font-size: 0.75rem;
  font-weight: 800;
  margin-right: 0.45rem;
}
.doc-field { font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; color: #e5e7eb; }
.doc-value { font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; color: #cbd5e1; white-space: pre-wrap; word-break: break-word; }
.json-pre { background: #0f172a; border: 1px solid #1f2937; border-radius: 12px; padding: 0.75rem; color: #cbd5e1; overflow: auto; }

.pager {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1rem;
  margin-top: 0.5rem;
  color: var(--text);
  font-size: 0.9rem;
}
.page-size select {
  margin-left: 0.4rem;
  background: #0b1221;
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.35rem 0.5rem;
}
.page-info { display: flex; align-items: center; gap: 0.45rem; }
.nav {
  background: #111827;
  border: 1px solid var(--border);
  color: var(--text);
  border-radius: 6px;
  padding: 0.35rem 0.55rem;
  cursor: pointer;
  transition: all 0.15s ease;
}
.nav:disabled { opacity: 0.4; cursor: not-allowed; }
.nav:not(:disabled):hover { border-color: var(--accent); color: var(--accent); box-shadow: 0 0 10px rgba(0, 255, 136, 0.2); }

@media (max-width: 820px) {
  .doc-row { grid-template-columns: 1fr; }
  .doc-col.value { border-left: none; border-top: 1px solid #1f2937; }
}
</style>
