<script setup>
import { ref, computed, onMounted, watch } from 'vue'

/* ------------------------
    상태 체크
------------------------ */
const loading = ref(false)

// Health
const health = ref({
  plugin:'unknown',
  wazuh_manager:'unknown',
  wazuh_indexer:'unknown',
  authenticated:false
})

// Operations 
const ops = ref([])
const selectedOp = ref('')
const windowSec = ref(60)

//  API 응답 표시
const starting = ref(false)
const startOut = ref('')
const loadingDet = ref(false)
const detectOut = ref('')

// 다운로드 링크 
const downloadHref = computed(() => {
  const op = encodeURIComponent(selectedOp.value || '')
  const win = encodeURIComponent(windowSec.value || '')
  return `/plugin/bas_wazuh/download?op_id=${op}&window=${win}`
})
const guiHref = computed(() => {
  const op = encodeURIComponent(selectedOp.value || '')
  const win = encodeURIComponent(windowSec.value || '')
  return `/plugin/bas_wazuh/gui?op_id=${op}&window=${win}`
})

/* ------------------------
   KPI
------------------------ */
const kpi = ref({ operations:0, agents:0, steps:0, detections:0, coverage:0 })
const lastSeen = ref(null)

// KPI 파생값 & 커버리지 그래프용 상태
const coveragePct = ref(0)
const totalAlerts = ref(0)
const tacticBars = ref([])   // [{ tactic, executed, detected }]
const barMax = computed(() => {
  if (!tacticBars.value.length) return 0
  return Math.max(
    ...tacticBars.value.map(b => Math.max(Number(b.executed||0), Number(b.detected||0)))
  )
})

/* ------------------------
   Coverage / Dashboard 추가 입력
------------------------ */
const idx = ref({ index:'wazuh-alerts-*', verify_ssl:false })
const opRange = ref({ start:'', end:'' })
const outCorr = ref('')
const outDash = ref('')
const loadingCorr = ref(false)
const loadingDash = ref(false)
const operationChain = ref([])
const chainOpId = ref(null)
let pendingDashboardRefresh = false

/* ------------------------
   Discover (하단 토글)
------------------------ */
const indices = ref([])
const loadingIdx = ref(false)
const idxHint = ref('인덱스 목록을 불러오려면 [인덱스] 버튼을 누르세요.')
const disc = ref({ q:'', index:'', frm:'', to:'', fields:'', size:100 })
const loadingDisc = ref(false)
const discOut = ref('')

/* ------------------------
   유틸
------------------------ */
function openKibana(){ window.open('https://localhost:5601','_blank') }

async function jsonOrText(res){
  const txt = await res.text()
  try { return JSON.parse(txt) } catch { return { error: txt } }
}

/* ------------------------
   Health + Dashboard
------------------------ */
async function fetchHealth(){
  try{
    const r = await fetch('/api/health', { credentials:'same-origin' })
    const j = await r.json()
    health.value = j || health.value
  }catch(e){ /* noop */ }
}

function buildTacticBarsFromCoverage(cov) {
  const alerts = Array.isArray(cov?.alerts_matched) ? cov.alerts_matched : []
  // tactic → {techSet:Set, detSet:Set}
  const bucket = new Map()
  for (const a of alerts) {
    const dm = (a?.data || {}).mitre || {}
    const tval = dm.tactic
    let tactics = []
    if (Array.isArray(tval)) tactics = tval
    else if (tval) tactics = [tval]
    else tactics = ['(unknown)']

    const tids = Array.isArray(a?.technique_ids) ? a.technique_ids : []
    const tidSet = new Set(tids.length ? tids : ['(unknown)'])

    for (const t of tactics) {
      const key = String(t)
      if (!bucket.has(key)) bucket.set(key, { techSet: new Set(), detSet: new Set() })
      const ent = bucket.get(key)
      tidSet.forEach(x => { ent.techSet.add(x); ent.detSet.add(x) })
    }
  }

  const rows = []
  for (const [t, v] of bucket.entries()) {
    rows.push({ tactic: t, executed: v.techSet.size, detected: v.detSet.size })
  }
  rows.sort((a,b)=>a.tactic.localeCompare(b.tactic))
  tacticBars.value = rows
}

async function refreshDashboard() {
  if (loadingDash.value) {
    pendingDashboardRefresh = true
    return
  }
  loadingDash.value = true
  try {
    await loadOperationChain()
    const payload = {
      operation: {
        id: selectedOp.value || null,
        start: null,
        end: null,
        chain: JSON.parse(JSON.stringify(operationChain.value))
      },
      indexer: {
        index: idx.value.index || 'wazuh-alerts-*',
        verify_ssl: !!idx.value.verify_ssl
      }
    }
    const r = await fetch('/api/dashboard/summary', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      credentials:'same-origin',
      body: JSON.stringify(payload)
    })
    const j = await jsonOrText(r)
    outDash.value = JSON.stringify(j, null, 2)

    if (j?.kpi) {
      kpi.value.operations = Number(j.kpi.operations ?? 0)
    }

    kpi.value.steps = Number(
      j.coverage?.attack_steps ??
      j.kpi?.steps ??
      (Array.isArray(j.coverage?.correlation?.all_operation_techniques)
        ? j.coverage.correlation.all_operation_techniques.length
        : 0)
    )

    kpi.value.detections = Number(j.coverage?.total_alerts ?? 0)

    try {
      const set = new Set()
      ;(j.coverage?.alerts_matched || []).forEach(a=>{
        const ag = a?.agent
        if (ag?.name) set.add(ag.name)
        else if (ag?.id) set.add(ag.id)
      })
      kpi.value.agents = set.size
    } catch { kpi.value.agents = 0 }

    lastSeen.value = j.coverage?.end_time || j.generated_at || null

    const coverageRate = Number(
      j.coverage?.correlation?.detection_rate ??
      j.kpi?.detection_rate ?? 0
    )
    kpi.value.coverage = coverageRate
    coveragePct.value = coverageRate
    totalAlerts.value = Number(j.coverage?.total_alerts ?? 0)

    buildTacticBarsFromCoverage(j.coverage)
  } finally {
    loadingDash.value = false
    if (pendingDashboardRefresh) {
      pendingDashboardRefresh = false
      await refreshDashboard()
    }
  }
}

async function refreshAll(){
  loading.value = true
  try{
    await fetchHealth()
    await loadOperationChain()
    await refreshDashboard()
  } finally { loading.value = false }
}

/* ------------------------
   Operations: 목록 로드
------------------------ */
async function loadOps() {
  try {
    const r = await fetch('/operations/list', { credentials:'same-origin' })
    const j = await r.json()
    ops.value = Array.isArray(j?.ops) ? j.ops : []
    if (!selectedOp.value && ops.value.length) {
      selectedOp.value = String(ops.value[0].id)
    }
  } catch (e) {
    console.warn('loadOps error', e)
    ops.value = []
  }
}

async function loadOperationChain(opId = selectedOp.value, force = false) {
  if (!opId) {
    operationChain.value = []
    chainOpId.value = null
    return
  }
  if (!force && chainOpId.value === opId && operationChain.value.length) {
    return
  }
  try {
    const body = { op_id: opId }
    if (windowSec.value) body.time_window_sec = Number(windowSec.value)
    const resp = await fetch('/operations/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(body)
    })
    if (!resp.ok) {
      throw new Error(`operations/start ${resp.status}`)
    }
    const data = await resp.json()
    const events = Array.isArray(data?.events) ? data.events : []
    const mapped = events.map(ev => {
      const finish = ev?.executed_at || ev?.timestamp || null
      return {
        id: ev?.link_id || ev?.id || '',
        link_id: ev?.link_id || ev?.id || '',
        technique_id: ev?.technique_id ||
          (ev?.ability && ev.ability.technique_id) || null,
        ability: {
          technique_id: ev?.technique_id || null,
          name: ev?.ability_name || ''
        },
        ability_name: ev?.ability_name || '',
        finish,
        start: ev?.start || null,
        executed_at: ev?.executed_at || null
      }
    }).filter(item => item.finish !== null && item.finish !== undefined)
    operationChain.value = mapped
    chainOpId.value = opId
  } catch (e) {
    console.warn('loadOperationChain error', e)
    operationChain.value = []
    chainOpId.value = null
  }
}

watch(selectedOp, async () => {
  operationChain.value = []
  chainOpId.value = null
  await refreshDashboard()
})

watch(windowSec, async () => {
  chainOpId.value = null
  await refreshDashboard()
})

/* ------------------------
  Operation / Detections
------------------------ */
async function startOperation(){
  if(!selectedOp.value){ alert('Operation을 선택하세요'); return; }
  starting.value = true
  startOut.value = '요청 중...'
  try{
    const body = { op_id: selectedOp.value }
    if(windowSec.value) body.time_window_sec = Number(windowSec.value)
    const r = await fetch('/operations/start', {
      method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin',
      body: JSON.stringify(body)
    })
    const j = await r.json()
    startOut.value = JSON.stringify(j, null, 2)
    await loadOperationChain(selectedOp.value, true)
    await refreshDashboard()
  }catch(e){
    startOut.value = '에러: ' + (e?.message || e)
  }finally{ starting.value = false }
}

async function loadDetections(){
  if(!selectedOp.value){ alert('Operation을 선택하세요'); return; }
  loadingDet.value = true
  detectOut.value = '요청 중...'
  try{
    const url = new URL(window.location.origin + '/detections')
    url.searchParams.set('op_id', selectedOp.value)
    if(windowSec.value) url.searchParams.set('time_window_sec', String(windowSec.value))
    const r = await fetch(url, { credentials:'same-origin' })
    const j = await r.json()
    detectOut.value = JSON.stringify(j, null, 2)
  }catch(e){
    detectOut.value = '에러: ' + (e?.message || e)
  }finally{ loadingDet.value = false }
}

function downloadJSON(){ try{ window.location.href = downloadHref.value }catch(e){ alert('다운로드 실패: '+(e?.message||e)) } }
function reloadGUI(){ try{ window.location.href = guiHref.value }catch(e){ alert('GUI 호출 실패: '+(e?.message||e)) } }

/* ------------------------
  Correlate
------------------------ */
async function callCorrelate(){
  if (loadingCorr.value) {
    return
  }
  loadingCorr.value = true
  outCorr.value = '요청 중...'
  try{
    await loadOperationChain()
    const payload = {
      operation: {
        id: selectedOp.value || null,
        name: 'manual',
        start: opRange.value.start || null,
        end: opRange.value.end || null,
        chain: JSON.parse(JSON.stringify(operationChain.value))
      },
      indexer: {
        index: idx.value.index || 'wazuh-alerts-*',
        verify_ssl: !!idx.value.verify_ssl
      }
    }
    const r = await fetch('/api/correlate', {
      method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin',
      body: JSON.stringify(payload)
    })
    outCorr.value = JSON.stringify(await jsonOrText(r), null, 2)
  }catch(e){
    outCorr.value = '에러: ' + (e?.message || e)
  }finally{ loadingCorr.value = false }
}

/* ------------------------
   Discover 하단 토글(테스트용)
------------------------ */
async function loadIndices(){
  loadingIdx.value = true
  idxHint.value = '인덱스 목록을 불러오는 중... (최대 10초)'
  const ac = new AbortController()
  const tid = setTimeout(()=>ac.abort(), 10000)
  try{
    const r = await fetch('/discover/indices', { signal: ac.signal, credentials:'same-origin' })
    const j = await r.json()
    indices.value = Array.isArray(j?.indices) ? j.indices : []
    idxHint.value = indices.value.length ? `${indices.value.length}개 인덱스 로드됨` : '인덱스가 없습니다.'
  }catch(e){
    idxHint.value = '인덱스 조회 실패: ' + (e?.message || e)
  }finally{
    clearTimeout(tid)
    loadingIdx.value = false
  }
}

async function discoverSearch(){
  loadingDisc.value = true
  discOut.value = 'requesting...'
  try{
    const url = new URL(window.location.origin + '/discover/search')
    const s = disc.value
    if(s.q) url.searchParams.set('q', s.q)
    if(s.index) url.searchParams.set('index', s.index)
    if(s.frm) url.searchParams.set('from', s.frm)
    if(s.to) url.searchParams.set('to', s.to)
    if(s.fields) url.searchParams.set('fields', s.fields)
    if(s.size) url.searchParams.set('size', String(s.size))
    url.searchParams.set('sort', '@timestamp:desc')
    const r = await fetch(url, { credentials:'same-origin' })
    discOut.value = JSON.stringify(await jsonOrText(r), null, 2)
  }catch(e){
    discOut.value = 'error: ' + (e?.message || e)
  }finally{ loadingDisc.value = false }
}

/* init */
onMounted(async () => {
  await loadOps()
  await refreshAll()
})
</script>

<template>
  <div class="p-4">

    <!-- 헤더 / 상단 컨트롤 -->
    <div class="is-flex is-justify-content-space-between is-align-items-center mb-3">
      <div>
        <h1 class="title is-3">CALDERA × Wazuh BAS Dashboard</h1>
        <p class="subtitle is-6">공격 시뮬레이션과 탐지 이벤트를 연계하여 커버리지와 리스크를 한눈에.</p>
      </div>
      <div class="buttons">
        <button class="button is-small" @click="refreshAll">
          <span class="icon"><i :class="loading ? 'fas fa-spinner fa-pulse' : 'fas fa-rotate-right'"></i></span>
          <span>{{ loading ? '갱신 중...' : '새로고침' }}</span>
        </button>
        <button class="button is-small is-link" @click="openKibana">
          <span class="icon"><i class="fas fa-external-link"></i></span><span>Kibana 열기</span>
        </button>
      </div>
    </div>

    <!-- 필터 바 -->
    <div class="box">
      <div class="columns is-vcentered is-multiline">
        <div class="column is-4">
          <input class="input is-small" placeholder="Agent, Description, Technique..." />
        </div>
        <div class="column is-4">
          <div class="select is-fullwidth is-small">
            <select v-model="selectedOp">
              <option value="">All Operations</option>
              <option v-for="o in ops" :key="o.id" :value="o.id">{{ o.name }} ({{ o.start }})</option>
            </select>
          </div>
        </div>
        <div class="column is-4">
          <div class="select is-fullwidth is-small">
            <select>
              <option>Any OS</option>
              <option>Windows</option>
              <option>Linux</option>
              <option>macOS</option>
            </select>
          </div>
        </div>
      </div>
    </div>

    <!-- KPI 카드 -->
    <div class="columns is-multiline">
      <div class="column is-2">
        <div class="box has-text-centered">
          <p class="has-text-grey is-size-7">OPERATIONS</p>
          <p class="is-size-3">{{ kpi.operations }}</p>
        </div>
      </div>
      <div class="column is-2">
        <div class="box has-text-centered">
          <p class="has-text-grey is-size-7">AGENTS</p>
          <p class="is-size-3">{{ kpi.agents }}</p>
        </div>
      </div>
      <div class="column is-2">
        <div class="box has-text-centered">
          <p class="has-text-grey is-size-7">ATTACK STEPS</p>
          <p class="is-size-3">{{ kpi.steps }}</p>
        </div>
      </div>
      <div class="column is-2">
        <div class="box has-text-centered">
          <p class="has-text-grey is-size-7">DETECTIONS</p>
          <p class="is-size-3">{{ kpi.detections }}</p>
        </div>
      </div>
      <div class="column is-2">
        <div class="box has-text-centered">
          <p class="has-text-grey is-size-7">COVERAGE</p>
          <p class="is-size-3">{{ kpi.coverage.toFixed(1) }}%</p>
          <p class="is-size-7 has-text-grey">alerts: {{ totalAlerts }}</p>
        </div>
      </div>
      <div class="column is-2">
        <div class="box has-text-centered">
          <p class="has-text-grey is-size-7">LAST SEEN</p>
          <p class="is-size-6">{{ lastSeen || '-' }}</p>
        </div>
      </div>
    </div>

    <!-- 그래프 영역 -->
    <div class="grid grid-cols-2 gap-3 mt-4">
      <!-- 좌측: Tactic Coverage 그래프 -->
      <div class="rounded-lg p-4 border">
        <div class="text-sm font-semibold mb-2">Tactic Coverage</div>
        <div v-if="!tacticBars.length" class="text-xs opacity-60">데이터가 없습니다.</div>

        <svg v-else :width="800" height="220" class="block">
          <!-- 좌측/하단 축 -->
          <line x1="50" y1="10" x2="50" y2="190" stroke="currentColor" opacity="0.2" />
          <line x1="50" y1="190" x2="780" y2="190" stroke="currentColor" opacity="0.2" />

          <!-- 막대그래프 반복 렌더링 -->
          <g v-for="(b, i) in tacticBars" :key="i">
            <template v-if="barMax">
              <g :transform="`translate(${70 + i * 70},0)`">
                <!-- Executed -->
                <rect
                  :x="0"
                  :y="190 - Math.round((b.executed / barMax) * 160)"
                  width="18"
                  :height="Math.round((b.executed / barMax) * 160)"
                  rx="3" ry="3" fill="#a0aec0" opacity="0.6"
                />
                <!-- Detected -->
                <rect
                  :x="22"
                  :y="190 - Math.round((b.detected / barMax) * 160)"
                  width="18"
                  :height="Math.round((b.detected / barMax) * 160)"
                  rx="3" ry="3" fill="#2563eb" opacity="0.9"
                />
                <!-- 값 라벨 -->
                <text :x="9"  :y="190 - Math.round((b.executed / barMax) * 160) - 4"
                      font-size="10" text-anchor="middle" fill="#aaa">{{ b.executed }}</text>
                <text :x="31" :y="190 - Math.round((b.detected / barMax) * 160) - 4"
                      font-size="10" text-anchor="middle" fill="#2563eb">{{ b.detected }}</text>
                <!-- tactic 이름 -->
                <text :x="11" y="206" font-size="10" text-anchor="middle" transform="rotate(45,11,206)">
                  {{ b.tactic }}
                </text>
              </g>
            </template>
          </g>

          <!-- 범례 -->
          <g>
            <rect x="60" y="10" width="10" height="10" fill="#a0aec0" opacity="0.6" />
            <text x="75" y="19" font-size="10">Executed</text>
            <rect x="130" y="10" width="10" height="10" fill="#2563eb" opacity="0.9" />
            <text x="145" y="19" font-size="10">Detected</text>
          </g>
        </svg>

        <div class="text-[11px] opacity-60 mt-1">범례: 좌측 = Executed, 우측 = Detected</div>
      </div>

      <!-- 우측: (플레이스홀더) Attack vs Detection Timeline -->
      <div class="rounded-lg p-4 border">
        <!-- 컴포넌트가 있다면 활성화하세요 -->
        <!-- <AttackTimelineChart /> -->
        <div class="has-text-grey is-size-7">Timeline 차트 영역</div>
      </div>
    </div>

    <!-- Operation & 탐지 (기존 유지) -->
    <div class="box" style="margin-top:16px;">
      <div class="is-flex is-justify-content-space-between is-align-items-center">
        <h3 class="title is-5">Operation & 탐지 API</h3>
        <div class="is-size-7">/operations/start, /detections</div>
      </div>

      <div class="columns is-vcentered is-mobile mb-3">
        <div class="column is-narrow"><label class="label is-size-7">시간 창(초)</label></div>
        <div class="column is-narrow" style="width:140px;">
          <input class="input is-small" type="number" min="1" step="1" v-model.number="windowSec">
        </div>

        <div class="column is-narrow">
          <button class="button is-small" @click="startOperation">
            <span class="icon"><i :class="starting ? 'fas fa-spinner fa-pulse' : 'fas fa-play'"></i></span>
            <span>작전 시작</span>
          </button>
        </div>
        <div class="column is-narrow">
          <button class="button is-small is-primary" @click="loadDetections">
            <span class="icon"><i :class="loadingDet ? 'fas fa-spinner fa-pulse' : 'fas fa-magnifying-glass'"></i></span>
            <span>탐지 조회</span>
          </button>
        </div>
        <div class="column is-narrow">
          <a class="button is-small" :href="downloadHref" @click.prevent="downloadJSON">
            <span class="icon"><i class="fas fa-file-download"></i></span><span>JSON</span>
          </a>
        </div>
        <div class="column is-narrow">
          <a class="button is-small" :href="guiHref" @click.prevent="reloadGUI">
            <span class="icon"><i class="fas fa-window-restore"></i></span><span>GUI</span>
          </a>
        </div>
      </div>

      <div class="columns" style="gap:16px;">
        <div class="column">
          <p class="is-size-7 has-text-grey">operations/start 응답</p>
          <pre style="max-height:220px; overflow:auto;">{{ startOut || '(대기 중)' }}</pre>
        </div>
        <div class="column">
          <p class="is-size-7 has-text-grey">detections 응답</p>
          <pre style="max-height:220px; overflow:auto;">{{ detectOut || '(대기 중)' }}</pre>
        </div>
      </div>
    </div>

    <!-- Coverage  (테스트용 섹션) -->
    <div class="box">
      <div class="is-flex is-justify-content-space-between is-align-items-center">
        <h3 class="title is-5">Coverage </h3>
        <div class="is-size-7">/api/correlate, /api/dashboard/summary</div>
      </div>

      <div class="columns is-multiline">
        <div class="column is-4">
          <label class="label is-size-7">index pattern</label>
          <input class="input is-small" v-model="idx.index" placeholder="wazuh-alerts-*">
        </div>
        <div class="column is-4">
          <label class="label is-size-7">operation start (ISO/epoch, 옵션)</label>
          <input class="input is-small" v-model="opRange.start" placeholder="예: 2025-10-15T12:00:00Z">
        </div>
        <div class="column is-4">
          <label class="label is-size-7">operation end (ISO/epoch, 옵션)</label>
          <input class="input is-small" v-model="opRange.end" placeholder="예: 2025-10-15T13:00:00Z">
        </div>
      </div>

      <div class="buttons">
        <button class="button is-small" @click="callCorrelate">
          <span class="icon"><i :class="loadingCorr ? 'fas fa-spinner fa-pulse' : 'fas fa-link'"></i></span>
          <span>Correlate</span>
        </button>
        <button class="button is-small" @click="refreshDashboard">
          <span class="icon"><i :class="loadingDash ? 'fas fa-spinner fa-pulse' : 'fas fa-chart-line'"></i></span>
          <span>Dashboard</span>
        </button>
      </div>

      <div class="columns" style="gap:16px;">
        <div class="column">
          <p class="is-size-7 has-text-grey">/api/correlate 응답</p>
          <pre style="max-height:220px; overflow:auto;">{{ outCorr || '(대기 중)' }}</pre>
        </div>
        <div class="column">
          <p class="is-size-7 has-text-grey">/api/dashboard/summary 응답</p>
          <pre style="max-height:220px; overflow:auto;">{{ outDash || '(대기 중)' }}</pre>
        </div>
      </div>
    </div>

    <!-- Discover: 필요 시만 열기 -->
    <details class="box" style="margin-top:16px;">
      <summary>/discover 테스트 (필요 시 열기)</summary>
      <div class="columns is-multiline mt-3">
        <div class="column is-8">
          <input class="input is-small" placeholder='query string (예: rule.level:>=10 AND data.mitre.id:T1057)' v-model="disc.q">
        </div>
        <div class="column is-4">
          <div class="field has-addons">
            <p class="control is-expanded">
              <div class="select is-fullwidth is-small">
                <select v-model="disc.index">
                  <option value="">(index 자동)</option>
                  <option v-for="name in indices" :key="name" :value="name">{{ name }}</option>
                </select>
              </div>
            </p>
            <p class="control">
              <button class="button is-small" @click="loadIndices">
                <span class="icon"><i :class="loadingIdx ? 'fas fa-spinner fa-pulse' : 'fas fa-database'"></i></span>
                <span>인덱스</span>
              </button>
            </p>
          </div>
          <p class="is-size-7 has-text-grey mt-1">{{ idxHint }}</p>
        </div>

        <div class="column is-3"><input class="input is-small" placeholder="from (ISO/epoch)" v-model="disc.frm"></div>
        <div class="column is-3"><input class="input is-small" placeholder="to (ISO/epoch)" v-model="disc.to"></div>
        <div class="column is-3"><input class="input is-small" placeholder="fields (comma separated)" v-model="disc.fields"></div>
        <div class="column is-2"><input class="input is-small" type="number" min="1" step="1" v-model.number="disc.size" placeholder="100"></div>
        <div class="column is-1">
          <button class="button is-small is-primary is-fullwidth" @click="discoverSearch">
            <span class="icon"><i :class="loadingDisc ? 'fas fa-spinner fa-pulse' : 'fas fa-search'"></i></span>
          </button>
        </div>
      </div>

      <pre style="max-height:300px; overflow:auto;">{{ discOut || '(empty)' }}</pre>
    </details>
  </div>
</template>

<style scoped>
/* 최소 스타일 (Bulma 전제) */
pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }
.grid { display: grid; }
.grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.gap-3 { gap: .75rem; }
.p-4 { padding: 1rem; }
.rounded-lg { border-radius: .75rem; }
.border { border: 1px solid rgba(255,255,255,.1); }
.text-sm { font-size: .875rem; }
.font-semibold { font-weight: 600; }
.mb-2 { margin-bottom: .5rem; }
.text-xs { font-size: .75rem; }
.opacity-60 { opacity: .6; }
.block { display: block; }
.text-\[11px] { font-size: 11px; }
.mt-1 { margin-top: .25rem; }
</style>
