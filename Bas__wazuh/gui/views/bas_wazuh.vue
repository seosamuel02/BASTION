<script setup>
import { ref, computed, onMounted } from 'vue'

/* ------------------------
   공통/기존 상태
------------------------ */
const loading = ref(false)

// Health
const health = ref({
  plugin:'unknown',
  wazuh_manager:'unknown',
  wazuh_indexer:'unknown',
  authenticated:false
})

// Operations (서버에서 주입되거나, 추후 동적 주입)
const ops = ref([])            // [{id,name,start}, ...]
const selectedOp = ref('')
const windowSec = ref(60)

// 기존 API 응답 표시
const starting = ref(false)
const startOut = ref('')
const loadingDet = ref(false)
const detectOut = ref('')

// 다운로드/GUI 링크 (기존 경로 유지)
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
  const vals = (tacticBars.value || []).flatMap(b => {
    const e = Number.isFinite(+b.executed) ? +b.executed : 0
    const d = Number.isFinite(+b.detected) ? +b.detected : 0
    return [e, d]
  })
  if (!vals.length) return 0
  return Math.max(...vals)
})

/* ------------------------
   Coverage / Dashboard (테스트)
------------------------ */
const idx = ref({ index:'wazuh-alerts-*', verify_ssl:false })
const opRange = ref({ start:'', end:'' })
const outCorr = ref('')
const outDash = ref('')
const loadingCorr = ref(false)
const loadingDash = ref(false)

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
function openKibana(){
  const base = (window.__KIBANA_URL__) || 'https://3.38.215.161'
  window.open(base, '_blank')
}

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

// ---------- helpers: /detections 응답 KPI 유도 ----------
function _arrayify(v) { return Array.isArray(v) ? v : (v != null ? [v] : []) }
function countDistinctTechniqueGroups(alerts) {
  const groups = new Set()
  for (const a of alerts || []) {
    let tids = []
    if (Array.isArray(a?.technique_ids)) tids = a.technique_ids
    else if (a?.data?.mitre?.id) tids = _arrayify(a.data.mitre.id)
    else if (a && (a['mitre.id'] != null)) tids = _arrayify(a['mitre.id'])
    if (!tids.length) tids = ['(unknown)']
    groups.add(tids.join('|'))
  }
  return groups.size
}
// /detections 응답 → KPI 도출
function deriveCoverageKPIFromDetections(detJson, prev = { steps: 0 }) {
  const cov = (detJson && (detJson.coverage || detJson)) || {}
  const endTime = cov.end_time || detJson?.end_time || null

  let attackSteps =
  Number(cov.attack_steps ??
  cov.total_links ??
   (Array.isArray(cov.correlation?.all_operation_techniques)
        ? cov.correlation.all_operation_techniques.length
        : NaN))

  let repAlerts =
   Number(cov.total_alerts ??
    cov.alerts_detected ??
    (Array.isArray(cov.alerts_per_link) ? cov.alerts_per_link.length : NaN))
  
  let detectionRate = Number(
    (cov.correlation && cov.correlation.detection_rate) ?? NaN
  )
  if (Number.isFinite(detectionRate) && detectionRate > 0 && detectionRate <= 1) {
    detectionRate = detectionRate * 100
    detectionRate = Math.round(detectionRate * 10) / 10
  }

   if (!Number.isFinite(repAlerts)) {
    const alertsArr =
      Array.isArray(detJson) ? detJson :
      (Array.isArray(detJson?.alerts) ? detJson.alerts : [])
    repAlerts = countDistinctTechniqueGroups(alertsArr) // 대표 1건/기술 단위
  }
  if (!Number.isFinite(attackSteps)) {
    attackSteps = repAlerts
  }
  if (!Number.isFinite(detectionRate)) {
    detectionRate = attackSteps ? Math.round((repAlerts / attackSteps) * 1000) / 10 : 0
  }
  return { attackSteps, repAlerts, detectionRate, endTime }
}



  // coverage 응답 → Tactic 막대그래프 집계
function buildTacticBarsFromCoverage(cov) {
  if (!cov) { tacticBars.value = []; return }
  const src = Array.isArray(cov?.alerts_per_link)
    ? cov.alerts_per_link.map(x => x?.representative_alert || x).filter(Boolean)
    : (Array.isArray(cov?.alerts_matched) ? cov.alerts_matched : [])
  if (!src.length) { tacticBars.value = []; return }

  const bucket = new Map() // tactic -> { techSet:Set, detSet:Set }
  for (const a of src) {
    const dm = (a?.data?.mitre) || {}
    const tval = dm.tactic
    const tactics = Array.isArray(tval) ? tval : (tval ? [tval] : ['(unknown)'])

    let tids = []
    if (Array.isArray(a?.technique_ids)) tids = a.technique_ids
    else if (dm.id) tids = Array.isArray(dm.id) ? dm.id : [dm.id]
    else tids = ['(unknown)']
    const tidSet = new Set(tids.map(String))

    for (const t of tactics) {
      const key = String(t)
      if (!bucket.has(key)) bucket.set(key, { techSet: new Set(), detSet: new Set() })
      const ent = bucket.get(key)
      tidSet.forEach(x => { ent.techSet.add(x); ent.detSet.add(x) })
    }
  }

  const rows = Array.from(bucket.entries()).map(([t, v]) => ({
    tactic: t, executed: v.techSet.size, detected: v.detSet.size
  }))
  rows.sort((a,b)=>a.tactic.localeCompare(b.tactic))
  tacticBars.value = rows
}

async function refreshDashboard() {
  const payload = {
    operation: {
      id: selectedOp.value || null,
      start: null,
      end: null,
      chain: []
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

  // 기본 KPI
  if (j?.kpi) {
    kpi.value.operations = Number(
    j.kpi.operations ??
    (Array.isArray(j?.operations) ? j.operations.length : 0)
  )
    kpi.value.detections = Number(j.kpi.alerts_total ?? 0)
  }

  // agents 추정
  try {
    const set = new Set()
    if (Array.isArray(j.coverage?.alerts_per_link)) {
      j.coverage.alerts_per_link.forEach(x => {
        const rep = x?.representative_alert || x
        const ag = rep?.agent
        if (ag?.name) set.add(ag.name)
        else if (ag?.id) set.add(ag.id)
      })
    } else if (Array.isArray(j.coverage?.alerts_matched)) {
      j.coverage.alerts_matched.forEach(a => {
        const ag = a?.agent
        if (ag?.name) set.add(ag.name)
        else if (ag?.id) set.add(ag.id)
      })
    }
    kpi.value.agents = set.size
  } catch { kpi.value.agents = 0 }

  // steps =  technique 수(없으면 0)
  kpi.value.steps = Array.isArray(j.coverage?.correlation?.all_operation_techniques)
    ? j.coverage.correlation.all_operation_techniques.length : 0

  lastSeen.value = j.coverage?.end_time || j.generated_at || null

  // 커버리지 KPI/그래프 파생값
  let dr = Number(
    j.coverage?.correlation?.detection_rate ??
    j.kpi?.detection_rate ?? 0
  )
  // 비율(0~1)인 경우 퍼센트로 보정
  if (dr > 0 && dr <= 1) dr = dr * 100
  coveragePct.value = dr
  kpi.value.coverage = dr

  // total alerts 폴백: alerts_per_link(대표 1건 기준) → alerts_matched
  totalAlerts.value = Number(
    j.coverage?.total_alerts ??
    (Array.isArray(j.coverage?.alerts_per_link) ? j.coverage.alerts_per_link.length :
     Array.isArray(j.coverage?.alerts_matched) ? j.coverage.alerts_matched.length : 0)
  )

  buildTacticBarsFromCoverage(j.coverage)
}

async function refreshAll(){
  loading.value = true
  try{
    await fetchHealth()
    await refreshDashboard()
  } finally { loading.value = false }
}

/* ------------------------
   Operations: 목록 로드
------------------------ */
async function loadOps() {
  try {
    const r = await fetch('/api/operations', { credentials:'same-origin' })
    const j = await r.json()
    const items = Array.isArray(j) ? j
                : Array.isArray(j?.items) ? j.items
                : Array.isArray(j?.ops) ? j.ops
                : []
    ops.value = items.map(o => ({ id: o.id || o.operation_id || o.name, name: o.name || o.id, start: o.start }))
    if (!selectedOp.value && ops.value.length) {
      selectedOp.value = String(ops.value[0].id)
    }
  } catch (e) {
    console.warn('loadOps error', e)
    ops.value = []
  }
}

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
     const { attackSteps, repAlerts, detectionRate, endTime } =
     deriveCoverageKPIFromDetections(j, { steps: kpi.value.steps })
    kpi.value.steps      = attackSteps
    kpi.value.detections = repAlerts
    kpi.value.coverage   = detectionRate
    coveragePct.value    = detectionRate
    totalAlerts.value    = repAlerts
    lastSeen.value       = endTime || lastSeen.value

  const covLike = (j && (j.coverage || j)) || {}
    buildTacticBarsFromCoverage(
      Array.isArray(covLike.alerts_per_link) || Array.isArray(covLike.alerts_matched)
        ? covLike : { alerts_matched: (Array.isArray(j) ? j : (j.alerts || [])) }
    )
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
  loadingCorr.value = true
  outCorr.value = '요청 중...'
  try{
    const payload = {
      operation: {
        id: selectedOp.value || null,
        name: 'manual',
        start: opRange.value.start || null,
        end: opRange.value.end || null,
        chain: []
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
          <p class="is-size-3">{{ coveragePct.toFixed(1) }}%</p>
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
      <!--  Coverage 그래프 들어갈곳-->
    </div>

    <!-- Operation & 탐지 -->
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

    <!-- Coverage / Dashboard (테스트용 섹션) -->
    <div class="box">
      <div class="is-flex is-justify-content-space-between is-align-items-center">
        <h3 class="title is-5">Coverage / Dashboard</h3>
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
.text-11px { font-size: 11px; }
.mt-1 { margin-top: .25rem; }
</style>