<script setup>
import { ref, computed, onMounted } from 'vue'

// --- State ---
const loading = ref(false)

// Health
const health = ref({ plugin:'unknown', wazuh_manager:'unknown', wazuh_indexer:'unknown', authenticated:false })

// Operations
const ops = ref([])          // optional: can be pre-fed by parent
const selectedOp = ref('')
const windowSec = ref(60)
const starting = ref(false)
const startOut = ref('')
const loadingDet = ref(false)
const detectOut = ref('')

// Discover
const indices = ref([])
const loadingIdx = ref(false)
const idxHint = ref('인덱스 목록을 불러오려면 [인덱스] 버튼을 누르세요.')
const disc = ref({ q:'', index:'', frm:'', to:'', fields:'', size:100 })
const loadingDisc = ref(false)
const discOut = ref('')

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

// --- Methods ---
function openKibana(){ window.open('https://localhost:5601','_blank') }

async function fetchHealth(){
  try{
    const r = await fetch('/plugin/bastion/health')
    const j = await r.json()
    health.value = j || health.value
  }catch(e){ console.warn('health error', e) }
}

async function refreshAll(){
  loading.value = true
  try{
    await Promise.all([fetchHealth()])
  } finally { loading.value = false }
}

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
  }catch(e){
    detectOut.value = '에러: ' + (e?.message || e)
  }finally{ loadingDet.value = false }
}

function downloadJSON(){ try{ window.location.href = downloadHref.value }catch(e){ alert('다운로드 실패: '+(e?.message||e)) } }
function reloadGUI(){ try{ window.location.href = guiHref.value }catch(e){ alert('GUI 호출 실패: '+(e?.message||e)) } }

async function loadIndices(){
  loadingIdx.value = true
  idxHint.value = '인덱스 목록을 불러오는 중... (최대 10초)'
  const ac = new AbortController()
  const tid = setTimeout(()=>ac.abort(), 10000)
  try{
    const r = await fetch('/discover/indices', { signal: ac.signal })
    const j = await r.json()
    indices.value = (j && Array.isArray(j.indices)) ? j.indices : (j || [])
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
    const j = await r.json()
    discOut.value = JSON.stringify(j, null, 2)
  }catch(e){
    discOut.value = 'error: ' + (e?.message || e)
  }finally{ loadingDisc.value = false }
}

onMounted(() => { refreshAll() })
</script>

<template>
  <div class="p-4">
    <div class="is-flex is-justify-content-space-between is-align-items-center mb-3">
      <div>
        <h2 class="title is-4">BAS ↔ Wazuh 대시보드</h2>
        <p class="subtitle is-6">Caldera Operation과 Wazuh 탐지 상관관계</p>
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

    <!-- Health -->
    <div class="columns is-multiline">
      <div class="column is-3">
        <div class="box">
          <p class="heading">BASTION 플러그인</p>
          <p class="title is-6">{{ health.plugin || 'unknown' }}</p>
        </div>
      </div>
      <div class="column is-3">
        <div class="box">
          <p class="heading">Wazuh Manager</p>
          <p class="title is-6">{{ health.wazuh_manager || 'unknown' }}</p>
        </div>
      </div>
      <div class="column is-3">
        <div class="box">
          <p class="heading">Wazuh Indexer</p>
          <p class="title is-6">{{ health.wazuh_indexer || 'unknown' }}</p>
        </div>
      </div>
      <div class="column is-3">
        <div class="box">
          <p class="heading">인증 상태</p>
          <p class="title is-6">{{ health.authenticated ? 'Authenticated' : 'Not Authenticated' }}</p>
        </div>
      </div>
    </div>

    <!-- Operations / Detections -->
    <div class="box">
      <div class="is-flex is-justify-content-space-between is-align-items-center">
        <h3 class="title is-5">Operation & 탐지 API</h3>
        <div class="is-size-7">/operations/start, /detections</div>
      </div>

      <div class="columns is-vcentered is-mobile mb-3">
        <div class="column is-narrow"><label class="label is-size-7">Operation</label></div>
        <div class="column">
          <div class="select is-fullwidth">
            <select v-model="selectedOp">
              <option value="">(Operation 없음)</option>
              <option v-for="o in ops" :key="o.id" :value="o.id">{{ o.name }} ({{ o.start }})</option>
            </select>
          </div>
        </div>

        <div class="column is-narrow"><label class="label is-size-7">시간 창(초)</label></div>
        <div class="column is-narrow"><input class="input is-small" type="number" min="1" step="1" v-model.number="windowSec"></div>

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
          <pre style="max-height:260px; overflow:auto;">{{ startOut || '(대기 중)' }}</pre>
        </div>
        <div class="column">
          <p class="is-size-7 has-text-grey">detections 응답</p>
          <pre style="max-height:260px; overflow:auto;">{{ detectOut || '(대기 중)' }}</pre>
        </div>
      </div>
    </div>

    <!-- Discover -->
    <div class="box">
      <div class="is-flex is-justify-content-space-between is-align-items-center">
        <h3 class="title is-5">Discover Search 테스트</h3>
        <div class="is-size-7">/discover/search, /discover/indices</div>
      </div>

      <div class="columns is-multiline">
        <div class="column is-8">
          <input class="input is-small" placeholder="query string (예: rule.level:>=10 AND data.mitre.id:T1057)" v-model="disc.q">
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

      <pre style="max-height:360px; overflow:auto;">{{ discOut || '(empty)' }}</pre>
    </div>
  </div>
</template>

<style scoped>
/* Light styling enhancements; relies on Bulma present in host app */
pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }
</style>
