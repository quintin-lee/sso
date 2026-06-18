<template>
  <div class="space-y-8 animate-fade-in">
    <!-- Stats Grid -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
      <!-- Total Evaluations -->
      <div class="bg-gradient-to-br from-slate-900 to-slate-950 border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden flex flex-col justify-between group hover:border-indigo-500 transition-all duration-300">
        <div class="absolute top-0 right-0 w-24 h-24 bg-indigo-500/10 rounded-full blur-2xl group-hover:bg-indigo-500/20 transition-all"></div>
        <div class="flex justify-between items-start">
          <span class="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-widest">{{ $t('dashboard.totalEvals') }}</span>
          <div class="w-8 h-8 bg-indigo-500/10 rounded-xl flex items-center justify-center text-indigo-400">
            <i class="pi pi-shield"></i>
          </div>
        </div>
        <div class="mt-4">
          <h3 class="text-3xl font-extrabold text-white tracking-tight">{{ totalEvals }}</h3>
          <p class="text-xs text-indigo-400 font-medium mt-1">Live requests stream</p>
        </div>
      </div>

      <!-- Interception Rate -->
      <div class="bg-gradient-to-br from-slate-900 to-slate-950 border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden flex flex-col justify-between group hover:border-rose-500 transition-all duration-300">
        <div class="absolute top-0 right-0 w-24 h-24 bg-rose-500/10 rounded-full blur-2xl group-hover:bg-rose-500/20 transition-all"></div>
        <div class="flex justify-between items-start">
          <span class="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-widest">{{ $t('dashboard.interceptionRate') }}</span>
          <div class="w-8 h-8 bg-rose-500/10 rounded-xl flex items-center justify-center text-rose-400">
            <i class="pi pi-ban"></i>
          </div>
        </div>
        <div class="mt-4 flex items-baseline gap-2">
          <h3 class="text-3xl font-extrabold text-white tracking-tight">{{ interceptionRate.toFixed(1) }}%</h3>
          <span class="text-xs font-semibold" :class="interceptionRate > 20 ? 'text-rose-400' : 'text-[var(--text-secondary)]'">
            {{ interceptionRate > 20 ? 'High' : 'Normal' }}
          </span>
        </div>
      </div>

      <!-- Average Latency -->
      <div class="bg-gradient-to-br from-slate-900 to-slate-950 border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden flex flex-col justify-between group hover:border-amber-500 transition-all duration-300">
        <div class="absolute top-0 right-0 w-24 h-24 bg-amber-500/10 rounded-full blur-2xl group-hover:bg-amber-500/20 transition-all"></div>
        <div class="flex justify-between items-start">
          <span class="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-widest">{{ $t('dashboard.avgLatency') }}</span>
          <div class="w-8 h-8 bg-amber-500/10 rounded-xl flex items-center justify-center text-amber-400">
            <i class="pi pi-clock"></i>
          </div>
        </div>
        <div class="mt-4">
          <h3 class="text-3xl font-extrabold text-white tracking-tight">{{ avgLatency.toFixed(2) }} ms</h3>
          <p class="text-xs text-amber-400 font-medium mt-1">L1/L2 cache-optimized</p>
        </div>
      </div>

      <!-- Cache Hit Rate -->
      <div class="bg-gradient-to-br from-slate-900 to-slate-950 border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden flex flex-col justify-between group hover:border-emerald-500 transition-all duration-300">
        <div class="absolute top-0 right-0 w-24 h-24 bg-emerald-500/10 rounded-full blur-2xl group-hover:bg-emerald-500/20 transition-all"></div>
        <div class="flex justify-between items-start">
          <span class="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-widest">{{ $t('dashboard.cacheHitRate') }}</span>
          <div class="w-8 h-8 bg-emerald-500/10 rounded-xl flex items-center justify-center text-emerald-400">
            <i class="pi pi-bolt"></i>
          </div>
        </div>
        <div class="mt-4">
          <h3 class="text-3xl font-extrabold text-white tracking-tight">{{ cacheHitRate.toFixed(1) }}%</h3>
          <p class="text-xs text-emerald-400 font-medium mt-1">L1: {{ cacheL1 }} | L2: {{ cacheL2 }}</p>
        </div>
      </div>
    </div>

    <!-- Charts Section -->
    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
      <!-- Active User Trends (Line Chart) -->
      <div class="bg-[var(--bg-card)] border border-[var(--border-primary)] rounded-2xl p-6 shadow-xl">
        <h3 class="text-lg font-bold text-white mb-6 flex items-center gap-2">
          <i class="pi pi-chart-line text-indigo-400"></i>
          <span>{{ $t('dashboard.activeUserTrends') }}</span>
        </h3>
        <div class="w-full h-64 flex items-center justify-center relative">
          <svg viewBox="0 0 500 200" class="w-full h-full overflow-visible">
            <defs>
              <linearGradient id="lineGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="#6366f1" stop-opacity="0.4" />
                <stop offset="100%" stop-color="#6366f1" stop-opacity="0.0" />
              </linearGradient>
            </defs>
            <!-- Grid Lines -->
            <line x1="40" y1="20" x2="480" y2="20" stroke="#334155" stroke-dasharray="4" stroke-width="0.5" />
            <line x1="40" y1="70" x2="480" y2="70" stroke="#334155" stroke-dasharray="4" stroke-width="0.5" />
            <line x1="40" y1="120" x2="480" y2="120" stroke="#334155" stroke-dasharray="4" stroke-width="0.5" />
            <line x1="40" y1="170" x2="480" y2="170" stroke="#475569" stroke-width="1" />

            <!-- Line Path -->
            <path :d="trendLinePath" fill="none" stroke="#6366f1" stroke-width="3" stroke-linecap="round" />
            <!-- Area Path -->
            <path :d="trendAreaPath" fill="url(#lineGrad)" />

            <!-- X-Axis Labels -->
            <text v-for="(lbl, idx) in trendLabels" :key="idx" :x="trendX(idx)" y="190" fill="#94a3b8" font-size="10" text-anchor="middle">
              {{ lbl }}
            </text>
            <!-- Y-Axis Labels -->
            <text x="30" y="25" fill="#94a3b8" font-size="10" text-anchor="end">{{ maxUsers }}</text>
            <text x="30" y="95" fill="#94a3b8" font-size="10" text-anchor="end">{{ Math.floor(maxUsers/2) }}</text>
            <text x="30" y="173" fill="#94a3b8" font-size="10" text-anchor="end">0</text>
          </svg>
        </div>
      </div>

      <!-- Policy Latency Bar Chart -->
      <div class="bg-[var(--bg-card)] border border-[var(--border-primary)] rounded-2xl p-6 shadow-xl">
        <h3 class="text-lg font-bold text-white mb-6 flex items-center gap-2">
          <i class="pi pi-chart-bar text-amber-400"></i>
          <span>{{ $t('dashboard.policyLatency') }}</span>
        </h3>
        <div class="w-full h-64 flex items-center justify-center relative">
          <svg viewBox="0 0 500 200" class="w-full h-full overflow-visible">
            <!-- Grid Lines -->
            <line x1="40" y1="20" x2="480" y2="20" stroke="#334155" stroke-dasharray="4" stroke-width="0.5" />
            <line x1="40" y1="70" x2="480" y2="70" stroke="#334155" stroke-dasharray="4" stroke-width="0.5" />
            <line x1="40" y1="120" x2="480" y2="120" stroke="#334155" stroke-dasharray="4" stroke-width="0.5" />
            <line x1="40" y1="170" x2="480" y2="170" stroke="#475569" stroke-width="1" />

            <!-- Bars -->
            <g v-for="(p, idx) in latencyData" :key="idx">
              <rect 
                :x="barX(idx)" 
                :y="barY(p.latency)" 
                width="30" 
                :height="barHeight(p.latency)" 
                fill="#f59e0b" 
                rx="4" 
                class="hover:fill-amber-400 transition-colors"
              />
              <text :x="barX(idx) + 15" y="188" fill="#94a3b8" font-size="10" text-anchor="middle">
                {{ p.name }}
              </text>
              <text :x="barX(idx) + 15" :y="barY(p.latency) - 6" fill="#f59e0b" font-size="10" font-weight="bold" text-anchor="middle">
                {{ p.latency }}ms
              </text>
            </g>
          </svg>
        </div>
      </div>
    </div>

    <!-- Security Warnings Board -->
    <div class="bg-slate-950 border border-slate-800 rounded-2xl p-6 shadow-xl">
      <h3 class="text-lg font-bold text-white mb-6 flex items-center gap-2">
        <i class="pi pi-exclamation-triangle text-rose-500 animate-pulse"></i>
        <span>{{ $t('dashboard.securityWarnings') }}</span>
      </h3>
      <div v-if="alerts.length === 0" class="flex flex-col items-center justify-center py-10 border border-dashed border-[var(--border-primary)] rounded-xl bg-[var(--bg-elevated)]/50">
        <i class="pi pi-verified text-emerald-400 text-3xl mb-3"></i>
        <p class="text-[var(--text-secondary)] text-sm font-medium">{{ $t('dashboard.noWarnings') }}</p>
      </div>
      <div v-else class="space-y-4">
        <div v-for="(a, idx) in alerts" :key="idx" class="flex gap-4 p-4 border border-rose-900/30 rounded-xl" :class="a.severity === 'high' ? 'bg-rose-950/20' : 'bg-amber-950/10 border-amber-900/30'">
          <div class="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0" :class="a.severity === 'high' ? 'bg-rose-500/10 text-rose-400' : 'bg-amber-500/10 text-amber-400'">
            <i class="pi" :class="a.severity === 'high' ? 'pi-shield' : 'pi-clock'"></i>
          </div>
          <div>
            <h4 class="font-bold" :class="a.severity === 'high' ? 'text-rose-400' : 'text-amber-400'">
              {{ a.severity === 'high' ? 'Access Anomaly Alert' : 'System Performance Warning' }}
            </h4>
            <p class="text-[var(--text-secondary)] text-sm mt-1">{{ a.message }}</p>
            <span class="text-[10px] text-[var(--text-muted)] font-mono mt-2 block">{{ a.time }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';
import { useI18n } from 'vue-i18n';
import axios from 'axios';
import { auditService } from '../../services/api';

const { t } = useI18n();

// Metrics State
const totalEvals = ref(0);
const cacheL1 = ref(0);
const cacheL2 = ref(0);
const allowsCount = ref(0);
const denysCount = ref(0);
const totalDurationUs = ref(0);

// Computed stats
const interceptionRate = computed(() => {
  if (totalEvals.value === 0) return 0;
  return (denysCount.value / totalEvals.value) * 100;
});

const avgLatency = computed(() => {
  if (totalEvals.value === 0) return 0;
  return (totalDurationUs.value / totalEvals.value) / 1000; // microsecond to millisecond
});

const cacheHitRate = computed(() => {
  if (totalEvals.value === 0) return 0;
  return ((cacheL1.value + cacheL2.value) / totalEvals.value) * 100;
});

// Logs and warnings state
interface Alert {
  severity: 'high' | 'medium';
  message: string;
  time: string;
}
const alerts = ref<Alert[]>([]);

interface LatencyBar {
  name: string;
  latency: number;
}
const latencyData = ref<LatencyBar[]>([]);

// Active User Trend (mocked data based on actual logs timeline)
const activeUsersData = ref<number[]>([1, 2, 1, 3, 2, 4, 3]);
const trendLabels = ref<string[]>(['14:00', '15:00', '16:00', '17:00', '18:00', '19:00', '20:00']);

const maxUsers = computed(() => Math.max(...activeUsersData.value, 5));

const trendX = (idx: number) => {
  return 40 + (idx * (440 / (activeUsersData.value.length - 1)));
};

const trendY = (val: number) => {
  return 170 - (val * (150 / maxUsers.value));
};

const trendLinePath = computed(() => {
  return activeUsersData.value.map((val, idx) => {
    return `${idx === 0 ? 'M' : 'L'} ${trendX(idx)} ${trendY(val)}`;
  }).join(' ');
});

const trendAreaPath = computed(() => {
  if (activeUsersData.value.length === 0) return '';
  const firstX = trendX(0);
  const lastX = trendX(activeUsersData.value.length - 1);
  return `${trendLinePath.value} L ${lastX} 170 L ${firstX} 170 Z`;
});

// Bar chart calculations
const barX = (idx: number) => {
  return 60 + (idx * 110);
};

const barY = (latency: number) => {
  const maxScale = 5;
  const heightVal = (Math.min(latency, maxScale) / maxScale) * 150;
  return 170 - heightVal;
};

const barHeight = (latency: number) => {
  return 170 - barY(latency);
};

// Parse Prometheus text format metrics
const fetchMetrics = async () => {
  try {
    const { data } = await axios.get<string>('/metrics');
    const lines = data.split('\n');
    lines.forEach(line => {
      if (line.startsWith('#') || !line.trim()) return;
      const parts = line.split(/\s+/);
      if (parts.length < 2) return;
      const key = parts[0];
      const val = parseInt(parts[1], 10);

      if (key === 'sso_perm_evals_total') totalEvals.value = val;
      else if (key.startsWith('sso_perm_cache_hits_total{level="l1"}')) cacheL1.value = val;
      else if (key.startsWith('sso_perm_cache_hits_total{level="l2"}')) cacheL2.value = val;
      else if (key.startsWith('sso_perm_decisions_total{effect="allow"}')) allowsCount.value = val;
      else if (key.startsWith('sso_perm_decisions_total{effect="deny"}')) denysCount.value = val;
      else if (key === 'sso_perm_eval_duration_us_total') totalDurationUs.value = val;
    });
  } catch (err) {
    console.error('Failed to load metrics', err);
  }
};

const scanSecurityAlerts = async () => {
  try {
    const res = await auditService.listLogs();
    const rawLogs = res.items;

    const policyMap: Record<string, { totalTime: number, count: number }> = {};
    const ipDenyMap: Record<string, { denies: number, lastResource: string }> = {};

    rawLogs.forEach(log => {
      const rawObj = log as any;
      const duration = rawObj.duration_ms || 0;
      const decision = rawObj.decision || 'ALLOW';
      const ip = rawObj.ip_address || '127.0.0.1';
      const traceText = rawObj.trace || '';

      let strategy = 'ABAC';
      if (traceText.includes('abac')) strategy = 'ABAC';
      else if (traceText.includes('lbac')) strategy = 'LBAC';
      else if (traceText.includes('rbac')) strategy = 'RBAC';
      else if (traceText.includes('location')) strategy = 'Location';
      else if (traceText.includes('api')) strategy = 'API';
      else if (traceText.includes('functional')) strategy = 'Functional';
      else if (traceText.includes('data')) strategy = 'Data';

      if (!policyMap[strategy]) {
        policyMap[strategy] = { totalTime: 0, count: 0 };
      }
      policyMap[strategy].totalTime += duration;
      policyMap[strategy].count++;

      if (decision === 'DENY') {
        if (!ipDenyMap[ip]) {
          ipDenyMap[ip] = { denies: 0, lastResource: traceText || 'Resource' };
        }
        ipDenyMap[ip].denies++;
      }
    });

    const newAlerts: Alert[] = [];

    Object.keys(ipDenyMap).forEach(ip => {
      if (ipDenyMap[ip].denies >= 3) {
        newAlerts.push({
          severity: 'high',
          message: t('dashboard.anomalyWarning', { ip, resource: ipDenyMap[ip].lastResource.substring(0, 40) }),
          time: new Date().toLocaleTimeString()
        });
      }
    });

    const list: LatencyBar[] = [];
    Object.keys(policyMap).forEach(key => {
      const avg = policyMap[key].totalTime / policyMap[key].count;
      list.push({
        name: key,
        latency: parseFloat(avg.toFixed(2)) || 0.1
      });

      if (avg > 3) {
        newAlerts.push({
          severity: 'medium',
          message: t('dashboard.latencyWarning', { name: key, duration: avg.toFixed(1) }),
          time: new Date().toLocaleTimeString()
        });
      }
    });

    latencyData.value = list.slice(0, 4);
    if (latencyData.value.length === 0) {
      latencyData.value = [
        { name: 'ABAC', latency: 0.8 },
        { name: 'LBAC', latency: 0.3 },
        { name: 'RBAC', latency: 0.2 },
        { name: 'API', latency: 0.5 }
      ];
    }

    alerts.value = newAlerts;

    const uniqueUsersPerHour: Record<string, Set<string>> = {};
    rawLogs.forEach(log => {
      const rawObj = log as any;
      const ts = rawObj.timestamp_ms || Date.now();
      const hourStr = new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      const uid = String(rawObj.user_id || '1');
      if (!uniqueUsersPerHour[hourStr]) {
        uniqueUsersPerHour[hourStr] = new Set();
      }
      uniqueUsersPerHour[hourStr].add(uid);
    });

    const hours = Object.keys(uniqueUsersPerHour).sort();
    if (hours.length >= 3) {
      trendLabels.value = hours.slice(-7);
      activeUsersData.value = trendLabels.value.map(h => uniqueUsersPerHour[h].size);
    }
  } catch (err) {
    console.error('Failed to parse logs for warnings', err);
  }
};

onMounted(() => {
  fetchMetrics();
  scanSecurityAlerts();
});
</script>

<style scoped>
.animate-fade-in {
  animation: fadeIn 0.4s ease-out;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>
