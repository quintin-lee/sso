<template>
  <div class="bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden">
    <DataTable :value="logs" paginator :rows="20" :loading="loading">
      <!-- Time Column -->
      <Column field="timestamp_ms" :header="$t('sidebar.logs')" class="w-48">
        <template #body="slotProps">
          <span class="text-xs text-slate-500 font-mono">
            {{ new Date(slotProps.data.timestamp_ms).toLocaleString() }}
          </span>
        </template>
      </Column>

      <!-- User ID Column -->
      <Column field="user_id" :header="$t('users.username')" class="w-24 font-mono text-xs text-slate-700">
        <template #body="slotProps">
          <span>ID: {{ slotProps.data.user_id }}</span>
        </template>
      </Column>

      <!-- Decision Column -->
      <Column field="decision" :header="$t('policies.effect')" class="w-32">
        <template #body="slotProps">
          <span :class="slotProps.data.decision === 'ALLOW' ? 'text-green-600 bg-green-50 px-2.5 py-1 rounded-lg text-xs font-extrabold' : 'text-red-600 bg-red-50 px-2.5 py-1 rounded-lg text-xs font-extrabold'">
            {{ slotProps.data.decision }}
          </span>
        </template>
      </Column>

      <!-- Cache Hit Column -->
      <Column field="cache_hit" :header="$t('dashboard.cacheHitRate')" class="w-32">
        <template #body="slotProps">
          <span :class="slotProps.data.cache_hit ? 'text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded text-xs font-semibold' : 'text-slate-500 bg-slate-50 px-2 py-0.5 rounded text-xs font-semibold'">
            {{ slotProps.data.cache_hit ? 'HIT' : 'MISS' }}
          </span>
        </template>
      </Column>

      <!-- Duration Column -->
      <Column field="duration_ms" :header="$t('dashboard.avgLatency')" class="w-32">
        <template #body="slotProps">
          <span class="text-xs font-semibold font-mono text-slate-600">
            {{ slotProps.data.duration_ms }} ms
          </span>
        </template>
      </Column>

      <!-- Trace/Details Column -->
      <Column field="trace" :header="$t('policies.rules')" class="font-mono text-xs text-slate-400 truncate max-w-xs"></Column>
    </DataTable>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useI18n } from 'vue-i18n';
import { auditService, type AuditLog } from '../../services/api';
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import { useToast } from 'primevue/usetoast';

const { t } = useI18n();
const toast = useToast();
const loading = ref(false);
const logs = ref<AuditLog[]>([]);

const loadLogs = async () => {
  loading.value = true;
  try {
    const res = await auditService.listLogs();
    // Audit logs from server are parsed from JSON Lines, already matching actual schema
    logs.value = res.items;
  } catch (err) {
    toast.add({ severity: 'error', summary: t('common.error'), detail: 'Failed to load audit logs', life: 3000 });
  } finally {
    loading.value = false;
  }
};

onMounted(() => {
  loadLogs();
});
</script>
