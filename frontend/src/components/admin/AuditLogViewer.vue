<template>
  <div class="bg-[var(--bg-card)] rounded-2xl border border-[var(--border-primary)] overflow-hidden">
    <DataTable :value="displayedLogs" paginator :rows="20" :loading="loading">
      <!-- Time Column -->
      <Column field="timestamp_ms" :header="$t('auditLog.timestamp')" class="w-44">
        <template #body="slotProps">
          <span class="text-xs text-[var(--text-muted)] font-mono">
            {{ new Date(slotProps.data.timestamp_ms).toLocaleString() }}
          </span>
        </template>
      </Column>

      <!-- Actor Column -->
      <Column field="username" :header="$t('auditLog.actor')" class="w-28">
        <template #body="slotProps">
          <span v-if="slotProps.data.action === 'admin'" class="text-xs font-semibold text-[var(--text-primary)]">{{ slotProps.data.username || 'ID:'+slotProps.data.user_id }}</span>
          <span v-else class="text-xs font-mono text-[var(--text-secondary)]">ID: {{ slotProps.data.user_id }}</span>
        </template>
      </Column>

      <!-- Type / Operation Column -->
      <Column field="action" :header="$t('auditLog.type')" class="w-24">
        <template #body="slotProps">
          <span v-if="slotProps.data.action === 'admin'" class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-amber-500/10 text-amber-400">{{ $t('auditLog.adminBadge') }}</span>
          <span v-else class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-indigo-500/10 text-indigo-400">{{ $t('auditLog.checkBadge') }}</span>
        </template>
      </Column>

      <!-- Operation (admin) / Decision (check) Column -->
      <Column field="operation" :header="$t('auditLog.operation')" class="w-36">
        <template #body="slotProps">
          <template v-if="slotProps.data.action === 'admin'">
            <span class="text-xs font-semibold text-[var(--text-primary)]">{{ slotProps.data.operation }}</span>
            <span :class="slotProps.data.status === 'success' ? 'text-emerald-400' : 'text-rose-400'" class="text-[10px] ml-1">({{ slotProps.data.status }})</span>
          </template>
          <span v-else :class="slotProps.data.decision === 'ALLOW' ? 'text-emerald-400' : 'text-rose-400'" class="px-2.5 py-1 rounded-lg text-xs font-extrabold">
            {{ slotProps.data.decision }}
          </span>
        </template>
      </Column>

      <!-- Resource (admin) / Cache (check) Column -->
      <Column field="resource" :header="$t('auditLog.resource')" class="w-28">
        <template #body="slotProps">
          <span v-if="slotProps.data.action === 'admin'" class="text-xs text-[var(--text-secondary)]">
            {{ slotProps.data.resource }}<template v-if="slotProps.data.resource_id"> #{{ slotProps.data.resource_id }}</template>
          </span>
          <span v-else :class="slotProps.data.cache_hit ? 'text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded text-xs font-semibold' : 'text-[var(--text-muted)] bg-[var(--bg-elevated)] px-2 py-0.5 rounded text-xs font-semibold'">
            {{ slotProps.data.cache_hit ? $t('auditLog.cacheHit') : $t('auditLog.cacheMiss') }}
          </span>
        </template>
      </Column>

      <!-- Details / Trace Column -->
      <Column field="details" :header="$t('auditLog.details')" class="font-mono text-xs text-[var(--text-muted)] max-w-xs">
        <template #body="slotProps">
          <span v-if="slotProps.data.action === 'admin'" class="text-xs text-[var(--text-muted)] truncate block max-w-xs">{{ slotProps.data.details }}</span>
          <span v-else class="text-xs text-[var(--text-muted)] truncate block max-w-xs">{{ slotProps.data.trace }}</span>
        </template>
      </Column>

      <!-- IP Column (admin only) -->
      <Column field="ip_address" :header="$t('auditLog.ip')" class="w-28 hidden lg:table-cell">
        <template #body="slotProps">
          <span v-if="slotProps.data.ip_address" class="text-[10px] font-mono text-[var(--text-muted)]">{{ slotProps.data.ip_address }}</span>
        </template>
      </Column>

      <!-- Duration Column (check only) -->
      <Column field="duration_ms" :header="$t('auditLog.latency')" class="w-20">
        <template #body="slotProps">
          <span v-if="slotProps.data.action !== 'admin'" class="text-xs font-semibold font-mono text-[var(--text-secondary)]">
            {{ slotProps.data.duration_ms }} ms
          </span>
        </template>
      </Column>

      <!-- Empty State -->
      <template #empty>
        <div class="flex flex-col items-center justify-center py-16 text-[var(--text-muted)]">
          <i class="pi pi-history text-4xl mb-3 opacity-40"></i>
          <p class="text-sm font-medium">{{ $t('auditLog.emptyText') }}</p>
          <p class="text-xs mt-1 opacity-60">{{ $t('auditLog.emptyHint') }}</p>
        </div>
      </template>
    </DataTable>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useI18n } from 'vue-i18n';
import { auditService, type AuditLog } from '../../services/api';
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import { useToast } from 'primevue/usetoast';

const props = defineProps<{ search?: string }>();

const { t } = useI18n();
const toast = useToast();
const loading = ref(false);
const logs = ref<AuditLog[]>([]);

const displayedLogs = computed(() => {
  const q = (props.search || '').toLowerCase().trim();
  if (!q) return logs.value;
  return logs.value.filter(l =>
    String(l.user_id || '').includes(q) ||
    (l.username || '').toLowerCase().includes(q) ||
    (l.decision || '').toLowerCase().includes(q) ||
    (l.operation || '').toLowerCase().includes(q) ||
    (l.resource || '').toLowerCase().includes(q) ||
    (l.details || '').toLowerCase().includes(q) ||
    (l.trace || '').toLowerCase().includes(q) ||
    String(l.duration_ms || '').includes(q)
  );
});

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
