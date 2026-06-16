<template>
  <div class="bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden">
    <DataTable :value="logs" paginator :rows="20" :loading="loading">
      <Column field="timestamp" header="Time" class="w-48">
        <template #body="slotProps">
          <span class="text-xs text-gray-500 font-mono">
            {{ new Date(slotProps.data.timestamp * 1000).toLocaleString() }}
          </span>
        </template>
      </Column>
      <Column field="username" header="User" class="font-medium"></Column>
      <Column field="action" header="Action">
        <template #body="slotProps">
          <span class="text-sm font-semibold">{{ slotProps.data.action }}</span>
        </template>
      </Column>
      <Column field="resource" header="Resource" class="font-mono text-xs text-gray-400"></Column>
      <Column field="status" header="Status">
        <template #body="slotProps">
          <span :class="slotProps.data.status === 'success' ? 'text-green-600' : 'text-red-600'">
            {{ slotProps.data.status }}
          </span>
        </template>
      </Column>
    </DataTable>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { auditService, type AuditLog } from '../../services/api';
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import { useToast } from 'primevue/usetoast';

const toast = useToast();
const loading = ref(false);
const logs = ref<AuditLog[]>([]);

const loadLogs = async () => {
  loading.value = true;
  try {
    const res = await auditService.listLogs();
    logs.value = res.items;
  } catch (err) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to load audit logs', life: 3000 });
  } finally {
    loading.value = false;
  }
};

onMounted(() => {
  loadLogs();
});
</script>
