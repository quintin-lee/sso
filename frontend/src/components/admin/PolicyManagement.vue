<template>
  <div class="bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden">
    <DataTable :value="policies" paginator :rows="10" :loading="loading">
      <Column field="id" header="ID" class="w-20 font-mono text-xs"></Column>
      <Column field="name" header="Name" class="font-semibold"></Column>
      <Column field="strategy_name" header="Strategy">
        <template #body="slotProps">
          <span class="px-2 py-1 bg-indigo-50 text-indigo-600 text-xs font-bold rounded uppercase">
            {{ slotProps.data.strategy_name }}
          </span>
        </template>
      </Column>
      <Column field="effect" header="Effect">
        <template #body="slotProps">
          <span :class="slotProps.data.effect === 1 ? 'text-green-600 bg-green-50 px-2 py-1 rounded text-xs font-bold' : 'text-red-600 bg-red-50 px-2 py-1 rounded text-xs font-bold'">
            {{ slotProps.data.effect === 1 ? 'ALLOW' : 'DENY' }}
          </span>
        </template>
      </Column>
      <Column header="Actions" class="w-32 text-right">
        <template #body="slotProps">
          <div class="flex gap-1 justify-end">
            <Button icon="pi pi-pencil" text rounded severity="secondary" @click="editPolicy(slotProps.data)" />
            <Button icon="pi pi-trash" text rounded severity="danger" @click="confirmDeletePolicy(slotProps.data)" />
          </div>
        </template>
      </Column>
    </DataTable>

    <Dialog v-model:visible="policyDialog" header="Policy Details" modal class="w-full max-w-lg">
       <div class="space-y-4 py-4">
         <div class="flex flex-col gap-2">
            <label class="text-sm font-bold text-gray-700">Name</label>
            <InputText v-model.trim="policy.name" class="rounded-xl border-gray-200" placeholder="Allow Dashboard" />
         </div>
         <div class="flex flex-col gap-2">
            <label class="text-sm font-bold text-gray-700">Rules (JSON)</label>
            <textarea v-model.trim="policy.rules" class="w-full h-32 rounded-xl border-gray-200 p-3 font-mono text-sm" placeholder='{"action": "read", "resource": "dashboard"}'></textarea>
         </div>
       </div>
       <template #footer>
          <div class="flex gap-2 justify-end pt-4">
            <Button label="Cancel" text severity="secondary" @click="policyDialog = false" />
            <Button label="Save" @click="savePolicy" class="p-button-primary rounded-xl px-6" />
          </div>
       </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { adminService, type Policy } from '../../services/api';
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import Button from 'primevue/button';
import Dialog from 'primevue/dialog';
import InputText from 'primevue/inputtext';
import { useToast } from 'primevue/usetoast';

const toast = useToast();
const loading = ref(false);
const policies = ref<Policy[]>([]);
const policyDialog = ref(false);
const policy = ref<Partial<Policy>>({});

const loadPolicies = async () => {
  loading.value = true;
  try {
    const res = await adminService.listPolicies();
    policies.value = res.items;
  } catch (err) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to load policies', life: 3000 });
  } finally {
    loading.value = false;
  }
};

const openCreateDialog = () => {
  policy.value = { status: 1, rules: '{}' };
  policyDialog.value = true;
};

const editPolicy = (data: Policy) => {
  policy.value = { ...data };
  policyDialog.value = true;
};

const savePolicy = async () => {
  try {
    if (policy.value.id) {
      await adminService.updatePolicy(policy.value.id, policy.value);
      toast.add({ severity: 'success', summary: 'Success', detail: 'Policy updated successfully', life: 3000 });
    } else {
      await adminService.createPolicy(policy.value);
      toast.add({ severity: 'success', summary: 'Success', detail: 'Policy created successfully', life: 3000 });
    }
    policyDialog.value = false;
    loadPolicies();
  } catch (err) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to save policy', life: 3000 });
  }
};

const confirmDeletePolicy = async (data: Policy) => {
  if (confirm(`Delete policy ${data.name}?`)) {
    try {
      await adminService.deletePolicy(data.id);
      toast.add({ severity: 'success', summary: 'Success', detail: 'Policy deleted successfully', life: 3000 });
      loadPolicies();
    } catch (err) {
      toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to delete policy', life: 3000 });
    }
  }
};

onMounted(() => {
  loadPolicies();
});

defineExpose({
  openCreateDialog
});
</script>
