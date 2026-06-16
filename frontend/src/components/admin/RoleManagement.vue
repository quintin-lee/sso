<template>
  <div class="bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden">
    <DataTable :value="roles" paginator :rows="10" :loading="loading">
      <Column field="id" header="ID" class="w-20 font-mono text-xs"></Column>
      <Column field="name" header="Name" class="font-semibold"></Column>
      <Column field="description" header="Description"></Column>
      <Column field="status" header="Status">
        <template #body="slotProps">
          <span :class="statusBadgeClass(slotProps.data.status)">
            {{ slotProps.data.status === 1 ? 'Active' : 'Disabled' }}
          </span>
        </template>
      </Column>
      <Column header="Actions" class="w-32 text-right">
        <template #body="slotProps">
          <div class="flex gap-1 justify-end">
            <Button icon="pi pi-pencil" text rounded severity="secondary" @click="editRole(slotProps.data)" />
            <Button icon="pi pi-trash" text rounded severity="danger" @click="confirmDeleteRole(slotProps.data)" />
          </div>
        </template>
      </Column>
    </DataTable>

    <Dialog v-model:visible="roleDialog" header="Role Details" modal class="w-full max-w-lg">
       <div class="space-y-4 py-4">
         <div class="flex flex-col gap-2">
            <label class="text-sm font-bold text-gray-700">Name</label>
            <InputText v-model.trim="role.name" class="rounded-xl border-gray-200" placeholder="admin" />
         </div>
         <div class="flex flex-col gap-2">
            <label class="text-sm font-bold text-gray-700">Description</label>
            <InputText v-model.trim="role.description" class="rounded-xl border-gray-200" placeholder="Administrator role" />
         </div>
       </div>
       <template #footer>
          <div class="flex gap-2 justify-end pt-4">
            <Button label="Cancel" text severity="secondary" @click="roleDialog = false" />
            <Button label="Save" @click="saveRole" class="p-button-primary rounded-xl px-6" />
          </div>
       </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { adminService, type Role } from '../../services/api';
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import Button from 'primevue/button';
import Dialog from 'primevue/dialog';
import InputText from 'primevue/inputtext';
import { useToast } from 'primevue/usetoast';

const toast = useToast();
const loading = ref(false);
const roles = ref<Role[]>([]);
const roleDialog = ref(false);
const role = ref<Partial<Role>>({});

const statusBadgeClass = (status: number) => [
  'px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider',
  status === 1 ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
];

const loadRoles = async () => {
  loading.value = true;
  try {
    const res = await adminService.listRoles();
    roles.value = res.items;
  } catch (err) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to load roles', life: 3000 });
  } finally {
    loading.value = false;
  }
};

const openCreateDialog = () => {
  role.value = { status: 1 };
  roleDialog.value = true;
};

const editRole = (data: Role) => {
  role.value = { ...data };
  roleDialog.value = true;
};

const saveRole = async () => {
  try {
    if (role.value.id) {
      await adminService.updateRole(role.value.id, role.value);
      toast.add({ severity: 'success', summary: 'Success', detail: 'Role updated successfully', life: 3000 });
    } else {
      await adminService.createRole(role.value);
      toast.add({ severity: 'success', summary: 'Success', detail: 'Role created successfully', life: 3000 });
    }
    roleDialog.value = false;
    loadRoles();
  } catch (err) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to save role', life: 3000 });
  }
};

const confirmDeleteRole = async (data: Role) => {
  if (confirm(`Delete role ${data.name}?`)) {
    try {
      await adminService.deleteRole(data.id);
      toast.add({ severity: 'success', summary: 'Success', detail: 'Role deleted successfully', life: 3000 });
      loadRoles();
    } catch (err) {
      toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to delete role', life: 3000 });
    }
  }
};

onMounted(() => {
  loadRoles();
});

defineExpose({
  openCreateDialog
});
</script>
