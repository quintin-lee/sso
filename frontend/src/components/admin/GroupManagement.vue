<template>
  <div class="bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden">
    <DataTable :value="groups" paginator :rows="10" :loading="loading">
      <Column field="id" header="ID" class="w-20 font-mono text-xs"></Column>
      <Column field="name" header="Name" class="font-semibold"></Column>
      <Column field="description" header="Description"></Column>
      <Column header="Actions" class="w-32 text-right">
        <template #body="slotProps">
          <div class="flex gap-1 justify-end">
            <Button icon="pi pi-pencil" text rounded severity="secondary" @click="editGroup(slotProps.data)" />
            <Button icon="pi pi-trash" text rounded severity="danger" @click="confirmDeleteGroup(slotProps.data)" />
          </div>
        </template>
      </Column>
    </DataTable>

    <Dialog v-model:visible="groupDialog" header="Group Details" modal class="w-full max-w-lg">
       <div class="space-y-4 py-4">
         <div class="flex flex-col gap-2">
            <label class="text-sm font-bold text-gray-700">Name</label>
            <InputText v-model.trim="group.name" class="rounded-xl border-gray-200" placeholder="Engineering" />
         </div>
         <div class="flex flex-col gap-2">
            <label class="text-sm font-bold text-gray-700">Description</label>
            <InputText v-model.trim="group.description" class="rounded-xl border-gray-200" placeholder="Engineering department" />
         </div>
       </div>
       <template #footer>
          <div class="flex gap-2 justify-end pt-4">
            <Button label="Cancel" text severity="secondary" @click="groupDialog = false" />
            <Button label="Save" @click="saveGroup" class="p-button-primary rounded-xl px-6" />
          </div>
       </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, defineExpose } from 'vue';
import { adminService, type Group } from '../../services/api';
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import Button from 'primevue/button';
import Dialog from 'primevue/dialog';
import InputText from 'primevue/inputtext';
import { useToast } from 'primevue/usetoast';

const toast = useToast();
const loading = ref(false);
const groups = ref<Group[]>([]);
const groupDialog = ref(false);
const group = ref<Partial<Group>>({});

const loadGroups = async () => {
  loading.value = true;
  try {
    const res = await adminService.listGroups();
    groups.value = res.items;
  } catch (err) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to load groups', life: 3000 });
  } finally {
    loading.value = false;
  }
};

const openCreateDialog = () => {
  group.value = { status: 1 };
  groupDialog.value = true;
};

const editGroup = (data: Group) => {
  group.value = { ...data };
  groupDialog.value = true;
};

const saveGroup = async () => {
  try {
    if (group.value.id) {
      await adminService.updateGroup(group.value.id, group.value);
      toast.add({ severity: 'success', summary: 'Success', detail: 'Group updated successfully', life: 3000 });
    } else {
      await adminService.createGroup(group.value);
      toast.add({ severity: 'success', summary: 'Success', detail: 'Group created successfully', life: 3000 });
    }
    groupDialog.value = false;
    loadGroups();
  } catch (err) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to save group', life: 3000 });
  }
};

const confirmDeleteGroup = async (data: Group) => {
  if (confirm(`Delete group ${data.name}?`)) {
    try {
      await adminService.deleteGroup(data.id);
      toast.add({ severity: 'success', summary: 'Success', detail: 'Group deleted successfully', life: 3000 });
      loadGroups();
    } catch (err) {
      toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to delete group', life: 3000 });
    }
  }
};

onMounted(() => {
  loadGroups();
});

defineExpose({
  openCreateDialog
});
</script>
