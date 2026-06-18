<template>
  <div class="bg-[var(--bg-card)] rounded-2xl border border-[var(--border-primary)] overflow-hidden">
    <DataTable :value="groups" paginator :rows="10" :loading="loading">
      <Column field="id" :header="$t('common.id')" class="w-20 font-mono text-xs"></Column>
      <Column field="name" :header="$t('common.name')" class="font-semibold"></Column>
      <Column field="description" :header="$t('common.description')"></Column>
      <Column :header="$t('common.actions')" class="w-32 text-right">
        <template #body="slotProps">
          <div class="flex gap-1 justify-end">
            <Button icon="pi pi-pencil" text rounded severity="secondary" @click="editGroup(slotProps.data)" />
            <Button icon="pi pi-trash" text rounded severity="danger" @click="confirmDeleteGroup(slotProps.data)" />
          </div>
        </template>
      </Column>
      <!-- Empty State -->
      <template #empty>
        <div class="flex flex-col items-center justify-center py-16 text-[var(--text-muted)]">
          <i class="pi pi-sitemap text-4xl mb-3 opacity-40"></i>
          <p class="text-sm font-medium">No groups found</p>
          <p class="text-xs mt-1 opacity-60">Click Add to create a new group</p>
        </div>
      </template>
    </DataTable>

    <Dialog v-model:visible="groupDialog" :header="group.id ? $t('groups.update') : $t('groups.create')" modal class="w-full max-w-lg">
       <div class="space-y-4">
         <div class="flex flex-col gap-1.5">
             <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('common.name') }}</label>
             <InputText v-model.trim="group.name" placeholder="Engineering" />
          </div>
          <div class="flex flex-col gap-1.5">
             <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('common.description') }}</label>
            <InputText v-model.trim="group.description" placeholder="Engineering department" />
         </div>
       </div>
       <template #footer>
         <div class="flex gap-2 justify-end">
             <Button :label="$t('common.cancel')" text severity="secondary" @click="groupDialog = false" class="!rounded-lg !text-[var(--text-secondary)] hover:!text-[var(--text-primary)]" />
             <Button :label="$t('common.save')" @click="saveGroup" class="!rounded-lg !px-6 !bg-[var(--accent-strong)] hover:!bg-[var(--accent)] !text-white !border-none" />
         </div>
       </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useI18n } from 'vue-i18n';
import { adminService, type Group } from '../../services/api';
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import Button from 'primevue/button';
import Dialog from 'primevue/dialog';
import InputText from 'primevue/inputtext';
import { useToast } from 'primevue/usetoast';

const { t } = useI18n();
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
    toast.add({ severity: 'error', summary: t('common.error'), detail: 'Failed to load groups', life: 3000 });
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
      toast.add({ severity: 'success', summary: t('common.success'), detail: 'Group updated successfully', life: 3000 });
    } else {
      await adminService.createGroup(group.value);
      toast.add({ severity: 'success', summary: t('common.success'), detail: 'Group created successfully', life: 3000 });
    }
    groupDialog.value = false;
    loadGroups();
  } catch (err) {
    toast.add({ severity: 'error', summary: t('common.error'), detail: 'Failed to save group', life: 3000 });
  }
};

const confirmDeleteGroup = async (data: Group) => {
  if (confirm(t('groups.deleteConfirm', { name: data.name }))) {
    try {
      await adminService.deleteGroup(data.id);
      toast.add({ severity: 'success', summary: t('common.success'), detail: 'Group deleted successfully', life: 3000 });
      loadGroups();
    } catch (err) {
      toast.add({ severity: 'error', summary: t('common.error'), detail: 'Failed to delete group', life: 3000 });
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
