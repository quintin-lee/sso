<template>
  <div class="bg-[var(--bg-card)] rounded-2xl border border-[var(--border-primary)] overflow-hidden">
    <DataTable :value="displayedRoles" paginator :rows="10" :loading="loading">
      <Column field="id" :header="$t('common.id')" class="w-20 font-mono text-xs"></Column>
      <Column field="name" :header="$t('common.name')" class="font-semibold"></Column>
      <Column field="description" :header="$t('common.description')"></Column>
      <Column field="status" :header="$t('common.status')">
        <template #body="slotProps">
          <span :class="statusBadgeClass(slotProps.data.status)">
            {{ slotProps.data.status === 1 ? $t('common.active') : $t('common.disabled') }}
          </span>
        </template>
      </Column>
      <Column :header="$t('common.actions')" class="w-32 text-right">
        <template #body="slotProps">
          <div class="flex gap-1 justify-end">
            <Button icon="pi pi-pencil" text rounded severity="secondary" @click="editRole(slotProps.data)" />
            <Button icon="pi pi-trash" text rounded severity="danger" @click="confirmDeleteRole(slotProps.data)" />
          </div>
        </template>
      </Column>
      <!-- Empty State -->
      <template #empty>
        <div class="flex flex-col items-center justify-center py-16 text-[var(--text-muted)]">
          <i class="pi pi-tags text-4xl mb-3 opacity-40"></i>
          <p class="text-sm font-medium">No roles found</p>
          <p class="text-xs mt-1 opacity-60">Click Add to create a new role</p>
        </div>
      </template>
    </DataTable>

    <Dialog v-model:visible="roleDialog" :header="role.id ? $t('roles.update') : $t('roles.create')" modal class="w-full max-w-lg">
       <div class="space-y-4">
         <div class="flex flex-col gap-1.5">
             <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('common.name') }}</label>
            <InputText v-model.trim="role.name" placeholder="admin" />
         </div>
         <div class="flex flex-col gap-1.5">
              <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('common.description') }}</label>
             <InputText v-model.trim="role.description" placeholder="Administrator role" />
          </div>
          <div class="flex items-center gap-2 pt-2">
            <Checkbox v-model="role.status" :binary="true" inputId="roleStatus" :trueValue="1" :falseValue="0" />
            <label for="roleStatus" class="text-sm font-semibold text-[var(--text-primary)] select-none">{{ $t('common.active') }}</label>
          </div>
        </div>
       <template #footer>
         <div class="flex gap-2 justify-end">
             <Button :label="$t('common.cancel')" text severity="secondary" @click="roleDialog = false" class="!rounded-lg !text-[var(--text-secondary)] hover:!text-[var(--text-primary)]" />
             <Button :label="$t('common.save')" @click="saveRole" class="!rounded-lg !px-6 !bg-[var(--accent-strong)] hover:!bg-[var(--accent)] !text-white !border-none" />
         </div>
       </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useI18n } from 'vue-i18n';
import { adminService, type Role } from '../../services/api';
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import Button from 'primevue/button';
import Dialog from 'primevue/dialog';
import InputText from 'primevue/inputtext';
import Checkbox from 'primevue/checkbox';
import { useToast } from 'primevue/usetoast';
import { useConfirm } from 'primevue/useconfirm';

const props = defineProps<{ search?: string }>();

const { t } = useI18n();
const toast = useToast();
const loading = ref(false);
const roles = ref<Role[]>([]);

const displayedRoles = computed(() => {
  const q = (props.search || '').toLowerCase().trim();
  if (!q) return roles.value;
  return roles.value.filter(r =>
    (r.name || '').toLowerCase().includes(q) ||
    (r.description || '').toLowerCase().includes(q)
  );
});
const roleDialog = ref(false);
const role = ref<Partial<Role>>({});

const statusBadgeClass = (status: number) => [
  'px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider',
  status === 1 ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400'
];

const loadRoles = async () => {
  loading.value = true;
  try {
    const res = await adminService.listRoles();
    roles.value = res.items;
  } catch (err) {
    toast.add({ severity: 'error', summary: t('common.error'), detail: 'Failed to load roles', life: 3000 });
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
      toast.add({ severity: 'success', summary: t('common.success'), detail: 'Role updated successfully', life: 3000 });
    } else {
      await adminService.createRole(role.value);
      toast.add({ severity: 'success', summary: t('common.success'), detail: 'Role created successfully', life: 3000 });
    }
    roleDialog.value = false;
    loadRoles();
  } catch (err) {
    toast.add({ severity: 'error', summary: t('common.error'), detail: 'Failed to save role', life: 3000 });
  }
};

const confirmDlg = useConfirm();

const confirmDeleteRole = (data: Role) => {
  confirmDlg.require({
    message: t('roles.deleteConfirm', { name: data.name }),
    header: t('common.confirmDelete'),
    icon: 'pi pi-exclamation-triangle',
    rejectLabel: t('common.cancel'),
    acceptLabel: t('common.delete'),
    rejectClass: 'p-button-text p-button-sm',
    acceptClass: 'p-button-danger p-button-sm',
    accept: async () => {
      try {
        await adminService.deleteRole(data.id);
        toast.add({ severity: 'success', summary: t('common.success'), detail: 'Role deleted successfully', life: 3000 });
        loadRoles();
      } catch (err) {
        toast.add({ severity: 'error', summary: t('common.error'), detail: 'Failed to delete role', life: 3000 });
      }
    }
  });
};

onMounted(() => {
  loadRoles();
});

defineExpose({
  openCreateDialog
});
</script>
