<template>
  <div class="bg-[var(--bg-card)] rounded-2xl border border-[var(--border-primary)] overflow-hidden">
    <DataTable :value="users" paginator :rows="10" :totalRecords="totalUsers" lazy @page="onUserPage" :loading="loading" class="p-datatable-sm">
      <Column field="id" :header="$t('common.id')" class="w-20 font-mono text-xs"></Column>
      <Column field="username" :header="$t('users.username')" class="font-semibold">
        <template #body="slotProps">
          <div class="flex items-center gap-3">
            <div class="w-8 h-8 rounded-lg bg-indigo-500/10 flex items-center justify-center text-xs font-bold text-indigo-400">
              {{ slotProps.data.username[0].toUpperCase() }}
            </div>
            <div>
              <div class="text-[var(--text-primary)]">{{ slotProps.data.username }}</div>
              <div class="text-xs text-[var(--text-muted)]">{{ slotProps.data.email }}</div>
            </div>
          </div>
        </template>
      </Column>
      <Column field="display_name" :header="$t('users.displayName')"></Column>
      <Column field="status" :header="$t('common.status')">
        <template #body="slotProps">
          <span :class="statusBadgeClass(slotProps.data.status)">
            {{ slotProps.data.status === 1 ? $t('common.active') : $t('common.disabled') }}
          </span>
        </template>
      </Column>
      <Column field="created_at" :header="$t('common.created')">
        <template #body="slotProps">
          <span class="text-[var(--text-muted)] text-sm">
            {{ new Date(slotProps.data.created_at * 1000).toLocaleDateString() }}
          </span>
        </template>
      </Column>
      <Column :header="$t('common.actions')" class="w-32">
        <template #body="slotProps">
          <div class="flex gap-1 justify-end">
            <Button icon="pi pi-pencil" text rounded severity="secondary" @click="editUser(slotProps.data)" />
            <Button icon="pi pi-trash" text rounded severity="danger" @click="confirmDeleteUser(slotProps.data)" />
          </div>
        </template>
      </Column>
    </DataTable>

    <Dialog v-model:visible="userDialog" :header="user.id ? $t('users.update') : $t('users.create')" modal class="w-full max-w-lg">
       <div class="space-y-4">
         <div class="flex flex-col gap-1.5">
            <label class="text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider">{{ $t('users.username') }}</label>
            <InputText v-model.trim="user.username" placeholder="johndoe" autofocus />
         </div>
         <div class="flex flex-col gap-1.5">
            <label class="text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider">{{ $t('users.displayName') }}</label>
            <InputText v-model.trim="user.display_name" placeholder="John Doe" />
         </div>
         <div class="flex flex-col gap-1.5">
            <label class="text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider">{{ $t('users.email') }}</label>
            <InputText v-model.trim="user.email" placeholder="john@example.com" />
         </div>
         <div class="flex items-center gap-2 mt-4">
            <Checkbox v-model="userStatus" :binary="true" inputId="userStatus" />
            <label for="userStatus" class="text-sm font-semibold text-[var(--text-primary)]">{{ $t('common.active') }}</label>
         </div>
       </div>
        <template #footer>
           <div class="flex gap-2 justify-end">
             <Button :label="$t('common.cancel')" text severity="secondary" @click="userDialog = false" class="!rounded-xl !text-[var(--text-muted)] hover:!text-[var(--text-primary)]" />
             <Button :label="$t('common.save')" @click="saveUser" class="!rounded-xl !px-6 !bg-indigo-500 hover:!bg-indigo-400 !text-white !border-none" />
           </div>
        </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';
import { useI18n } from 'vue-i18n';
import { adminService, type User } from '../../services/api';
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import Button from 'primevue/button';
import Dialog from 'primevue/dialog';
import InputText from 'primevue/inputtext';
import Checkbox from 'primevue/checkbox';
import { useToast } from 'primevue/usetoast';

const { t } = useI18n();
const toast = useToast();
const loading = ref(false);
const users = ref<User[]>([]);
const totalUsers = ref(0);
const userDialog = ref(false);
const user = ref<Partial<User>>({});

const userStatus = computed({
  get: () => user.value.status === 1,
  set: (val) => user.value.status = val ? 1 : 0
});

const statusBadgeClass = (status: number) => [
  'px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider',
  status === 1 ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400'
];

const loadUsers = async (page = 1) => {
  loading.value = true;
  try {
    const res = await adminService.listUsers(page);
    users.value = res.items;
    totalUsers.value = res.total;
  } catch (err) {
    toast.add({ severity: 'error', summary: t('common.error'), detail: 'Failed to load users', life: 3000 });
  } finally {
    loading.value = false;
  }
};

const onUserPage = (event: any) => {
  loadUsers(event.page + 1);
};

const openCreateDialog = () => {
  user.value = { status: 1 };
  userDialog.value = true;
};

const editUser = (data: User) => {
  user.value = { ...data };
  userDialog.value = true;
};

const saveUser = async () => {
  try {
    if (user.value.id) {
      await adminService.updateUser(user.value.id, user.value);
      toast.add({ severity: 'success', summary: t('common.success'), detail: 'User updated successfully', life: 3000 });
    } else {
      await adminService.createUser(user.value);
      toast.add({ severity: 'success', summary: t('common.success'), detail: 'User created successfully', life: 3000 });
    }
    userDialog.value = false;
    loadUsers();
  } catch (err) {
    toast.add({ severity: 'error', summary: t('common.error'), detail: 'Failed to save user', life: 3000 });
  }
};

const confirmDeleteUser = async (data: User) => {
  if (confirm(t('users.deleteConfirm', { name: data.username }))) {
    try {
      await adminService.deleteUser(data.id);
      toast.add({ severity: 'success', summary: t('common.success'), detail: 'User deleted successfully', life: 3000 });
      loadUsers();
    } catch (err) {
      toast.add({ severity: 'error', summary: t('common.error'), detail: 'Failed to delete user', life: 3000 });
    }
  }
};

onMounted(() => {
  loadUsers();
});

defineExpose({
  openCreateDialog
});
</script>
