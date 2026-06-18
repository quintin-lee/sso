<template>
  <div class="bg-[var(--bg-card)] rounded-2xl border border-[var(--border-primary)] overflow-hidden">
    <DataTable :value="displayedUsers" paginator :rows="10" :totalRecords="totalUsers" lazy @page="onUserPage" :loading="loading" class="p-datatable-sm">
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
            {{ new Date(slotProps.data.created_at).toLocaleString() }}
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
      <!-- Empty State -->
      <template #empty>
        <div class="flex flex-col items-center justify-center py-16 text-[var(--text-muted)]">
          <i class="pi pi-users text-4xl mb-3 opacity-40"></i>
          <p class="text-sm font-medium">{{ $t('common.noData') || 'No users found' }}</p>
          <p class="text-xs mt-1 opacity-60">{{ $t('common.addNewHint') || 'Click Add to create a new user' }}</p>
        </div>
      </template>
    </DataTable>

    <Dialog v-model:visible="userDialog" :header="user.id ? $t('users.update') : $t('users.create')" modal class="w-full max-w-lg">
       <div class="space-y-4">
         <div class="flex flex-col gap-1.5">
             <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('users.username') }}</label>
             <InputText v-model.trim="user.username" placeholder="johndoe" autofocus />
          </div>
          <div class="flex flex-col gap-1.5">
             <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('users.displayName') }}</label>
             <InputText v-model.trim="user.display_name" placeholder="John Doe" />
          </div>
          <div class="flex flex-col gap-1.5">
             <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('users.email') }}</label>
             <InputText v-model.trim="user.email" placeholder="john@example.com" />
          </div>
         <div v-if="!user.id" class="flex flex-col gap-1.5">
             <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('login.password') }}</label>
             <Password v-model="user.password" :feedback="false" placeholder="••••••••" toggleMask class="w-full" inputClass="w-full !bg-[var(--bg-elevated)] !border-[var(--border-primary)] !text-[var(--text-primary)] !placeholder-[var(--text-muted)] !rounded-lg !px-4 !py-3 hover:!border-[var(--accent)] transition-all" required />
         </div>
         <div class="flex flex-col gap-1.5" v-if="user.id">
             <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('users.roles') }}</label>
             <MultiSelect v-model="selectedRoles" :options="roleOptions" optionLabel="name" optionValue="id" :loading="rolesLoading" filter class="w-full" :maxSelectedLabels="3" />
         </div>
          <div class="flex flex-col gap-1.5" v-if="user.id">
              <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('users.groups') }}</label>
              <MultiSelect v-model="selectedGroups" :options="groupOptions" optionLabel="name" optionValue="id" :loading="groupsLoading" filter class="w-full" :maxSelectedLabels="3" />
          </div>
          <div class="flex flex-col gap-1.5" v-if="user.id">
              <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('users.policies') }}</label>
              <MultiSelect v-model="selectedPolicies" :options="policyOptions" optionLabel="name" optionValue="id" :loading="policiesLoading" filter class="w-full" :maxSelectedLabels="3" />
          </div>
         <div class="flex items-center gap-2 mt-4">
             <Checkbox v-model="userStatus" :binary="true" inputId="userStatus" />
             <label for="userStatus" class="text-sm font-semibold text-[var(--text-primary)]">{{ $t('common.active') }}</label>
         </div>
       </div>
        <template #footer>
           <div class="flex gap-2 justify-end">
              <Button :label="$t('common.cancel')" text severity="secondary" @click="userDialog = false" class="!rounded-lg !text-[var(--text-secondary)] hover:!text-[var(--text-primary)]" />
              <Button :label="$t('common.save')" @click="saveUser" class="!rounded-lg !px-6 !bg-[var(--accent-strong)] hover:!bg-[var(--accent)] !text-white !border-none" />
           </div>
        </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';
import { useI18n } from 'vue-i18n';
import { adminService, type User, type Role, type Group, type Policy } from '../../services/api';
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import Button from 'primevue/button';
import Dialog from 'primevue/dialog';
import InputText from 'primevue/inputtext';
import Password from 'primevue/password';
import Checkbox from 'primevue/checkbox';
import MultiSelect from 'primevue/multiselect';
import { useToast } from 'primevue/usetoast';
import { useConfirm } from 'primevue/useconfirm';

const props = defineProps<{ search?: string }>();

const { t, locale } = useI18n();
const toast = useToast();
const loading = ref(false);
const users = ref<User[]>([]);
const totalUsers = ref(0);

const displayedUsers = computed(() => {
  const q = (props.search || '').toLowerCase().trim();
  if (!q) return users.value;
  return users.value.filter(u =>
    (u.username || '').toLowerCase().includes(q) ||
    (u.display_name || '').toLowerCase().includes(q) ||
    (u.email || '').toLowerCase().includes(q)
  );
});
const userDialog = ref(false);
const user = ref<Partial<User>>({});
const selectedRoles = ref<number[]>([]);
const selectedGroups = ref<number[]>([]);
const selectedPolicies = ref<number[]>([]);
const roleOptions = ref<Role[]>([]);
const groupOptions = ref<Group[]>([]);
const policyOptions = ref<Policy[]>([]);
const rolesLoading = ref(false);
const groupsLoading = ref(false);
const policiesLoading = ref(false);

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

const loadRoleGroupOptions = async () => {
  if (roleOptions.value.length === 0) {
    rolesLoading.value = true;
    try {
      const res = await adminService.listRoles(1, 200);
      roleOptions.value = res.items;
    } catch (_) { /* ignore */ }
    rolesLoading.value = false;
  }
  if (groupOptions.value.length === 0) {
    groupsLoading.value = true;
    try {
      const res = await adminService.listGroups(1, 200);
      groupOptions.value = res.items;
    } catch (_) { /* ignore */ }
    groupsLoading.value = false;
  }
  if (policyOptions.value.length === 0) {
    policiesLoading.value = true;
    try {
      const res = await adminService.listPolicies(1, 200);
      policyOptions.value = res.items;
    } catch (_) { /* ignore */ }
    policiesLoading.value = false;
  }
};

const openCreateDialog = () => {
  user.value = { status: 1 };
  selectedRoles.value = [];
  selectedGroups.value = [];
  selectedPolicies.value = [];
  loadRoleGroupOptions();
  userDialog.value = true;
};

const editUser = async (data: User) => {
  user.value = { ...data };
  selectedRoles.value = (data.roles || []).map(r => r.id);
  selectedGroups.value = (data.groups || []).map(g => g.id);
  selectedPolicies.value = [];
  loadRoleGroupOptions();
  // Load directly-assigned policies for this user
  try {
    const policies = await adminService.getUserPolicies(data.id);
    selectedPolicies.value = policies.map(p => p.id);
  } catch { /* not critical */ }
  userDialog.value = true;
};

const saveUser = async () => {
  // Client-side validations
  if (!user.value.username || user.value.username.trim().length < 3) {
    toast.add({
      severity: 'error',
      summary: t('common.error'),
      detail: locale.value === 'zh' ? '用户名至少需要3个字符' : 'Username must be at least 3 characters long',
      life: 3000
    });
    return;
  }

  if (user.value.email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(user.value.email)) {
      toast.add({
        severity: 'error',
        summary: t('common.error'),
        detail: locale.value === 'zh' ? '电子邮箱格式不正确' : 'Invalid email address format',
        life: 3000
      });
      return;
    }
  }

  if (!user.value.id) {
    if (!user.value.password || user.value.password.length < 6) {
      toast.add({
        severity: 'error',
        summary: t('common.error'),
        detail: locale.value === 'zh' ? '密码长度至少为6位' : 'Password must be at least 6 characters long',
        life: 3000
      });
      return;
    }
  }

  try {
    if (user.value.id) {
      await adminService.updateUser(user.value.id, user.value);

      // Sync role assignments
      const oldRoleIds = (user.value.roles || []).map(r => r.id);
      const newRoleIds = selectedRoles.value;
      const toAdd = newRoleIds.filter(id => !oldRoleIds.includes(id));
      const toRemove = oldRoleIds.filter(id => !newRoleIds.includes(id));
      await Promise.all(toAdd.map(id => adminService.assignRole(id, user.value.id!)));
      await Promise.all(toRemove.map(id => adminService.unassignRole(id, user.value.id!)));

      // Sync group memberships
      const oldGroupIds = (user.value.groups || []).map(g => g.id);
      const newGroupIds = selectedGroups.value;
      const toAddG = newGroupIds.filter(id => !oldGroupIds.includes(id));
      const toRemoveG = oldGroupIds.filter(id => !newGroupIds.includes(id));
      await Promise.all(toAddG.map(id => adminService.addGroupMember(id, user.value.id!)));
      await Promise.all(toRemoveG.map(id => adminService.removeGroupMember(id, user.value.id!)));

      // Assign selected policies
      for (const pid of selectedPolicies.value) {
        try {
          await adminService.assignPolicy(pid, 0, user.value.id!);
        } catch { /* skip duplicates */ }
      }

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

const confirm = useConfirm();

const confirmDeleteUser = (data: User) => {
  confirm.require({
    message: t('users.deleteConfirm', { name: data.username }),
    header: t('common.confirmDelete'),
    icon: 'pi pi-exclamation-triangle',
    rejectLabel: t('common.cancel'),
    acceptLabel: t('common.delete'),
    rejectClass: 'p-button-text p-button-sm',
    acceptClass: 'p-button-danger p-button-sm',
    accept: async () => {
      try {
        await adminService.deleteUser(data.id);
        toast.add({ severity: 'success', summary: t('common.success'), detail: 'User deleted successfully', life: 3000 });
        loadUsers();
      } catch (err) {
        toast.add({ severity: 'error', summary: t('common.error'), detail: 'Failed to delete user', life: 3000 });
      }
    }
  });
};

onMounted(() => {
  loadUsers();
});

defineExpose({
  openCreateDialog
});
</script>
