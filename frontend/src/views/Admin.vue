<template>
  <div class="admin-layout flex h-screen bg-gray-50 font-sans">
    <!-- Sidebar -->
    <aside class="w-72 bg-white border-r border-gray-200 flex flex-col shadow-sm">
      <div class="p-8 flex items-center gap-3 border-b border-gray-100">
        <div class="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center shadow-lg shadow-indigo-100">
          <i class="pi pi-shield text-white text-xl"></i>
        </div>
        <div>
          <h2 class="text-lg font-bold text-gray-900 leading-none">SSO Admin</h2>
          <span class="text-xs text-gray-500 font-medium">Control Center</span>
        </div>
      </div>
      
      <nav class="flex-grow py-6 px-4 space-y-1">
        <div class="px-4 mb-2 text-xs font-semibold text-gray-400 uppercase tracking-wider">Management</div>
        <button @click="currentTab = 'users'" :class="tabClass('users')">
          <i class="pi pi-users text-lg"></i>
          <span>Users</span>
        </button>
        <button @click="currentTab = 'roles'" :class="tabClass('roles')">
          <i class="pi pi-tags text-lg"></i>
          <span>Roles</span>
        </button>
        <button @click="currentTab = 'groups'" :class="tabClass('groups')">
          <i class="pi pi-sitemap text-lg"></i>
          <span>Groups</span>
        </button>
        
        <div class="px-4 mt-8 mb-2 text-xs font-semibold text-gray-400 uppercase tracking-wider">Security</div>
        <button @click="currentTab = 'policies'" :class="tabClass('policies')">
          <i class="pi pi-lock text-lg"></i>
          <span>Policies</span>
        </button>
        <button @click="currentTab = 'logs'" :class="tabClass('logs')">
          <i class="pi pi-history text-lg"></i>
          <span>Audit Logs</span>
        </button>
      </nav>

      <div class="p-6 border-t border-gray-100 mt-auto">
        <div class="flex items-center gap-3 mb-6 px-2">
          <div class="w-8 h-8 rounded-full bg-gray-100 flex items-center justify-center text-sm font-bold text-gray-600">
            A
          </div>
          <div class="overflow-hidden">
            <p class="text-sm font-semibold text-gray-900 truncate">Administrator</p>
            <p class="text-xs text-gray-500 truncate">admin@sso.local</p>
          </div>
        </div>
        <button @click="handleLogout" class="w-full flex items-center justify-center gap-2 py-2.5 px-4 text-sm font-semibold text-red-600 bg-red-50 hover:bg-red-100 rounded-xl transition-colors">
          <i class="pi pi-sign-out"></i>
          <span>Sign Out</span>
        </button>
      </div>
    </aside>

    <!-- Main Content -->
    <main class="flex-grow flex flex-col min-w-0">
      <header class="h-20 bg-white border-b border-gray-200 px-10 flex items-center justify-between sticky top-0 z-10">
        <div>
          <h1 class="text-2xl font-bold text-gray-900 capitalize leading-none">{{ currentTab.replace('-', ' ') }}</h1>
          <nav class="flex text-xs text-gray-400 mt-1 font-medium">
            <span class="hover:text-indigo-600 cursor-pointer">Dashboard</span>
            <span class="mx-2">/</span>
            <span class="text-gray-600 capitalize">{{ currentTab }}</span>
          </nav>
        </div>
        
        <div class="flex items-center gap-4">
          <div class="relative">
            <i class="pi pi-search absolute left-3 top-1/2 -translate-y-1/2 text-gray-400"></i>
            <input type="text" placeholder="Quick search..." class="pl-10 pr-4 py-2 bg-gray-100 border-none rounded-xl text-sm focus:ring-2 focus:ring-indigo-500 w-64 transition-all" />
          </div>
          <Button v-if="currentTab !== 'logs'" :label="'Add ' + currentTab.slice(0, -1)" icon="pi pi-plus" class="p-button-primary shadow-lg shadow-indigo-100 rounded-xl" @click="openCreateDialog" />
        </div>
      </header>

      <div class="p-10 flex-grow">
        <div class="bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden">
          <!-- Users Tab -->
          <DataTable v-if="currentTab === 'users'" :value="users" paginator :rows="10" :totalRecords="totalUsers" lazy @page="onUserPage" :loading="loading" class="p-datatable-sm">
            <Column field="id" header="ID" class="w-20 font-mono text-xs"></Column>
            <Column field="username" header="User" class="font-semibold">
              <template #body="slotProps">
                <div class="flex items-center gap-3">
                  <div class="w-8 h-8 rounded-lg bg-indigo-50 flex items-center justify-center text-xs font-bold text-indigo-600">
                    {{ slotProps.data.username[0].toUpperCase() }}
                  </div>
                  <div>
                    <div class="text-gray-900">{{ slotProps.data.username }}</div>
                    <div class="text-xs text-gray-400">{{ slotProps.data.email }}</div>
                  </div>
                </div>
              </template>
            </Column>
            <Column field="display_name" header="Display Name"></Column>
            <Column field="status" header="Status">
              <template #body="slotProps">
                <span :class="statusBadgeClass(slotProps.data.status)">
                  {{ slotProps.data.status === 1 ? 'Active' : 'Disabled' }}
                </span>
              </template>
            </Column>
            <Column field="created_at" header="Joined">
              <template #body="slotProps">
                <span class="text-gray-500 text-sm">
                  {{ new Date(slotProps.data.created_at * 1000).toLocaleDateString() }}
                </span>
              </template>
            </Column>
            <Column header="Actions" class="w-32">
              <template #body="slotProps">
                <div class="flex gap-1 justify-end">
                  <Button icon="pi pi-pencil" text rounded severity="secondary" @click="editUser(slotProps.data)" />
                  <Button icon="pi pi-trash" text rounded severity="danger" @click="confirmDeleteUser(slotProps.data)" />
                </div>
              </template>
            </Column>
          </DataTable>

          <!-- Roles Tab -->
          <DataTable v-if="currentTab === 'roles'" :value="roles" paginator :rows="10" :loading="loading">
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

          <!-- Groups Tab -->
          <DataTable v-if="currentTab === 'groups'" :value="groups" paginator :rows="10" :loading="loading">
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

          <!-- Policies Tab -->
          <DataTable v-if="currentTab === 'policies'" :value="policies" paginator :rows="10" :loading="loading">
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

          <!-- Logs Tab -->
          <DataTable v-if="currentTab === 'logs'" :value="logs" paginator :rows="20" :loading="loading">
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
      </div>
    </main>

    <!-- Dialogs -->
    <Dialog v-model:visible="userDialog" header="User Details" modal class="w-full max-w-lg" :pt="{ mask: { style: 'backdrop-filter: blur(4px)' } }">
       <div class="space-y-4 py-4">
         <div class="flex flex-col gap-2">
            <label class="text-sm font-bold text-gray-700">Username</label>
            <InputText v-model.trim="user.username" class="rounded-xl border-gray-200" placeholder="johndoe" autofocus />
         </div>
         <div class="flex flex-col gap-2">
            <label class="text-sm font-bold text-gray-700">Display Name</label>
            <InputText v-model.trim="user.display_name" class="rounded-xl border-gray-200" placeholder="John Doe" />
         </div>
         <div class="flex flex-col gap-2">
            <label class="text-sm font-bold text-gray-700">Email Address</label>
            <InputText v-model.trim="user.email" class="rounded-xl border-gray-200" placeholder="john@example.com" />
         </div>
         <div class="flex items-center gap-2 mt-4">
            <Checkbox v-model="userStatus" :binary="true" inputId="userStatus" />
            <label for="userStatus" class="text-sm font-semibold text-gray-700">Active Account</label>
         </div>
       </div>
       <template #footer>
          <div class="flex gap-2 justify-end pt-4">
            <Button label="Cancel" text severity="secondary" @click="userDialog = false" class="rounded-xl" />
            <Button label="Save Changes" @click="saveUser" class="p-button-primary rounded-xl px-6" />
          </div>
       </template>
    </Dialog>

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
import { ref, onMounted, watch, computed } from 'vue';
import { useRouter } from 'vue-router';
import { adminService, auditService, authService, type User, type Role, type Group, type Policy, type AuditLog } from '../services/api';
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import Button from 'primevue/button';
import Dialog from 'primevue/dialog';
import InputText from 'primevue/inputtext';
import Checkbox from 'primevue/checkbox';

const router = useRouter();
const currentTab = ref('users');
const loading = ref(false);

const users = ref<User[]>([]);
const totalUsers = ref(0);
const roles = ref<Role[]>([]);
const groups = ref<Group[]>([]);
const policies = ref<Policy[]>([]);
const logs = ref<AuditLog[]>([]);

const userDialog = ref(false);
const user = ref<Partial<User>>({});
const userStatus = computed({
  get: () => user.value.status === 1,
  set: (val) => user.value.status = val ? 1 : 0
});

const roleDialog = ref(false);
const role = ref<Partial<Role>>({});

const groupDialog = ref(false);
const group = ref<Partial<Group>>({});

const policyDialog = ref(false);
const policy = ref<Partial<Policy>>({});

const tabClass = (tab: string) => [
  'w-full flex items-center gap-3 py-3 px-4 rounded-xl transition-all font-semibold text-sm',
  currentTab.value === tab 
    ? 'bg-indigo-50 text-indigo-700 shadow-sm shadow-indigo-50' 
    : 'text-gray-500 hover:bg-gray-50 hover:text-gray-700'
];

const statusBadgeClass = (status: number) => [
  'px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider',
  status === 1 ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
];

const loadUsers = async (page = 1) => {
  loading.value = true;
  try {
    const res = await adminService.listUsers(page);
    users.value = res.items;
    totalUsers.value = res.total;
  } catch (err) {
    console.error('Failed to load users:', err);
  } finally {
    loading.value = false;
  }
};

const loadRoles = async () => {
  loading.value = true;
  try {
    const res = await adminService.listRoles();
    roles.value = res.items;
  } catch (err) {
    console.error('Failed to load roles:', err);
  } finally {
    loading.value = false;
  }
};

const loadGroups = async () => {
  loading.value = true;
  try {
    const res = await adminService.listGroups();
    groups.value = res.items;
  } finally {
    loading.value = false;
  }
};

const loadPolicies = async () => {
  loading.value = true;
  try {
    const res = await adminService.listPolicies();
    policies.value = res.items;
  } finally {
    loading.value = false;
  }
};

const loadLogs = async () => {
  loading.value = true;
  try {
    const res = await auditService.listLogs();
    logs.value = res.items;
  } finally {
    loading.value = false;
  }
};

const onUserPage = (event: any) => {
  loadUsers(event.page + 1);
};

watch(currentTab, (newTab) => {
  if (newTab === 'users') loadUsers();
  if (newTab === 'roles') loadRoles();
  if (newTab === 'groups') loadGroups();
  if (newTab === 'policies') loadPolicies();
  if (newTab === 'logs') loadLogs();
});

onMounted(() => {
  loadUsers();
});

const openCreateDialog = () => {
  if (currentTab.value === 'users') {
    user.value = { status: 1 };
    userDialog.value = true;
  } else if (currentTab.value === 'roles') {
    role.value = { status: 1 };
    roleDialog.value = true;
  } else if (currentTab.value === 'groups') {
    group.value = { status: 1 };
    groupDialog.value = true;
  } else if (currentTab.value === 'policies') {
    policy.value = { status: 1, rules: '{}' };
    policyDialog.value = true;
  }
};

const editUser = (data: User) => {
  user.value = { ...data };
  userDialog.value = true;
};

const saveUser = async () => {
  try {
    if (user.value.id) {
      await adminService.updateUser(user.value.id, user.value);
    } else {
      await adminService.createUser(user.value);
    }
    userDialog.value = false;
    loadUsers();
  } catch (err) {
    alert('Failed to save user');
  }
};

const confirmDeleteUser = async (data: User) => {
  if (confirm(`Delete user ${data.username}?`)) {
    try {
      await adminService.deleteUser(data.id);
      loadUsers();
    } catch (err) {
      alert('Failed to delete user');
    }
  }
};

const editRole = (data: Role) => {
  role.value = { ...data };
  roleDialog.value = true;
};

const saveRole = async () => {
  try {
    if (role.value.id) {
      await adminService.updateRole(role.value.id, role.value);
    } else {
      await adminService.createRole(role.value);
    }
    roleDialog.value = false;
    loadRoles();
  } catch (err) {
    alert('Failed to save role');
  }
};

const confirmDeleteRole = async (data: Role) => {
  if (confirm(`Delete role ${data.name}?`)) {
    try {
      await adminService.deleteRole(data.id);
      loadRoles();
    } catch (err) {
      alert('Failed to delete role');
    }
  }
};

const editGroup = (data: Group) => {
  group.value = { ...data };
  groupDialog.value = true;
};

const saveGroup = async () => {
  try {
    if (group.value.id) {
      await adminService.updateGroup(group.value.id, group.value);
    } else {
      await adminService.createGroup(group.value);
    }
    groupDialog.value = false;
    loadGroups();
  } catch (err) {
    alert('Failed to save group');
  }
};

const confirmDeleteGroup = async (data: Group) => {
  if (confirm(`Delete group ${data.name}?`)) {
    try {
      await adminService.deleteGroup(data.id);
      loadGroups();
    } catch (err) {
      alert('Failed to delete group');
    }
  }
};

const editPolicy = (data: Policy) => {
  policy.value = { ...data };
  policyDialog.value = true;
};

const savePolicy = async () => {
  try {
    if (policy.value.id) {
      await adminService.updatePolicy(policy.value.id, policy.value);
    } else {
      await adminService.createPolicy(policy.value);
    }
    policyDialog.value = false;
    loadPolicies();
  } catch (err) {
    alert('Failed to save policy');
  }
};

const confirmDeletePolicy = async (data: Policy) => {
  if (confirm(`Delete policy ${data.name}?`)) {
    try {
      await adminService.deletePolicy(data.id);
      loadPolicies();
    } catch (err) {
      alert('Failed to delete policy');
    }
  }
};

const handleLogout = async () => {
  try {
    await authService.logout();
    router.push('/login');
  } catch (err) {
    router.push('/login');
  }
};
</script>

<style>
/* Custom PrimeVue styles override */
.p-datatable .p-datatable-thead > tr > th {
  @apply bg-gray-50 text-gray-500 font-bold text-xs uppercase tracking-wider py-4 border-b border-gray-100;
}
.p-datatable .p-datatable-tbody > tr {
  @apply transition-colors hover:bg-gray-50/50;
}
.p-datatable .p-datatable-tbody > tr > td {
  @apply py-4 border-b border-gray-50;
}
.p-paginator {
  @apply border-none py-4;
}
.p-button {
  @apply transition-all duration-200 active:scale-95;
}
.p-dialog-header {
  @apply p-8 border-b border-gray-100;
}
.p-dialog-content {
  @apply px-8;
}
.p-dialog-footer {
  @apply p-8 border-t border-gray-100;
}
</style>
