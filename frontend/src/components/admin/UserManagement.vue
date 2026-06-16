<template>
  <div class="bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden">
    <DataTable :value="users" paginator :rows="10" :totalRecords="totalUsers" lazy @page="onUserPage" :loading="loading" class="p-datatable-sm">
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
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';
import { adminService, type User } from '../../services/api';
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import Button from 'primevue/button';
import Dialog from 'primevue/dialog';
import InputText from 'primevue/inputtext';
import Checkbox from 'primevue/checkbox';
import { useToast } from 'primevue/usetoast';

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
  status === 1 ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
];

const loadUsers = async (page = 1) => {
  loading.value = true;
  try {
    const res = await adminService.listUsers(page);
    users.value = res.items;
    totalUsers.value = res.total;
  } catch (err) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to load users', life: 3000 });
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
      toast.add({ severity: 'success', summary: 'Success', detail: 'User updated successfully', life: 3000 });
    } else {
      await adminService.createUser(user.value);
      toast.add({ severity: 'success', summary: 'Success', detail: 'User created successfully', life: 3000 });
    }
    userDialog.value = false;
    loadUsers();
  } catch (err) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to save user', life: 3000 });
  }
};

const confirmDeleteUser = async (data: User) => {
  if (confirm(`Delete user ${data.username}?`)) {
    try {
      await adminService.deleteUser(data.id);
      toast.add({ severity: 'success', summary: 'Success', detail: 'User deleted successfully', life: 3000 });
      loadUsers();
    } catch (err) {
      toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to delete user', life: 3000 });
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
