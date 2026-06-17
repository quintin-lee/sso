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
          <span class="text-xs text-gray-500 font-medium">{{ $t('sidebar.controlCenter') }}</span>
        </div>
      </div>
      
      <nav class="flex-grow py-6 px-4 space-y-1">
        <button @click="currentTab = 'dashboard'" :class="tabClass('dashboard')">
          <i class="pi pi-chart-bar text-lg"></i>
          <span>{{ $t('sidebar.dashboard') }}</span>
        </button>

        <div class="px-4 pt-6 mb-2 text-xs font-semibold text-gray-400 uppercase tracking-wider">{{ $t('sidebar.management') }}</div>
        <button @click="currentTab = 'users'" :class="tabClass('users')">
          <i class="pi pi-users text-lg"></i>
          <span>{{ $t('sidebar.users') }}</span>
        </button>
        <button @click="currentTab = 'roles'" :class="tabClass('roles')">
          <i class="pi pi-tags text-lg"></i>
          <span>{{ $t('sidebar.roles') }}</span>
        </button>
        <button @click="currentTab = 'groups'" :class="tabClass('groups')">
          <i class="pi pi-sitemap text-lg"></i>
          <span>{{ $t('sidebar.groups') }}</span>
        </button>
        
        <div class="px-4 pt-6 mb-2 text-xs font-semibold text-gray-400 uppercase tracking-wider">{{ $t('sidebar.security') }}</div>
        <button @click="currentTab = 'policies'" :class="tabClass('policies')">
          <i class="pi pi-lock text-lg"></i>
          <span>{{ $t('sidebar.policies') }}</span>
        </button>
        <button @click="currentTab = 'logs'" :class="tabClass('logs')">
          <i class="pi pi-history text-lg"></i>
          <span>{{ $t('sidebar.logs') }}</span>
        </button>
      </nav>

      <div class="p-6 border-t border-gray-100 mt-auto">
        <div class="flex items-center gap-3 mb-6 px-2">
          <div class="w-8 h-8 rounded-full bg-gray-100 flex items-center justify-center text-sm font-bold text-gray-600">
            A
          </div>
          <div class="overflow-hidden">
            <p class="text-sm font-semibold text-gray-900 truncate">{{ $t('sidebar.administrator') }}</p>
            <p class="text-xs text-gray-500 truncate">admin@sso.local</p>
          </div>
        </div>
        <button @click="handleLogout" class="w-full flex items-center justify-center gap-2 py-2.5 px-4 text-sm font-semibold text-red-600 bg-red-50 hover:bg-red-100 rounded-xl transition-colors">
          <i class="pi pi-sign-out"></i>
          <span>{{ $t('sidebar.signOut') }}</span>
        </button>
      </div>
    </aside>

    <!-- Main Content -->
    <main class="flex-grow flex flex-col min-w-0">
      <header class="h-20 bg-white border-b border-gray-200 px-10 flex items-center justify-between sticky top-0 z-10">
        <div>
          <h1 class="text-2xl font-bold text-gray-900 leading-none">
            {{ $t(`sidebar.${currentTab}`) }}
          </h1>
          <nav class="flex text-xs text-gray-400 mt-1 font-medium">
            <span class="hover:text-indigo-600 cursor-pointer" @click="currentTab = 'dashboard'">SSO Admin</span>
            <span class="mx-2">/</span>
            <span class="text-gray-600">{{ $t(`sidebar.${currentTab}`) }}</span>
          </nav>
        </div>
        
        <div class="flex items-center gap-4">
          <!-- Search -->
          <div class="relative">
            <i class="pi pi-search absolute left-3 top-1/2 -translate-y-1/2 text-gray-400"></i>
            <input type="text" :placeholder="$t('common.search')" class="pl-10 pr-4 py-2 bg-gray-100 border-none rounded-xl text-sm focus:ring-2 focus:ring-indigo-500 w-64 transition-all" />
          </div>

          <!-- Language Selector Switcher -->
          <button @click="toggleLanguage" class="flex items-center gap-2 py-2 px-3 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-xl font-bold text-xs uppercase transition-all select-none">
            <i class="pi pi-globe text-sm"></i>
            <span>{{ locale === 'en' ? '中文' : 'EN' }}</span>
          </button>

          <!-- Add Action Button -->
          <Button v-if="currentTab !== 'logs' && currentTab !== 'dashboard'" :label="$t('common.add')" icon="pi pi-plus" class="p-button-primary shadow-lg shadow-indigo-100 rounded-xl" @click="handleCreate" />
        </div>
      </header>

      <div class="p-10 flex-grow overflow-y-auto">
        <Dashboard v-if="currentTab === 'dashboard'" />
        <UserManagement v-else-if="currentTab === 'users'" ref="userRef" />
        <RoleManagement v-else-if="currentTab === 'roles'" ref="roleRef" />
        <GroupManagement v-else-if="currentTab === 'groups'" ref="groupRef" />
        <PolicyManagement v-else-if="currentTab === 'policies'" ref="policyRef" />
        <AuditLogViewer v-else-if="currentTab === 'logs'" />
      </div>
    </main>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { useI18n } from 'vue-i18n';
import { authService } from '../services/api';
import Button from 'primevue/button';
import Dashboard from '../components/admin/Dashboard.vue';
import UserManagement from '../components/admin/UserManagement.vue';
import RoleManagement from '../components/admin/RoleManagement.vue';
import GroupManagement from '../components/admin/GroupManagement.vue';
import PolicyManagement from '../components/admin/PolicyManagement.vue';
import AuditLogViewer from '../components/admin/AuditLogViewer.vue';

const { locale } = useI18n();
const router = useRouter();
const currentTab = ref('dashboard');

const userRef = ref();
const roleRef = ref();
const groupRef = ref();
const policyRef = ref();

const toggleLanguage = () => {
  locale.value = locale.value === 'en' ? 'zh' : 'en';
  localStorage.setItem('locale', locale.value);
};

const tabClass = (tab: string) => [
  'w-full flex items-center gap-3 py-3 px-4 rounded-xl transition-all font-semibold text-sm',
  currentTab.value === tab 
    ? 'bg-indigo-50 text-indigo-700 shadow-sm shadow-indigo-50' 
    : 'text-gray-500 hover:bg-gray-50 hover:text-gray-700'
];

const handleCreate = () => {
  if (currentTab.value === 'users') userRef.value?.openCreateDialog();
  if (currentTab.value === 'roles') roleRef.value?.openCreateDialog();
  if (currentTab.value === 'groups') groupRef.value?.openCreateDialog();
  if (currentTab.value === 'policies') policyRef.value?.openCreateDialog();
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
