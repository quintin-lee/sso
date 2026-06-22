<template>
  <div class="admin-layout flex h-screen bg-[var(--bg-primary)]">
    <!-- Sidebar -->
    <aside class="w-[var(--sidebar-width)] bg-[var(--bg-secondary)] border-r border-[var(--border-primary)] flex flex-col flex-shrink-0">
      <!-- Brand -->
      <div class="px-5 py-5 flex items-center gap-3 border-b border-[var(--border-primary)]">
        <div class="w-9 h-9 rounded-lg bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center shadow-md shadow-indigo-500/20">
          <i class="pi pi-shield text-white text-base"></i>
        </div>
        <div>
          <h2 class="text-base font-bold text-[var(--text-primary)] leading-tight tracking-tight">{{ $t('admin.brand') }}</h2>
          <span class="text-[10px] text-[var(--text-muted)] font-medium tracking-wider uppercase">{{ $t('sidebar.controlCenter') }}</span>
        </div>
      </div>

      <!-- Navigation -->
      <nav class="flex-grow py-4 px-3 space-y-1 overflow-y-auto">
        <button @click="currentTab = 'dashboard'" :class="tabClass('dashboard')">
          <i class="pi pi-chart-bar text-sm"></i>
          <span>{{ $t('sidebar.dashboard') }}</span>
        </button>

        <div class="px-3 pt-5 pb-2 text-[10px] font-bold text-[var(--text-muted)] uppercase tracking-[0.1em]">{{ $t('sidebar.management') }}</div>
        <button @click="currentTab = 'users'" :class="tabClass('users')">
          <i class="pi pi-users text-sm"></i>
          <span>{{ $t('sidebar.users') }}</span>
        </button>
        <button @click="currentTab = 'roles'" :class="tabClass('roles')">
          <i class="pi pi-tags text-sm"></i>
          <span>{{ $t('sidebar.roles') }}</span>
        </button>
        <button @click="currentTab = 'groups'" :class="tabClass('groups')">
          <i class="pi pi-sitemap text-sm"></i>
          <span>{{ $t('sidebar.groups') }}</span>
        </button>
        <button @click="currentTab = 'apps'" :class="tabClass('apps')">
          <i class="pi pi-desktop text-sm"></i>
          <span>{{ $t('sidebar.apps') }}</span>
        </button>
        <button @click="currentTab = 'cluster'" :class="tabClass('cluster')">
          <i class="pi pi-server text-sm"></i>
          <span>{{ $t('admin.cluster.title') }}</span>
        </button>

        <div class="px-3 pt-5 pb-2 text-[10px] font-bold text-[var(--text-muted)] uppercase tracking-[0.1em]">{{ $t('sidebar.security') }}</div>
        <button @click="currentTab = 'policies'" :class="tabClass('policies')">
          <i class="pi pi-lock text-sm"></i>
          <span>{{ $t('sidebar.policies') }}</span>
        </button>
        <button @click="currentTab = 'logs'" :class="tabClass('logs')">
          <i class="pi pi-history text-sm"></i>
          <span>{{ $t('sidebar.logs') }}</span>
        </button>
      </nav>

      <!-- User area -->
      <div class="p-4 border-t border-[var(--border-primary)]">
        <div class="flex items-center gap-3 mb-3 px-2">
          <div class="w-8 h-8 rounded-full bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center text-xs font-bold text-white">
            A
          </div>
          <div class="overflow-hidden">
            <p class="text-sm font-semibold text-[var(--text-primary)] truncate">{{ $t('sidebar.administrator') }}</p>
            <p class="text-[11px] text-[var(--text-muted)] truncate font-mono">admin@sso.local</p>
          </div>
        </div>
        <button @click="handleLogout" class="w-full flex items-center justify-center gap-2 py-2 px-3 text-xs font-semibold text-rose-400 bg-rose-500/10 hover:bg-rose-500/20 rounded-lg transition-colors">
          <i class="pi pi-sign-out text-xs"></i>
          <span>{{ $t('sidebar.signOut') }}</span>
        </button>
      </div>
    </aside>

    <!-- Main Content -->
    <main class="flex-grow flex flex-col min-w-0">
      <!-- Header -->
      <header class="h-14 bg-[var(--bg-secondary)] border-b border-[var(--border-primary)] px-6 flex items-center justify-between sticky top-0 z-10">
        <div>
          <h1 class="text-lg font-bold text-[var(--text-primary)] leading-tight tracking-tight">
            {{ $t(`sidebar.${currentTab}`) }}
          </h1>
          <nav class="flex text-[11px] text-[var(--text-muted)] mt-0.5 font-medium">
            <span class="hover:text-[var(--accent)] cursor-pointer transition-colors" @click="currentTab = 'dashboard'">{{ $t('admin.breadcrumb') }}</span>
            <span class="mx-1.5 text-[var(--border-primary)]">/</span>
            <span class="text-[var(--text-secondary)]">{{ $t(`sidebar.${currentTab}`) }}</span>
          </nav>
        </div>

        <div class="flex items-center gap-2.5">
          <div class="relative">
            <i class="pi pi-search absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)] text-xs"></i>
            <input type="text" v-model="searchQuery" :placeholder="$t('common.search')" class="pl-8 pr-3 py-1.5 bg-[var(--bg-elevated)] border border-[var(--border-primary)] rounded-lg text-xs text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] w-48 transition-all" />
          </div>

          <button @click="toggleLanguage" class="flex items-center gap-1.5 py-1.5 px-2.5 bg-[var(--bg-elevated)] border border-[var(--border-primary)] hover:border-[var(--accent)] text-[var(--text-secondary)] hover:text-[var(--accent)] rounded-lg font-semibold text-[11px] uppercase transition-all">
            <i class="pi pi-globe text-xs"></i>
            <span>{{ locale === 'en' ? '中文' : 'EN' }}</span>
          </button>

          <Button v-if="currentTab !== 'logs' && currentTab !== 'dashboard'" :label="$t('common.add')" icon="pi pi-plus" size="small"
            class="!bg-[var(--accent-strong)] !border-none hover:!bg-[var(--accent)] !text-white !rounded-lg !px-3 !py-1.5 !text-xs !font-semibold"
            @click="handleCreate" />
        </div>
      </header>

      <!-- Content -->
      <div class="flex-grow overflow-y-auto p-6 bg-[var(--bg-primary)]">
        <Dashboard v-if="currentTab === 'dashboard'" />
        <UserManagement v-else-if="currentTab === 'users'" ref="userRef" :search="searchQuery" />
        <RoleManagement v-else-if="currentTab === 'roles'" ref="roleRef" :search="searchQuery" />
        <GroupManagement v-else-if="currentTab === 'groups'" ref="groupRef" :search="searchQuery" />
        <PolicyManagement v-else-if="currentTab === 'policies'" ref="policyRef" :search="searchQuery" />
        <AppManagement v-else-if="currentTab === 'apps'" ref="appRef" :search="searchQuery" />
        <AuditLogViewer v-else-if="currentTab === 'logs'" :search="searchQuery" />
        
        <!-- Cluster Content -->
        <div v-else-if="currentTab === 'cluster'" class="bg-[var(--bg-elevated)] rounded-xl border border-[var(--border-primary)] shadow-sm p-6 overflow-hidden flex flex-col h-full">
          <div class="flex items-center justify-between mb-6">
            <h3 class="text-sm font-bold text-[var(--text-primary)] flex items-center gap-2">
              <i class="pi pi-server text-[var(--accent)]"></i> {{ $t('admin.cluster.title') }}
            </h3>
            <button @click="fetchClusterStatus" class="px-3 py-1.5 text-xs bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)] rounded-lg transition-colors font-medium flex items-center gap-2">
              <i class="pi pi-refresh" :class="{ 'animate-spin': loadingCluster }"></i> {{ $t('admin.cluster.refresh') }}
            </button>
          </div>
          
          <div v-if="loadingCluster && !clusterStatus" class="flex-grow flex items-center justify-center">
            <i class="pi pi-spinner animate-spin text-2xl text-[var(--text-muted)]"></i>
          </div>
          
          <div v-else-if="clusterStatus" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div class="bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-lg p-4 flex flex-col items-center justify-center gap-2">
              <span class="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider">{{ $t('admin.cluster.nodeState') }}</span>
              <div class="flex items-center gap-2">
                <div class="w-2.5 h-2.5 rounded-full" :class="{
                  'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]': clusterStatus.state === 'leader',
                  'bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)]': clusterStatus.state === 'follower',
                  'bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.5)]': clusterStatus.state === 'candidate'
                }"></div>
                <span class="text-lg font-bold text-[var(--text-primary)] capitalize">{{ clusterStatus.state }}</span>
              </div>
            </div>
            
            <div class="bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-lg p-4 flex flex-col items-center justify-center gap-2">
              <span class="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider">{{ $t('admin.cluster.currentTerm') }}</span>
              <span class="text-2xl font-mono font-bold text-[var(--text-primary)]">{{ clusterStatus.term }}</span>
            </div>
            
            <div class="bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-lg p-4 flex flex-col items-center justify-center gap-2">
              <span class="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider">{{ $t('admin.cluster.logIndex') }}</span>
              <span class="text-2xl font-mono font-bold text-[var(--text-primary)]">{{ clusterStatus.current_idx }}</span>
            </div>
            
            <div class="bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-lg p-4 flex flex-col items-center justify-center gap-2">
              <span class="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider">{{ $t('admin.cluster.clusterSize') }}</span>
              <span class="text-2xl font-mono font-bold text-[var(--text-primary)]">{{ clusterStatus.num_nodes }} {{ $t('admin.cluster.nodes') }}</span>
            </div>
            
            <div class="bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-lg p-4 flex flex-col items-center justify-center gap-2 col-span-1 md:col-span-2 lg:col-span-2">
              <span class="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider">{{ $t('admin.cluster.leaderAddress') }}</span>
              <span class="text-sm font-mono text-[var(--text-secondary)] bg-[var(--bg-primary)] px-3 py-1 rounded border border-[var(--border-primary)] w-full text-center truncate">
                {{ clusterStatus.leader_url || $t('admin.cluster.unknownLeader') }}
              </span>
            </div>
          </div>
          
          <div v-else class="flex-grow flex flex-col items-center justify-center text-[var(--text-muted)] gap-3">
            <i class="pi pi-exclamation-triangle text-3xl"></i>
            <p class="text-sm">{{ $t('admin.cluster.failedLoad') }}</p>
          </div>
        </div>
      </div>
    </main>
  </div>
  <ConfirmDialog />
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { useI18n } from 'vue-i18n';
import { authService } from '../services/api';
import Button from 'primevue/button';
import ConfirmDialog from 'primevue/confirmdialog';
import Dashboard from '../components/admin/Dashboard.vue';
import UserManagement from '../components/admin/UserManagement.vue';
import RoleManagement from '../components/admin/RoleManagement.vue';
import GroupManagement from '../components/admin/GroupManagement.vue';
import PolicyManagement from '../components/admin/PolicyManagement.vue';
import AppManagement from '../components/admin/AppManagement.vue';
import AuditLogViewer from '../components/admin/AuditLogViewer.vue';

const searchQuery = ref('');
const loadingCluster = ref(false);
const clusterStatus = ref<any>(null);

const { locale } = useI18n();
const router = useRouter();
const route = useRoute();

const currentTab = computed({
  get: () => (route.query.tab as string) || 'dashboard',
  set: (val) => {
    router.replace({ query: { ...route.query, tab: val } });
  }
});

const userRef = ref();
const roleRef = ref();
const groupRef = ref();
const policyRef = ref();
const appRef = ref();

const toggleLanguage = () => {
  locale.value = locale.value === 'en' ? 'zh' : 'en';
  localStorage.setItem('locale', locale.value);
};

const tabClass = (tab: string) => [
  'w-full flex items-center gap-2.5 py-2 px-3 rounded-lg transition-colors font-semibold text-[13px]',
  currentTab.value === tab
    ? 'bg-[var(--accent)]/15 text-[var(--accent)] border border-[var(--accent)]/25'
    : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] border border-transparent'
];

const handleCreate = () => {
  if (currentTab.value === 'users') userRef.value?.openCreateDialog();
  if (currentTab.value === 'roles') roleRef.value?.openCreateDialog();
  if (currentTab.value === 'groups') groupRef.value?.openCreateDialog();
  if (currentTab.value === 'policies') policyRef.value?.openCreateDialog();
  if (currentTab.value === 'apps') appRef.value?.openCreateDialog();
};

onMounted(() => {
  document.documentElement.classList.add('sso-dark');
});

onUnmounted(() => {
  document.documentElement.classList.remove('sso-dark');
});

const handleLogout = async () => {
  try {
    await authService.logout();
    router.push('/login');
  } catch (err) {
    router.push('/login');
  }
};

watch(currentTab, (newTab) => {
  if (newTab === 'cluster') {
    fetchClusterStatus();
  }
});

const fetchClusterStatus = async () => {
  loadingCluster.value = true;
  try {
    const res = await fetch('/api/v1/raft/status');
    if (res.ok) {
      clusterStatus.value = await res.json();
    } else {
      console.error("Failed to fetch cluster status");
    }
  } catch (e) {
    console.error(e);
  } finally {
    loadingCluster.value = false;
  }
};
</script>

<style>
.sso-dark .p-datatable {
  background: var(--bg-card);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-premium);
  overflow: hidden;
}

.sso-dark .p-datatable-table-container {
  border-radius: var(--radius-premium);
}

.sso-dark .p-datatable-thead > tr > th,
.sso-dark .p-datatable-header-cell {
  background: var(--bg-elevated);
  color: var(--text-secondary);
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  padding: 14px 20px;
  border-bottom: 1px solid var(--border-primary);
  text-align: left;
}

.sso-dark .p-datatable-tbody > tr {
  background: transparent;
  color: var(--text-secondary);
  transition: background-color 0.15s ease;
}

.sso-dark .p-datatable-tbody > tr:hover {
  background: var(--bg-hover);
}

.sso-dark .p-datatable-tbody > tr > td {
  padding: 14px 20px;
  border-bottom: 1px solid var(--border-subtle);
}

.sso-dark .p-datatable-tbody > tr:last-child > td {
  border-bottom: 0;
}

.sso-dark .p-datatable-emptymessage td {
  padding: 48px 20px;
  text-align: center;
  color: var(--text-muted);
}

.sso-dark .p-paginator {
  background: var(--bg-elevated);
  border-top: 1px solid var(--border-primary);
  padding: 12px 16px;
  min-height: 48px;
}

.sso-dark .p-paginator .p-paginator-page,
.sso-dark .p-paginator .p-paginator-first,
.sso-dark .p-paginator .p-paginator-prev,
.sso-dark .p-paginator .p-paginator-next,
.sso-dark .p-paginator .p-paginator-last {
  min-width: 32px;
  height: 32px;
  margin: 0 2px;
  border-radius: 8px;
  color: var(--text-secondary);
  background: transparent;
  border: 1px solid transparent;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  transition: all 0.15s ease;
}

.sso-dark .p-paginator .p-paginator-page:hover,
.sso-dark .p-paginator .p-paginator-first:not(:disabled):hover,
.sso-dark .p-paginator .p-paginator-prev:not(:disabled):hover,
.sso-dark .p-paginator .p-paginator-next:not(:disabled):hover,
.sso-dark .p-paginator .p-paginator-last:not(:disabled):hover {
  background: var(--bg-hover);
  color: var(--text-primary);
  border-color: var(--border-primary);
}

.sso-dark .p-paginator .p-paginator-page.p-paginator-page-selected {
  background: rgba(129, 140, 248, 0.18);
  color: var(--accent);
  border-color: rgba(129, 140, 248, 0.3);
}

.sso-dark .p-dialog {
  background: var(--bg-secondary);
  border: 1px solid var(--border-primary);
  border-radius: 16px;
  box-shadow: 0 24px 48px -12px rgba(0, 0, 0, 0.7);
}

.sso-dark .p-dialog-mask {
  background: rgba(5, 8, 20, 0.75);
  backdrop-filter: blur(6px);
}

.sso-dark .p-dialog-header {
  padding: 20px 24px;
  border-bottom: 1px solid var(--border-subtle);
}

.sso-dark .p-dialog-title {
  font-size: 17px;
  font-weight: 700;
  color: var(--text-primary);
}

.sso-dark .p-dialog-content {
  padding: 24px;
}

.sso-dark .p-dialog-footer {
  padding: 16px 24px 20px;
  border-top: 1px solid var(--border-subtle);
  display: flex;
  justify-content: flex-end;
  gap: 12px;
}

.sso-dark .p-dialog .p-dialog-header-action {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  color: var(--text-muted);
  background: transparent;
  border: 1px solid transparent;
  transition: all 0.15s ease;
}

.sso-dark .p-dialog .p-dialog-header-action:hover {
  color: var(--text-primary);
  background: var(--bg-hover);
}

.sso-dark .p-inputtext {
  background: var(--bg-elevated);
  border: 1px solid var(--border-primary);
  color: var(--text-primary);
  border-radius: 10px;
  padding: 10px 14px;
  font-size: 14px;
  transition: border-color 0.15s ease, box-shadow 0.15s ease;
}

.sso-dark .p-inputtext:focus,
.sso-dark .p-inputtext:hover:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-glow);
  outline: none;
}

.sso-dark .p-inputtext::placeholder {
  color: var(--text-placeholder);
}

.sso-dark .p-button {
  border-radius: 10px;
  font-weight: 600;
  transition: all 0.15s ease;
}

.sso-dark .p-button:not(:disabled):active {
  transform: scale(0.97);
}

.sso-dark select {
  background: var(--bg-elevated);
  border: 1px solid var(--border-primary);
  color: var(--text-primary);
  border-radius: 10px;
  padding: 10px 14px;
  font-size: 14px;
}

.sso-dark select:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-glow);
  outline: none;
}

.sso-dark textarea {
  background: var(--bg-elevated);
  border: 1px solid var(--border-primary);
  color: var(--text-primary);
  border-radius: 10px;
  padding: 12px 14px;
  font-size: 13px;
  font-family: ui-monospace, 'SF Mono', Menlo, monospace;
}

.sso-dark textarea:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-glow);
  outline: none;
}

.sso-dark .p-message.p-message-error {
  background: rgba(251, 113, 133, 0.1);
  border: 1px solid rgba(251, 113, 133, 0.25);
  border-radius: 10px;
  color: var(--danger);
}

.sso-dark .p-checkbox .p-checkbox-box {
  width: 18px;
  height: 18px;
  border-radius: 5px;
  background: var(--bg-elevated);
  border: 1px solid var(--border-primary);
}

.sso-dark .p-checkbox.p-checkbox-checked .p-checkbox-box {
  background: var(--accent);
  border-color: var(--accent);
}

.sso-dark .p-confirmdialog .p-confirmdialog-icon {
  font-size: 24px;
  color: var(--warning, #f59e0b);
  margin-bottom: 8px;
}

.sso-dark .p-confirmdialog .p-confirmdialog-message {
  font-size: 14px;
  color: var(--text-secondary);
  line-height: 1.5;
}
</style>
