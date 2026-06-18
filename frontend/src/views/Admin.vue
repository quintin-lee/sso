<template>
  <div class="admin-layout flex h-screen bg-[var(--bg-primary)]">
    <!-- Sidebar -->
    <aside class="w-[var(--sidebar-width)] bg-[var(--bg-secondary)]/80 backdrop-blur-xl border-r border-[var(--border-primary)] flex flex-col flex-shrink-0">
      <!-- Brand -->
      <div class="px-6 py-7 flex items-center gap-3 border-b border-[var(--border-primary)]">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center shadow-lg shadow-indigo-500/20">
          <i class="pi pi-shield text-white text-lg"></i>
        </div>
        <div>
          <h2 class="text-lg font-extrabold text-[var(--text-primary)] leading-none tracking-tight">SSO Admin</h2>
          <span class="text-xs text-[var(--text-secondary)] font-medium tracking-wider uppercase">{{ $t('sidebar.controlCenter') }}</span>
        </div>
      </div>

      <!-- Navigation -->
      <nav class="flex-grow py-5 px-3 space-y-0.5 overflow-y-auto">
        <!-- Dashboard -->
        <button @click="currentTab = 'dashboard'" :class="tabClass('dashboard')">
          <i class="pi pi-chart-bar text-lg"></i>
          <span>{{ $t('sidebar.dashboard') }}</span>
        </button>

        <!-- Management Section -->
        <div class="px-4 pt-6 pb-2 text-xs font-bold text-[var(--text-secondary)]/70 uppercase tracking-[0.12em]">{{ $t('sidebar.management') }}</div>
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

        <!-- Security Section -->
        <div class="px-4 pt-6 pb-2 text-xs font-bold text-[var(--text-secondary)]/70 uppercase tracking-[0.12em]">{{ $t('sidebar.security') }}</div>
        <button @click="currentTab = 'policies'" :class="tabClass('policies')">
          <i class="pi pi-lock text-lg"></i>
          <span>{{ $t('sidebar.policies') }}</span>
        </button>
        <button @click="currentTab = 'logs'" :class="tabClass('logs')">
          <i class="pi pi-history text-lg"></i>
          <span>{{ $t('sidebar.logs') }}</span>
        </button>
      </nav>

      <!-- User area -->
      <div class="p-5 border-t border-[var(--border-primary)]">
        <div class="flex items-center gap-3 mb-4 px-2">
          <div class="w-9 h-9 rounded-full bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center text-sm font-bold text-white shadow-md">
            A
          </div>
          <div class="overflow-hidden">
            <p class="text-sm font-semibold text-[var(--text-primary)] truncate">{{ $t('sidebar.administrator') }}</p>
            <p class="text-xs text-[var(--text-secondary)] truncate font-mono">admin@sso.local</p>
          </div>
        </div>
        <button @click="handleLogout" class="w-full flex items-center justify-center gap-2 py-2.5 px-4 text-sm font-semibold text-rose-400 bg-rose-500/10 hover:bg-rose-500/20 rounded-xl transition-all">
          <i class="pi pi-sign-out"></i>
          <span>{{ $t('sidebar.signOut') }}</span>
        </button>
      </div>
    </aside>

    <!-- Main Content -->
    <main class="flex-grow flex flex-col min-w-0">
      <!-- Header -->
      <header class="h-16 bg-[var(--bg-secondary)]/80 backdrop-blur-xl border-b border-[var(--border-primary)] px-8 flex items-center justify-between sticky top-0 z-10">
        <div>
          <h1 class="text-xl font-extrabold text-[var(--text-primary)] leading-none tracking-tight">
            {{ $t(`sidebar.${currentTab}`) }}
          </h1>
          <nav class="flex text-xs text-[var(--text-secondary)] mt-1 font-medium">
            <span class="hover:text-[var(--accent)] cursor-pointer transition-colors" @click="currentTab = 'dashboard'">SSO Admin</span>
            <span class="mx-2 text-[var(--border-primary)]">/</span>
            <span class="text-[var(--text-secondary)]">{{ $t(`sidebar.${currentTab}`) }}</span>
          </nav>
        </div>

        <div class="flex items-center gap-3">
          <!-- Search -->
          <div class="relative">
            <i class="pi pi-search absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-secondary)] text-sm"></i>
            <input type="text" :placeholder="$t('common.search')" class="pl-9 pr-4 py-2 bg-[var(--bg-elevated)] border border-[var(--border-primary)] rounded-xl text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] focus:ring-1 focus:ring-[var(--accent)] w-56 transition-all" />
          </div>

          <!-- Language Toggle -->
          <button @click="toggleLanguage" class="flex items-center gap-2 py-2 px-3 bg-[var(--bg-elevated)] border border-[var(--border-primary)] hover:border-[var(--accent)] text-[var(--text-secondary)] hover:text-[var(--accent)] rounded-xl font-bold text-xs uppercase transition-all">
            <i class="pi pi-globe text-sm"></i>
            <span>{{ locale === 'en' ? '中文' : 'EN' }}</span>
          </button>

          <!-- Add button -->
          <Button v-if="currentTab !== 'logs' && currentTab !== 'dashboard'" :label="$t('common.add')" icon="pi pi-plus"
            class="!bg-[var(--accent)] !border-none hover:!bg-indigo-500 !shadow-lg !shadow-indigo-500/20 !rounded-xl !px-4 !py-2 !text-sm !font-bold"
            @click="handleCreate" />
        </div>
      </header>

      <!-- Content -->
      <div class="flex-grow overflow-y-auto p-8 bg-[var(--bg-primary)]">
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
import { ref, computed } from 'vue';
import { useRouter, useRoute } from 'vue-router';
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

const toggleLanguage = () => {
  locale.value = locale.value === 'en' ? 'zh' : 'en';
  localStorage.setItem('locale', locale.value);
};

const tabClass = (tab: string) => [
  'w-full flex items-center gap-3 py-2.5 px-4 rounded-xl transition-all font-semibold text-sm',
  currentTab.value === tab
    ? 'bg-indigo-500/10 text-indigo-400 shadow-sm shadow-indigo-500/5 border border-indigo-500/10'
    : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] border border-transparent'
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
/* PrimeVue global dark theme overrides */

/* DataTable */
.p-datatable {
  @apply rounded-xl overflow-hidden border border-[var(--border-primary)];
}
.p-datatable .p-datatable-thead > tr > th {
  @apply bg-[var(--bg-elevated)] text-[var(--text-secondary)] font-bold text-xs uppercase tracking-[0.12em] py-4 px-5 border-b border-[var(--border-primary)] text-left;
}
.p-datatable .p-datatable-tbody > tr {
  @apply bg-[var(--bg-card)] text-[var(--text-secondary)] transition-colors;
}
.p-datatable .p-datatable-tbody > tr:hover {
  @apply bg-[var(--bg-hover)];
}
.p-datatable .p-datatable-tbody > tr > td {
  @apply py-4 px-5 border-b border-[var(--border-subtle)];
}
.p-datatable .p-datatable-tbody > tr:last-child > td {
  @apply border-b-0;
}

/* Paginator */
.p-paginator {
  @apply bg-[var(--bg-elevated)] border-t border-[var(--border-primary)] py-3 px-4 flex items-center justify-end gap-1;
}
.p-paginator .p-paginator-pages {
  @apply flex gap-1;
}
.p-paginator .p-paginator-page {
  @apply w-8 h-8 flex items-center justify-center rounded-lg text-xs font-semibold text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors cursor-pointer;
}
.p-paginator .p-paginator-page.p-highlight {
  @apply bg-indigo-500/15 text-indigo-400;
}

/* Dialog Overlay & Card */
.p-dialog {
  @apply bg-[var(--bg-card)] border border-[var(--border-primary)] rounded-2xl shadow-2xl overflow-hidden;
  backdrop-filter: blur(24px);
  -webkit-backdrop-filter: blur(24px);
  background-image: linear-gradient(135deg, rgba(255, 255, 255, 0.04) 0%, rgba(255, 255, 255, 0.0) 100%);
}
.p-dialog-mask {
  @apply bg-black/70;
  backdrop-filter: blur(10px);
  transition: all 0.3s ease;
}
.p-dialog-header {
  @apply p-6 border-b border-[var(--border-subtle)] flex items-center justify-between;
}
.p-dialog-title {
  @apply text-lg font-extrabold text-[var(--text-primary)] tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-slate-100 to-indigo-200;
}
.p-dialog-content {
  @apply p-6;
}
.p-dialog-footer {
  @apply p-6 border-t border-[var(--border-subtle)] flex justify-end gap-3 pt-4;
}

/* Close action styling */
.p-dialog .p-dialog-header-action {
  @apply w-8 h-8 rounded-xl bg-white/5 border border-white/5 text-[var(--text-secondary)] hover:text-white hover:bg-white/10 hover:border-white/10 flex items-center justify-center transition-all duration-200 focus:outline-none cursor-pointer;
}

/* Form inputs & labels inside Dialogs */
.p-dialog label:not(.text-sm) {
  @apply text-[11px] font-bold text-[var(--text-secondary)] uppercase tracking-[0.12em] mb-2 block;
}
.p-dialog .p-inputtext,
.p-dialog select,
.p-dialog textarea,
.p-dialog .p-password-input {
  @apply w-full bg-[var(--bg-elevated)] hover:bg-[var(--bg-elevated)] border border-[var(--border-primary)] hover:border-[var(--accent)] focus:border-[var(--accent)] rounded-xl px-4 py-3 text-sm transition-all focus:ring-1 focus:ring-[var(--accent)] outline-none !important;
}

/* Springy Dialog Transitions */
.p-dialog-enter-active {
  transition: all 0.35s cubic-bezier(0.34, 1.56, 0.64, 1);
}
.p-dialog-leave-active {
  transition: all 0.25s cubic-bezier(0.25, 1, 0.5, 1);
}
.p-dialog-enter-from, .p-dialog-leave-to {
  opacity: 0;
  transform: scale(0.96) translateY(8px);
}

/* Button */
.p-button {
  @apply transition-all duration-200 active:scale-95 rounded-xl font-bold;
}
.p-button.p-button-primary:not(.p-button-text):not(.p-button-outlined) {
  @apply bg-indigo-500 hover:bg-indigo-400 text-white border-none;
}

/* InputText */
.p-inputtext {
  @apply bg-[var(--bg-elevated)] border border-[var(--border-primary)] text-[var(--text-primary)] placeholder-[var(--text-muted)] rounded-xl px-4 py-2.5 text-sm transition-all;
}
.p-inputtext:focus {
  @apply border-[var(--accent)] ring-1 ring-[var(--accent)] outline-none;
}

/* Message */
.p-message {
  @apply rounded-xl text-sm;
}
.p-message.p-message-error {
  @apply bg-rose-500/10 border border-rose-500/20 text-rose-400;
}

/* Checkbox */
.p-checkbox {
  @apply w-5 h-5;
}
.p-checkbox .p-checkbox-box {
  @apply w-5 h-5 rounded-md bg-[var(--bg-elevated)] border border-[var(--border-primary)] transition-colors;
}
.p-checkbox.p-highlight .p-checkbox-box {
  @apply bg-indigo-500 border-indigo-500;
}

/* Password wrapper & inputs style */
.p-password {
  @apply w-full relative block;
}
.p-password .p-password-input {
  @apply bg-[var(--bg-elevated)] border border-[var(--border-primary)] text-[var(--text-primary)] placeholder-[var(--text-muted)] rounded-xl pl-4 pr-10 py-2.5 text-sm w-full;
}
.p-password-toggle-button,
.p-password-toggle-icon,
.p-password .p-password-toggle-button,
.p-password .p-password-toggle-icon {
  position: absolute !important;
  right: 1rem !important;
  top: 50% !important;
  transform: translateY(-50%) !important;
  cursor: pointer !important;
  z-index: 10 !important;
  background: transparent !important;
  border: none !important;
  outline: none !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  padding: 0 !important;
  box-shadow: none !important;
}

/* Select dropdown */
select {
  @apply bg-[var(--bg-elevated)] border border-[var(--border-primary)] text-[var(--text-primary)] rounded-xl px-3 py-2.5 text-sm focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 outline-none transition-all;
}

/* Textarea */
textarea {
  @apply bg-[var(--bg-elevated)] border border-[var(--border-primary)] text-[var(--text-primary)] placeholder-[var(--text-muted)] rounded-xl text-sm transition-all;
}
textarea:focus,
input:focus {
  @apply border-[var(--accent)] ring-1 ring-[var(--accent)] outline-none;
}
</style>
