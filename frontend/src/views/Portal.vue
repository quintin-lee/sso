<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';
import { useRouter } from 'vue-router';
import { useI18n } from 'vue-i18n';
import { authService, type User } from '../services/api';
import Button from 'primevue/button';

const router = useRouter();
const { locale, t } = useI18n();

const currentUser = ref<User | null>(null);
const loading = ref(true);
const searchQuery = ref('');

const isAdmin = computed(() => {
  if (!currentUser.value) return false;
  // Check if username is admin or has admin role
  return currentUser.value.username === 'admin' || 
         currentUser.value.roles?.some(r => r.name.toLowerCase() === 'admin' || r.name.toLowerCase() === 'system_admin') || 
         false;
});

const displayName = computed(() => {
  return currentUser.value?.display_name || currentUser.value?.username || '';
});

onMounted(async () => {
  try {
    const data = await authService.me();
    currentUser.value = data;
  } catch (err) {
    console.error('Failed to fetch user info:', err);
    // If not authenticated, authService interceptor will redirect to login
  } finally {
    loading.value = false;
  }
});

const toggleLanguage = () => {
  locale.value = locale.value === 'en' ? 'zh' : 'en';
  localStorage.setItem('locale', locale.value);
};

const handleLogout = async () => {
  try {
    await authService.logout();
    router.push('/login');
  } catch (err) {
    console.error('Logout failed:', err);
    router.push('/login');
  }
};

const apps = computed(() => [
  {
    id: 'gogs',
    name: t('portal.apps.gogs.name'),
    desc: t('portal.apps.gogs.desc'),
    url: '/gogs/',
    icon: 'pi pi-code',
    colorClass: 'from-emerald-500 to-teal-600 shadow-emerald-500/10',
    iconColor: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    action: () => {
      window.location.href = '/gogs/';
    },
    requiresAdmin: false,
    available: true
  },
  {
    id: 'admin',
    name: t('portal.apps.admin.name'),
    desc: t('portal.apps.admin.desc'),
    url: '/admin',
    icon: 'pi pi-sliders-h',
    colorClass: 'from-indigo-500 to-violet-600 shadow-indigo-500/10',
    iconColor: 'text-indigo-400 bg-indigo-500/10 border-indigo-500/20',
    action: () => {
      router.push('/admin');
    },
    requiresAdmin: true,
    available: isAdmin.value
  }
]);

const filteredApps = computed(() => {
  const q = searchQuery.value.toLowerCase().trim();
  if (!q) return apps.value;
  return apps.value.filter(app => 
    app.name.toLowerCase().includes(q) || 
    app.desc.toLowerCase().includes(q)
  );
});
</script>

<template>
  <div class="portal-container min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)] relative overflow-hidden flex flex-col">
    <!-- Glowing background decorative orbs -->
    <div class="absolute -top-40 -right-40 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pulse-neon"></div>
    <div class="absolute -bottom-40 -left-40 w-96 h-96 bg-violet-600/10 rounded-full blur-3xl"></div>

    <!-- Navigation Header -->
    <header class="w-full h-16 border-b border-[var(--border-primary)] bg-[var(--bg-secondary)]/50 backdrop-blur-xl flex items-center justify-between px-6 md:px-12 z-10 relative">
      <div class="flex items-center gap-3">
        <div class="w-9 h-9 bg-gradient-to-br from-indigo-500 to-violet-600 rounded-xl flex items-center justify-center shadow-lg border border-white/10">
          <i class="pi pi-shield text-white text-base"></i>
        </div>
        <span class="font-extrabold text-base tracking-wider bg-clip-text text-transparent bg-gradient-to-r from-slate-100 to-indigo-200">
          SSO PORTAL
        </span>
      </div>

      <div class="flex items-center gap-4">
        <!-- Language Toggle -->
        <button @click="toggleLanguage" class="flex items-center gap-1.5 py-1.5 px-3 bg-[var(--bg-elevated)] border border-[var(--border-primary)] hover:border-[var(--accent)] text-[var(--text-secondary)] hover:text-[var(--accent)] rounded-lg font-bold text-xs uppercase transition-all shadow-md select-none">
          <i class="pi pi-globe text-xs"></i>
          <span>{{ locale === 'en' ? '中文' : 'EN' }}</span>
        </button>

        <!-- User Profile Dropdown/Details -->
        <div v-if="currentUser" class="flex items-center gap-3 border-l border-[var(--border-primary)] pl-4">
          <div class="flex flex-col items-end hidden sm:flex">
            <span class="text-xs font-extrabold text-[var(--text-primary)]">{{ displayName }}</span>
            <span :class="[
              'text-[9px] font-extrabold uppercase tracking-widest px-2 py-0.5 rounded-md mt-0.5 border',
              isAdmin ? 'text-indigo-400 bg-indigo-500/10 border-indigo-500/20' : 'text-slate-400 bg-slate-500/10 border-slate-500/20'
            ]">
              {{ isAdmin ? t('portal.adminBadge') : t('portal.userBadge') }}
            </span>
          </div>

          <button @click="handleLogout" class="flex items-center justify-center w-9 h-9 bg-[var(--bg-elevated)] border border-[var(--border-primary)] hover:border-rose-500/40 text-[var(--text-secondary)] hover:text-rose-400 rounded-xl transition-all shadow-md" :title="t('portal.logout')">
            <i class="pi pi-power-off text-sm"></i>
          </button>
        </div>
      </div>
    </header>

    <!-- Main Content -->
    <main class="flex-grow flex flex-col items-center justify-center px-6 py-12 z-0 relative max-w-5xl mx-auto w-full">
      <!-- Welcome Header -->
      <div class="text-center mb-10 max-w-2xl animate-fade-in">
        <h1 class="text-4xl md:text-5xl font-extrabold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-slate-50 via-slate-100 to-indigo-200">
          {{ t('portal.title') }}
        </h1>
        <p class="text-[var(--text-secondary)] mt-3 text-sm md:text-base font-medium leading-relaxed">
          {{ t('portal.subtitle') }}
        </p>

        <!-- Search Bar -->
        <div class="mt-8 max-w-md mx-auto relative group">
          <i class="pi pi-search absolute left-4 top-1/2 -translate-y-1/2 text-[var(--text-muted)] group-focus-within:text-[var(--accent)] transition-colors"></i>
          <input 
            type="text" 
            v-model="searchQuery" 
            :placeholder="t('common.search')" 
            class="w-full pl-11 pr-4 py-3 bg-[var(--bg-elevated)]/50 border border-[var(--border-primary)] rounded-2xl text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] outline-none focus:border-[var(--accent)] focus:ring-1 focus:ring-[var(--accent)]/30 backdrop-blur-md transition-all shadow-lg"
          />
        </div>
      </div>

      <!-- Apps Grid -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-8 w-full max-w-4xl px-4">
        <div 
          v-for="app in filteredApps" 
          :key="app.id" 
          :class="[
            'glass-card p-6 flex flex-col justify-between relative overflow-hidden transition-all duration-300 group',
            !app.available ? 'opacity-65 cursor-not-allowed border-dashed border-red-500/20' : 'cursor-pointer hover:-translate-y-1'
          ]"
          @click="app.available && app.action()"
        >
          <!-- Icon & Info -->
          <div>
            <div class="flex items-start justify-between mb-5">
              <!-- App Icon -->
              <div :class="['w-14 h-14 rounded-2xl border flex items-center justify-center transition-all duration-300 group-hover:scale-110 shadow-md', app.iconColor]">
                <i :class="[app.icon, 'text-2xl']"></i>
              </div>

              <!-- Status Badge -->
              <div v-if="!app.available && app.requiresAdmin" class="flex items-center gap-1.5 py-1 px-2.5 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-400 font-bold text-[10px] uppercase tracking-wider">
                <i class="pi pi-lock text-[9px]"></i>
                <span>{{ t('common.disabled') }}</span>
              </div>
              <div v-else-if="app.available && app.requiresAdmin" class="flex items-center gap-1.5 py-1 px-2.5 bg-indigo-500/10 border border-indigo-500/20 rounded-lg text-indigo-400 font-bold text-[10px] uppercase tracking-wider">
                <i class="pi pi-key text-[9px]"></i>
                <span>ADMIN</span>
              </div>
            </div>

            <!-- Text Content -->
            <h3 class="text-xl font-bold text-[var(--text-primary)] mb-2 group-hover:text-[var(--accent)] transition-colors">
              {{ app.name }}
            </h3>
            <p class="text-[var(--text-secondary)] text-sm leading-relaxed mb-6 font-medium">
              {{ app.desc }}
            </p>
          </div>

          <!-- Action Button -->
          <div class="flex items-center justify-between border-t border-[var(--border-primary)]/40 pt-4 mt-auto">
            <span class="text-xs text-[var(--text-muted)] font-semibold group-hover:text-[var(--text-secondary)] transition-colors">
              {{ app.available ? 'SSO ACTIVE' : 'LOCKED' }}
            </span>
            <Button 
              :label="app.available ? t('portal.openApp') : 'Locked'"
              :disabled="!app.available"
              :icon="app.available ? 'pi pi-arrow-right' : 'pi pi-lock'"
              iconPos="right"
              :class="[
                '!py-2.5 !px-4.5 !text-xs !font-bold !rounded-xl !border-none !shadow-sm !transition-all',
                app.available 
                  ? '!bg-indigo-600 hover:!bg-indigo-500 !text-white active:!scale-95' 
                  : '!bg-[var(--bg-secondary)] !text-[var(--text-muted)]'
              ]"
            />
          </div>

          <!-- Decorative Ambient Background Gradient inside card -->
          <div :class="['absolute -bottom-16 -right-16 w-32 h-32 rounded-full blur-2xl opacity-0 group-hover:opacity-10 transition-opacity duration-500 bg-gradient-to-br', app.colorClass]"></div>
        </div>
      </div>
    </main>

    <!-- Footer -->
    <footer class="w-full py-6 text-center text-xs text-[var(--text-muted)] border-t border-[var(--border-primary)] relative z-10">
      &copy; 2026 Enterprise SSO. All rights reserved.
    </footer>
  </div>
</template>

<style scoped>
/* Extra page animations */
.portal-container {
  background-image:
    radial-gradient(at 15% 0%, rgba(99, 102, 241, 0.05) 0px, transparent 50%),
    radial-gradient(at 85% 100%, rgba(129, 140, 248, 0.03) 0px, transparent 50%);
}
</style>
