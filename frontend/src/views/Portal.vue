<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';
import { useRouter } from 'vue-router';
import { useI18n } from 'vue-i18n';
import { authService, type User } from '../services/api';

const router = useRouter();
const { locale, t } = useI18n();

const currentUser = ref<User | null>(null);
const loading = ref(true);
const searchQuery = ref('');

const isAdmin = computed(() => {
  if (!currentUser.value) return false;
  return currentUser.value.username === 'admin' || 
         currentUser.value.roles?.some(r => r.name.toLowerCase() === 'admin' || r.name.toLowerCase() === 'system_admin') || 
         false;
});

const displayName = computed(() => {
  return currentUser.value?.display_name || currentUser.value?.username || '';
});

// Generate a 2-letter avatar text
const avatarText = computed(() => {
  const name = displayName.value;
  if (!name) return 'U';
  if (name.length <= 2) return name.toUpperCase();
  return name.slice(0, 2).toUpperCase();
});

onMounted(async () => {
  try {
    const data = await authService.me();
    currentUser.value = data;
  } catch (err) {
    console.error('Failed to fetch user info:', err);
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
    accentColor: '#10b981', // emerald
    gradientClass: 'from-emerald-500/20 via-teal-500/10 to-transparent',
    glowClass: 'hover:shadow-[0_0_30px_-5px_rgba(16,185,129,0.3)] hover:border-emerald-500/35',
    iconColor: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20 group-hover:bg-emerald-500/20 group-hover:border-emerald-500/40',
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
    accentColor: '#6366f1', // indigo
    gradientClass: 'from-indigo-500/20 via-purple-500/10 to-transparent',
    glowClass: 'hover:shadow-[0_0_30px_-5px_rgba(99,102,241,0.3)] hover:border-indigo-500/35',
    iconColor: 'text-indigo-400 bg-indigo-500/10 border-indigo-500/20 group-hover:bg-indigo-500/20 group-hover:border-indigo-500/40',
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
  <div class="portal-container min-h-screen bg-[#070a13] text-[#f1f5f9] relative overflow-hidden flex flex-col font-sans select-none">
    <!-- Premium background grid pattern -->
    <div class="grid-bg"></div>

    <!-- Glowing ambient background lights -->
    <div class="absolute top-[-10%] right-[-5%] w-[500px] h-[500px] bg-indigo-600/15 rounded-full blur-[120px] animate-pulse-slow"></div>
    <div class="absolute bottom-[-10%] left-[-5%] w-[500px] h-[500px] bg-purple-700/10 rounded-full blur-[120px] animate-pulse-medium"></div>
    <div class="absolute top-[30%] left-[20%] w-[350px] h-[350px] bg-emerald-500/5 rounded-full blur-[100px]"></div>

    <!-- Navigation Header -->
    <header class="w-full h-20 border-b border-white/5 bg-[#0b0f19]/60 backdrop-blur-xl flex items-center justify-between px-8 md:px-16 z-20 relative">
      <div class="flex items-center gap-3.5 group cursor-pointer">
        <div class="w-10 h-10 bg-gradient-to-tr from-indigo-500 via-purple-500 to-pink-500 rounded-2xl flex items-center justify-center shadow-lg shadow-indigo-500/20 border border-white/10 group-hover:rotate-6 transition-all duration-300">
          <i class="pi pi-shield text-white text-lg"></i>
        </div>
        <div class="flex flex-col">
          <span class="font-black text-lg tracking-wider bg-clip-text text-transparent bg-gradient-to-r from-slate-50 via-slate-100 to-indigo-200 heading-font">
            {{ t('portal.brandTitle') }}
          </span>
          <span class="text-[9px] text-[var(--text-muted)] tracking-[0.2em] font-extrabold uppercase mt-0.5">{{ t('portal.brandSubtitle') }}</span>
        </div>
      </div>

      <div class="flex items-center gap-6">
        <!-- Language Toggle -->
        <button @click="toggleLanguage" class="flex items-center gap-2 py-2 px-3.5 bg-white/[0.03] border border-white/5 hover:border-[var(--accent)] text-[var(--text-secondary)] hover:text-white rounded-xl font-bold text-xs uppercase transition-all shadow-md select-none backdrop-blur-sm">
          <i class="pi pi-globe text-xs"></i>
          <span>{{ locale === 'en' ? '中文' : 'EN' }}</span>
        </button>

        <!-- User Profile Card -->
        <div v-if="currentUser" class="flex items-center gap-4 border-l border-white/5 pl-6">
          <div class="flex flex-col items-end hidden sm:flex">
            <span class="text-sm font-extrabold text-slate-100 heading-font tracking-tight">{{ displayName }}</span>
            <span :class="[
              'text-[8px] font-black uppercase tracking-[0.18em] px-2.5 py-1 rounded-lg mt-1 border',
              isAdmin ? 'text-indigo-400 bg-indigo-500/10 border-indigo-500/20' : 'text-slate-400 bg-slate-500/10 border-slate-500/20'
            ]">
              {{ isAdmin ? t('portal.adminBadge') : t('portal.userBadge') }}
            </span>
          </div>

          <!-- Avatar with Gradient -->
          <div class="w-10 h-10 bg-gradient-to-tr from-indigo-500 via-purple-500 to-pink-500 rounded-2xl flex items-center justify-center font-black text-xs text-white shadow-md shadow-indigo-500/15 border border-white/15">
            {{ avatarText }}
          </div>

          <!-- Log Out Button -->
          <button @click="handleLogout" class="flex items-center justify-center w-10 h-10 bg-white/[0.03] border border-white/5 hover:border-rose-500/30 text-slate-400 hover:text-rose-400 rounded-2xl transition-all shadow-md backdrop-blur-sm" :title="t('portal.logout')">
            <i class="pi pi-power-off text-sm"></i>
          </button>
        </div>
      </div>
    </header>

    <!-- Main Section -->
    <main class="flex-grow flex flex-col items-center justify-center px-8 py-16 z-10 relative max-w-6xl mx-auto w-full">
      <!-- Title & Header -->
      <div class="text-center mb-16 max-w-3xl animate-fade-in">
        <h1 class="text-5xl md:text-6xl font-black tracking-tight leading-[1.15] bg-clip-text text-transparent bg-gradient-to-r from-slate-50 via-indigo-100 to-slate-200 heading-font">
          {{ t('portal.title') }}
        </h1>
        <p class="text-[var(--text-secondary)] mt-4 text-base font-medium max-w-2xl mx-auto leading-relaxed">
          {{ t('portal.subtitle') }}
        </p>

        <!-- Fancy Glowing Search Bar -->
        <div class="mt-10 max-w-lg mx-auto relative group">
          <div class="absolute inset-0 bg-gradient-to-r from-indigo-500 to-purple-600 rounded-[20px] blur-md opacity-25 group-focus-within:opacity-40 transition-opacity duration-300"></div>
          <div class="relative">
            <i class="pi pi-search absolute left-4.5 top-1/2 -translate-y-1/2 text-slate-500 group-focus-within:text-[var(--accent)] transition-colors"></i>
            <input 
              type="text" 
              v-model="searchQuery" 
              :placeholder="t('common.search')" 
              class="w-full pl-12 pr-5 py-4 bg-[#0c101c]/80 border border-white/10 rounded-[20px] text-sm text-slate-100 placeholder-slate-500 outline-none focus:border-[var(--accent)] focus:ring-0 backdrop-blur-xl transition-all shadow-xl"
            />
          </div>
        </div>
      </div>

      <!-- App Card Grid -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-8 w-full max-w-4xl px-4">
        <div 
          v-for="app in filteredApps" 
          :key="app.id" 
          :class="[
            'premium-card p-8 flex flex-col justify-between relative overflow-hidden transition-all duration-300 group border border-white/[0.04]',
            !app.available ? 'opacity-50 cursor-not-allowed border-dashed' : 'cursor-pointer hover:-translate-y-2',
            app.available ? app.glowClass : ''
          ]"
          @click="app.available && app.action()"
        >
          <!-- Radial ambient overlay inside card -->
          <div :class="['absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none bg-gradient-to-b', app.gradientClass]"></div>

          <div>
            <div class="flex items-start justify-between mb-6 relative z-10">
              <!-- Animated App Icon Container -->
              <div :class="['w-16 h-16 rounded-[22px] border flex items-center justify-center transition-all duration-300 shadow-md group-hover:scale-105', app.iconColor]">
                <i :class="[app.icon, 'text-3xl']"></i>
              </div>

              <!-- Premium Badges -->
              <div v-if="!app.available && app.requiresAdmin" class="flex items-center gap-1.5 py-1 px-3 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-400 font-extrabold text-[9px] uppercase tracking-wider">
                <i class="pi pi-lock text-[8px]"></i>
                <span>{{ t('common.disabled') }}</span>
              </div>
              <div v-else-if="app.available && app.requiresAdmin" class="flex items-center gap-1.5 py-1 px-3 bg-indigo-500/10 border border-indigo-500/20 rounded-lg text-indigo-400 font-extrabold text-[9px] uppercase tracking-wider">
                <i class="pi pi-key text-[9px]"></i>
                <span>{{ t('portal.adminBadgeLabel') }}</span>
              </div>
            </div>

            <!-- Header and Description -->
            <h3 class="text-2xl font-black text-slate-100 mb-3 group-hover:text-white transition-colors heading-font tracking-tight relative z-10">
              {{ app.name }}
            </h3>
            <p class="text-slate-400 text-sm leading-relaxed mb-8 font-medium relative z-10 group-hover:text-slate-300 transition-colors">
              {{ app.desc }}
            </p>
          </div>

          <!-- Bottom Actions -->
          <div class="flex items-center justify-between border-t border-white/[0.05] pt-5 mt-auto relative z-10">
            <span class="text-[10px] text-slate-500 font-bold uppercase tracking-widest group-hover:text-slate-400 transition-colors">
              {{ app.available ? t('portal.trustedBadge') : t('portal.unauthorizedBadge') }}
            </span>
            
            <div class="flex items-center gap-2 launch-btn">
              <span class="text-xs font-bold text-[var(--accent)] opacity-0 group-hover:opacity-100 transition-all duration-300 -translate-x-2 group-hover:translate-x-0">
                {{ app.available ? t('portal.openApp') : t('portal.locked') }}
              </span>
              <div :class="[
                'w-10 h-10 rounded-xl flex items-center justify-center transition-all duration-300',
                app.available 
                  ? 'bg-white/5 border border-white/10 text-white group-hover:bg-gradient-to-r group-hover:from-indigo-600 group-hover:to-purple-600 group-hover:border-transparent group-hover:shadow-lg group-hover:shadow-indigo-500/20' 
                  : 'bg-white/[0.02] border border-white/5 text-slate-600'
              ]">
                <i :class="[app.available ? 'pi pi-arrow-right group-hover:translate-x-0.5 transition-transform' : 'pi pi-lock', 'text-xs']"></i>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>

    <!-- Footer -->
    <footer class="w-full py-8 text-center text-xs text-slate-600 border-t border-white/5 bg-[#0b0f19]/20 relative z-20">
      {{ t('portal.footer') }}
    </footer>
  </div>
</template>

<style scoped>
/* Outfit Header font support */
.heading-font {
  font-family: 'Outfit', 'Inter', system-ui, sans-serif;
}

/* Background grid pattern */
.grid-bg {
  position: absolute;
  inset: 0;
  background-image: 
    linear-gradient(rgba(255, 255, 255, 0.007) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255, 255, 255, 0.007) 1px, transparent 1px);
  background-size: 50px 50px;
  background-position: center;
  mask-image: radial-gradient(circle at 50% 50%, black 30%, transparent 80%);
  -webkit-mask-image: radial-gradient(circle at 50% 50%, black 30%, transparent 80%);
  pointer-events: none;
}

/* Custom premium card design */
.premium-card {
  background: rgba(15, 22, 38, 0.65);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-radius: 28px;
  box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5);
  transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1);
}

.premium-card:hover {
  background: rgba(18, 26, 46, 0.8);
}

/* Animations */
@keyframes pulseSlow {
  0%, 100% { opacity: 0.8; transform: scale(1) translate(0, 0); }
  50% { opacity: 1; transform: scale(1.08) translate(10px, -10px); }
}

@keyframes pulseMedium {
  0%, 100% { opacity: 0.6; transform: scale(1) translate(0, 0); }
  50% { opacity: 0.8; transform: scale(1.12) translate(-15px, 15px); }
}

.animate-pulse-slow {
  animation: pulseSlow 12s infinite ease-in-out;
}

.animate-pulse-medium {
  animation: pulseMedium 10s infinite ease-in-out;
}

/* Focus helper overrides for inputs */
input:focus {
  box-shadow: 0 0 20px -2px rgba(129, 140, 248, 0.15) !important;
}
</style>
