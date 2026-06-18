<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { useI18n } from 'vue-i18n';
import { authService } from '../services/api';
import InputText from 'primevue/inputtext';
import Password from 'primevue/password';
import Button from 'primevue/button';
import Message from 'primevue/message';

const router = useRouter();
const { locale, t } = useI18n();

const username = ref('');
const password = ref('');
const mfaCode = ref('');
const mfaToken = ref('');
const showMfa = ref(false);
const error = ref('');
const loading = ref(false);

const toggleLanguage = () => {
  locale.value = locale.value === 'en' ? 'zh' : 'en';
  localStorage.setItem('locale', locale.value);
};

const handleLogin = async () => {
  error.value = '';
  loading.value = true;
  try {
    const res = await authService.login(username.value, password.value);
    if (res.mfa_required && res.mfa_token) {
      mfaToken.value = res.mfa_token;
      showMfa.value = true;
    } else {
      router.push('/');
    }
  } catch (err: any) {
    error.value = err.response?.data?.message || t('login.failed');
  } finally {
    loading.value = false;
  }
};

const handleMfaVerify = async () => {
  error.value = '';
  loading.value = true;
  try {
    await authService.mfaVerify(mfaToken.value, mfaCode.value);
    router.push('/');
  } catch (err: any) {
    error.value = err.response?.data?.message || t('login.mfaFailed');
  } finally {
    loading.value = false;
  }
};
</script>

<template>
  <div class="login-container flex items-center justify-center min-h-screen bg-[var(--bg-primary)] relative overflow-hidden">
    <!-- Glowing background decorative orbs -->
    <div class="absolute -top-40 -right-40 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pulse-neon"></div>
    <div class="absolute -bottom-40 -left-40 w-96 h-96 bg-violet-600/10 rounded-full blur-3xl"></div>

    <!-- Language Toggle -->
    <div class="absolute top-6 right-6 z-10">
      <button @click="toggleLanguage" class="flex items-center gap-2 py-2.5 px-3 bg-[var(--bg-elevated)] border border-[var(--border-primary)] hover:border-[var(--accent)] text-[var(--text-secondary)] hover:text-[var(--accent)] rounded-xl font-bold text-xs uppercase transition-all select-none shadow-xl">
        <i class="pi pi-globe text-sm"></i>
        <span>{{ locale === 'en' ? '中文' : 'EN' }}</span>
      </button>
    </div>

    <!-- Glassmorphic Login Card -->
    <div class="glass-card w-full max-w-md p-8 relative z-0 backdrop-blur-xl animate-fade-in">
      <!-- Brand -->
      <div class="text-center mb-8">
        <div class="w-14 h-14 bg-gradient-to-br from-indigo-500 via-purple-500 to-violet-600 rounded-2xl flex items-center justify-center mx-auto mb-5 shadow-lg shadow-indigo-500/30 border border-white/10 hover:rotate-6 transition-transform duration-300">
          <i class="pi pi-shield text-white text-2xl"></i>
        </div>
        <h1 class="text-3xl font-extrabold bg-clip-text text-transparent bg-gradient-to-r from-slate-100 via-indigo-200 to-violet-300 tracking-tight">{{ $t('login.title') }}</h1>
        <p class="text-[var(--text-secondary)] text-sm mt-1.5 font-medium">{{ $t('login.subtitle') }}</p>
      </div>

      <!-- Login Form -->
      <form v-if="!showMfa" @submit.prevent="handleLogin" class="space-y-5">
        <div class="flex flex-col gap-1.5">
          <label for="username" class="text-[11px] font-bold text-[var(--text-secondary)] uppercase tracking-[0.12em]">{{ $t('login.username') }}</label>
          <InputText
            id="username"
            v-model="username"
            :placeholder="$t('login.usernamePlaceholder')"
            class="!bg-[var(--bg-elevated)]/60 !border-[var(--border-primary)] !text-[var(--text-primary)] !placeholder-[var(--text-muted)] !rounded-xl !px-4 !py-3 hover:!border-[var(--accent)] transition-all"
            required
          />
        </div>

        <div class="flex flex-col gap-1.5">
          <label for="password" class="text-[11px] font-bold text-[var(--text-secondary)] uppercase tracking-[0.12em]">{{ $t('login.password') }}</label>
          <Password
            id="password"
            v-model="password"
            :feedback="false"
            :placeholder="$t('login.passwordPlaceholder')"
            toggleMask
            class="w-full"
            inputClass="w-full !bg-[var(--bg-elevated)]/60 !border-[var(--border-primary)] !text-[var(--text-primary)] !placeholder-[var(--text-muted)] !rounded-xl !px-4 !py-3 hover:!border-[var(--accent)] transition-all"
            required
          />
        </div>

        <Message v-if="error" severity="error" variant="simple" size="small" class="!bg-rose-500/10 !border-rose-500/20 !text-rose-400 !rounded-xl">
          {{ error }}
        </Message>

        <Button
          type="submit"
          :label="$t('login.signIn')"
          :loading="loading"
          class="!w-full !bg-indigo-600 hover:!bg-indigo-500 !border-none !py-3 !font-extrabold !tracking-wider !text-sm !uppercase !rounded-xl !shadow-lg !shadow-indigo-500/20 !transition-all !duration-200 active:!scale-[0.98] border border-white/5"
        />
      </form>

      <!-- MFA Form -->
      <form v-else @submit.prevent="handleMfaVerify" class="space-y-5">
        <div class="text-center mb-4">
          <div class="w-12 h-12 bg-amber-500/10 rounded-2xl flex items-center justify-center mx-auto mb-4 border border-amber-500/20">
            <i class="pi pi-shield text-amber-400 text-xl"></i>
          </div>
          <h2 class="text-lg font-extrabold text-[var(--text-primary)] tracking-tight mb-1">{{ $t('login.mfaTitle') }}</h2>
          <p class="text-[var(--text-secondary)] text-sm">{{ $t('login.mfaSubtitle') }}</p>
        </div>

        <div class="flex flex-col gap-1.5">
          <label for="mfaCode" class="text-[11px] font-bold text-[var(--text-secondary)] uppercase tracking-[0.12em] text-center">{{ $t('login.mfaCode') }}</label>
          <InputText
            id="mfaCode"
            v-model="mfaCode"
            :placeholder="$t('login.mfaPlaceholder')"
            class="!text-center !text-2xl !tracking-[0.3em] !bg-[var(--bg-elevated)]/60 !border-[var(--border-primary)] !text-[var(--text-primary)] !placeholder-[var(--text-muted)] !rounded-xl !px-4 !py-3 hover:!border-[var(--accent)] transition-all"
            required
            maxlength="6"
            autofocus
          />
        </div>

        <Message v-if="error" severity="error" variant="simple" size="small" class="!bg-rose-500/10 !border-rose-500/20 !text-rose-400 !rounded-xl">
          {{ error }}
        </Message>

        <Button
          type="submit"
          :label="$t('login.verify')"
          :loading="loading"
          class="!w-full !bg-emerald-600 hover:!bg-emerald-500 !border-none !py-3 !font-extrabold !tracking-wider !text-sm !uppercase !rounded-xl !shadow-lg !shadow-emerald-500/20 !transition-all !duration-200 active:!scale-[0.98] border border-white/5"
        />

        <button
          type="button"
          @click="showMfa = false"
          class="w-full text-[var(--text-muted)] text-xs hover:text-[var(--text-secondary)] transition-colors uppercase tracking-widest font-semibold"
        >
          {{ $t('login.back') }}
        </button>
      </form>
    </div>
  </div>
</template>

<style scoped>
:deep(.p-inputtext) {
  padding: 0.75rem 1rem;
}
:deep(.p-password-input) {
  padding: 0.75rem 1rem;
}
</style>
