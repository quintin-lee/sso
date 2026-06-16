<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { authService } from '../services/api';
import InputText from 'primevue/inputtext';
import Password from 'primevue/password';
import Button from 'primevue/button';
import Message from 'primevue/message';

const router = useRouter();
const username = ref('');
const password = ref('');
const mfaCode = ref('');
const mfaToken = ref('');
const showMfa = ref(false);
const error = ref('');
const loading = ref(false);

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
    error.value = err.response?.data?.message || 'Login failed. Please check your credentials.';
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
    error.value = err.response?.data?.message || 'Invalid MFA code.';
  } finally {
    loading.value = false;
  }
};
</script>

<template>
  <div class="login-container flex items-center justify-center min-h-screen bg-slate-950">
    <div class="login-card w-full max-w-md p-8 bg-slate-900 border border-slate-800 shadow-2xl rounded-lg">
      <div class="text-center mb-8">
        <h1 class="text-3xl font-bold text-white tracking-tight uppercase">SSO Authentication</h1>
        <p class="text-slate-400 text-sm mt-2">Secure Gateway Access</p>
      </div>

      <form v-if="!showMfa" @submit.prevent="handleLogin" class="space-y-6">
        <div class="flex flex-col gap-2">
          <label for="username" class="text-xs font-semibold text-slate-500 uppercase tracking-widest">Username</label>
          <InputText 
            id="username" 
            v-model="username" 
            placeholder="Enter username" 
            class="w-full bg-slate-800 border-slate-700 text-white focus:border-blue-500 transition-colors"
            required 
          />
        </div>

        <div class="flex flex-col gap-2">
          <label for="password" class="text-xs font-semibold text-slate-500 uppercase tracking-widest">Password</label>
          <Password 
            id="password" 
            v-model="password" 
            :feedback="false" 
            placeholder="Enter password" 
            toggleMask 
            class="w-full"
            inputClass="w-full bg-slate-800 border-slate-700 text-white focus:border-blue-500 transition-colors"
            required 
          />
        </div>

        <Message v-if="error" severity="error" variant="simple" size="small" class="bg-red-900/20 border-red-800 text-red-400">
          {{ error }}
        </Message>

        <Button 
          type="submit" 
          label="Sign In" 
          :loading="loading" 
          class="w-full bg-blue-600 hover:bg-blue-500 border-none py-3 font-bold uppercase tracking-widest" 
        />
      </form>

      <form v-else @submit.prevent="handleMfaVerify" class="space-y-6">
        <div class="text-center mb-4">
          <p class="text-slate-300">Two-Factor Authentication required</p>
        </div>

        <div class="flex flex-col gap-2">
          <label for="mfaCode" class="text-xs font-semibold text-slate-500 uppercase tracking-widest">Verification Code</label>
          <InputText 
            id="mfaCode" 
            v-model="mfaCode" 
            placeholder="000000" 
            class="w-full text-center text-2xl tracking-[1em] bg-slate-800 border-slate-700 text-white focus:border-blue-500 transition-colors"
            required 
            maxlength="6"
            autofocus
          />
        </div>

        <Message v-if="error" severity="error" variant="simple" size="small" class="bg-red-900/20 border-red-800 text-red-400">
          {{ error }}
        </Message>

        <Button 
          type="submit" 
          label="Verify Code" 
          :loading="loading" 
          class="w-full bg-emerald-600 hover:bg-emerald-500 border-none py-3 font-bold uppercase tracking-widest" 
        />
        
        <button 
          type="button" 
          @click="showMfa = false" 
          class="w-full text-slate-500 text-xs hover:text-slate-300 transition-colors uppercase tracking-widest"
        >
          Back to Login
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
