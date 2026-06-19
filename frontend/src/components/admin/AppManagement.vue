<template>
  <div class="bg-[var(--bg-card)] rounded-2xl border border-[var(--border-primary)] overflow-hidden">
    <DataTable :value="displayedApps" paginator :rows="10" :totalRecords="totalApps" lazy @page="onAppPage" :loading="loading" class="p-datatable-sm">
      <Column field="app_name" :header="$t('apps.appName')" class="font-semibold">
        <template #body="slotProps">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center overflow-hidden flex-shrink-0">
              <img v-if="slotProps.data.app_logo_url" :src="slotProps.data.app_logo_url" class="w-full h-full object-cover" alt="Logo" @error="handleLogoError" />
              <i v-else class="pi pi-desktop text-indigo-400 text-lg"></i>
            </div>
            <div>
              <div class="text-[var(--text-primary)] text-sm font-bold">{{ slotProps.data.app_name || slotProps.data.client_id }}</div>
              <div class="text-xs text-[var(--text-muted)] line-clamp-1 max-w-[250px]">{{ slotProps.data.app_description }}</div>
            </div>
          </div>
        </template>
      </Column>
      <Column field="client_id" :header="$t('apps.clientId')" class="font-mono text-xs text-[var(--text-primary)]"></Column>
      <Column field="redirect_uris" :header="$t('apps.redirectUris')" class="max-w-[200px]">
        <template #body="slotProps">
          <div class="flex flex-col gap-1">
            <span v-for="uri in splitUris(slotProps.data.redirect_uris)" :key="uri" class="text-xs font-mono bg-[var(--bg-elevated)] border border-[var(--border-primary)] rounded px-1.5 py-0.5 text-[var(--text-muted)] truncate max-w-xs" :title="uri">
              {{ uri }}
            </span>
          </div>
        </template>
      </Column>
      <Column field="allowed_scopes" :header="$t('apps.allowedScopes')">
        <template #body="slotProps">
          <div class="flex flex-wrap gap-1 max-w-[150px]">
            <span v-for="scope in splitScopes(slotProps.data.allowed_scopes)" :key="scope" class="text-[10px] font-semibold bg-violet-500/10 text-violet-400 border border-violet-500/20 rounded px-1 py-0.2">
              {{ scope }}
            </span>
          </div>
        </template>
      </Column>
      <Column field="status" :header="$t('apps.status')">
        <template #body="slotProps">
          <span :class="statusBadgeClass(slotProps.data.status)">
            {{ slotProps.data.status === 1 ? $t('common.active') : $t('common.disabled') }}
          </span>
        </template>
      </Column>
      <Column :header="$t('common.actions')" class="w-32">
        <template #body="slotProps">
          <div class="flex gap-1 justify-end">
            <Button icon="pi pi-pencil" text rounded severity="secondary" @click="editApp(slotProps.data)" />
            <Button icon="pi pi-trash" text rounded severity="danger" @click="confirmDeleteApp(slotProps.data)" />
          </div>
        </template>
      </Column>
      <!-- Empty State -->
      <template #empty>
        <div class="flex flex-col items-center justify-center py-16 text-[var(--text-muted)]">
          <i class="pi pi-desktop text-4xl mb-3 opacity-40"></i>
          <p class="text-sm font-medium">{{ locale === 'zh' ? '没有找到应用' : 'No applications found' }}</p>
          <p class="text-xs mt-1 opacity-60">{{ locale === 'zh' ? '点击添加来创建一个新应用' : 'Click Add to register a new application' }}</p>
        </div>
      </template>
    </DataTable>

    <Dialog v-model:visible="appDialog" :header="app.id ? $t('apps.update') : $t('apps.create')" modal class="w-full max-w-xl">
       <div class="space-y-4">
         <div class="grid grid-cols-2 gap-4">
           <div class="flex flex-col gap-1.5 col-span-2 md:col-span-1">
               <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('apps.appName') }}</label>
               <InputText v-model.trim="app.app_name" placeholder="My Enterprise App" autofocus />
           </div>
           <div class="flex flex-col gap-1.5 col-span-2 md:col-span-1">
               <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('apps.clientId') }}</label>
               <InputText v-model.trim="app.client_id" placeholder="my_enterprise_app" :disabled="!!app.id" />
           </div>
         </div>

         <div class="flex flex-col gap-1.5">
             <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('apps.clientSecret') }}</label>
             <div class="flex gap-2">
               <Password v-model="app.client_secret" :feedback="false" :placeholder="app.id ? '••••••••' : 'Enter or generate client secret'" toggleMask class="w-full flex-grow" inputClass="w-full !bg-[var(--bg-elevated)] !border-[var(--border-primary)] !text-[var(--text-primary)] !placeholder-[var(--text-muted)] !rounded-lg !px-4 !py-3 hover:!border-[var(--accent)] transition-all" />
               <Button icon="pi pi-key" @click="generateSecret" class="p-button-outlined !border-[var(--border-primary)] hover:!border-[var(--accent)] !rounded-lg !text-[var(--text-secondary)] hover:!text-[var(--accent)]" title="Generate Secret" />
             </div>
             <small class="text-[11px] text-[var(--text-muted)] mt-0.5">{{ $t('apps.clientSecretHelp') }}</small>
         </div>

         <div class="flex flex-col gap-1.5">
             <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('apps.redirectUris') }}</label>
             <InputText v-model.trim="app.redirect_uris" placeholder="http://localhost:8080/callback,http://127.0.0.1:8080/callback" />
             <small class="text-[11px] text-[var(--text-muted)] mt-0.5">{{ $t('apps.redirectUrisHelp') }}</small>
         </div>

         <div class="grid grid-cols-2 gap-4">
           <div class="flex flex-col gap-1.5 col-span-2 md:col-span-1">
               <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('apps.appLogoUrl') }}</label>
               <InputText v-model.trim="app.app_logo_url" placeholder="https://example.com/logo.png" />
           </div>
           <div class="flex flex-col gap-1.5 col-span-2 md:col-span-1">
               <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('apps.tokenTtl') }}</label>
               <input type="number" v-model.number="app.token_ttl_ms" class="p-inputtext w-full" placeholder="3600000" />
           </div>
         </div>

         <div class="grid grid-cols-2 gap-4">
           <div class="flex flex-col gap-1.5 col-span-2 md:col-span-1">
               <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('apps.allowedScopes') }}</label>
               <InputText v-model.trim="app.allowed_scopes" placeholder="openid,profile,email" />
           </div>
           <div class="flex flex-col gap-1.5 col-span-2 md:col-span-1">
               <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('apps.allowedGrantTypes') }}</label>
               <InputText v-model.trim="app.allowed_grant_types" placeholder="authorization_code,refresh_token" />
           </div>
         </div>

         <div class="flex flex-col gap-1.5">
             <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('apps.appDescription') }}</label>
             <textarea v-model.trim="app.app_description" rows="3" class="w-full !font-sans text-sm" placeholder="Briefly describe the application."></textarea>
         </div>

         <div class="flex items-center gap-2 mt-4">
             <Checkbox v-model="appStatus" :binary="true" inputId="appStatus" />
             <label for="appStatus" class="text-sm font-semibold text-[var(--text-primary)]">{{ $t('common.active') }}</label>
         </div>
       </div>
        <template #footer>
           <div class="flex gap-2 justify-end">
              <Button :label="$t('common.cancel')" text severity="secondary" @click="appDialog = false" class="!rounded-lg !text-[var(--text-secondary)] hover:!text-[var(--text-primary)]" />
              <Button :label="$t('common.save')" @click="saveApp" class="!rounded-lg !px-6 !bg-[var(--accent-strong)] hover:!bg-[var(--accent)] !text-white !border-none" />
           </div>
        </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';
import { useI18n } from 'vue-i18n';
import { clientService, type OAuthClient } from '../../services/api';
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import Button from 'primevue/button';
import Dialog from 'primevue/dialog';
import InputText from 'primevue/inputtext';
import Password from 'primevue/password';
import Checkbox from 'primevue/checkbox';
import { useToast } from 'primevue/usetoast';
import { useConfirm } from 'primevue/useconfirm';

const props = defineProps<{ search?: string }>();

const { t, locale } = useI18n();
const toast = useToast();
const loading = ref(false);
const apps = ref<OAuthClient[]>([]);
const totalApps = ref(0);

const displayedApps = computed(() => {
  const q = (props.search || '').toLowerCase().trim();
  if (!q) return apps.value;
  return apps.value.filter(a =>
    (a.client_id || '').toLowerCase().includes(q) ||
    (a.app_name || '').toLowerCase().includes(q) ||
    (a.app_description || '').toLowerCase().includes(q) ||
    (a.redirect_uris || '').toLowerCase().includes(q)
  );
});

const appDialog = ref(false);
const app = ref<Partial<OAuthClient> & { client_secret?: string }>({});

const appStatus = computed({
  get: () => app.value.status === 1,
  set: (val) => app.value.status = val ? 1 : 0
});

const statusBadgeClass = (status: number) => [
  'px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider',
  status === 1 ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400'
];

const splitUris = (uris: string) => {
  if (!uris) return [];
  return uris.split(',').map(u => u.trim()).filter(Boolean);
};

const splitScopes = (scopes: string) => {
  if (!scopes) return [];
  return scopes.split(',').map(s => s.trim()).filter(Boolean);
};

const handleLogoError = (e: Event) => {
  const target = e.target as HTMLImageElement;
  target.style.display = 'none';
};

const loadApps = async (page = 1) => {
  loading.value = true;
  try {
    const res = await clientService.listClients(page);
    apps.value = res.items;
    totalApps.value = res.total;
  } catch (err) {
    toast.add({ severity: 'error', summary: t('common.error'), detail: 'Failed to load applications', life: 3000 });
  } finally {
    loading.value = false;
  }
};

const onAppPage = (event: any) => {
  loadApps(event.page + 1);
};

const openCreateDialog = () => {
  app.value = {
    status: 1,
    token_ttl_ms: 3600000,
    allowed_scopes: 'openid,profile,email',
    allowed_grant_types: 'authorization_code,refresh_token'
  };
  appDialog.value = true;
};

const editApp = (data: OAuthClient) => {
  app.value = { ...data, client_secret: '' }; // Leave secret empty by default
  appDialog.value = true;
};

const generateSecret = () => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let result = '';
  const randomValues = new Uint32Array(32);
  window.crypto.getRandomValues(randomValues);
  for (let i = 0; i < 32; i++) {
    result += chars[randomValues[i] % chars.length];
  }
  app.value.client_secret = result;
};

const saveApp = async () => {
  // Validations
  if (!app.value.client_id || app.value.client_id.trim().length < 2) {
    toast.add({
      severity: 'error',
      summary: t('common.error'),
      detail: locale.value === 'zh' ? '客户端 ID (Client ID) 至少需要2个字符' : 'Client ID must be at least 2 characters long',
      life: 3000
    });
    return;
  }

  if (!app.value.app_name || app.value.app_name.trim().length < 2) {
    toast.add({
      severity: 'error',
      summary: t('common.error'),
      detail: locale.value === 'zh' ? '应用名称至少需要2个字符' : 'App Name must be at least 2 characters long',
      life: 3000
    });
    return;
  }

  if (!app.value.redirect_uris || app.value.redirect_uris.trim().length === 0) {
    toast.add({
      severity: 'error',
      summary: t('common.error'),
      detail: locale.value === 'zh' ? '重定向 URI 不能为空' : 'Redirect URIs cannot be empty',
      life: 3000
    });
    return;
  }

  if (!app.value.id && (!app.value.client_secret || app.value.client_secret.trim().length < 8)) {
    toast.add({
      severity: 'error',
      summary: t('common.error'),
      detail: locale.value === 'zh' ? '新应用的客户端密钥 (Client Secret) 至少需要8位' : 'Client Secret for new apps must be at least 8 characters long',
      life: 3000
    });
    return;
  }

  try {
    if (app.value.id) {
      const payload = { ...app.value };
      if (!payload.client_secret || payload.client_secret.trim() === '') {
        delete payload.client_secret;
      }
      await clientService.updateClient(app.value.client_id!, payload);
      toast.add({ severity: 'success', summary: t('common.success'), detail: 'Application updated successfully', life: 3000 });
    } else {
      await clientService.createClient(app.value as any);
      toast.add({ severity: 'success', summary: t('common.success'), detail: 'Application created successfully', life: 3000 });
    }
    appDialog.value = false;
    loadApps();
  } catch (err) {
    toast.add({ severity: 'error', summary: t('common.error'), detail: 'Failed to save application', life: 3000 });
  }
};

const confirm = useConfirm();

const confirmDeleteApp = (data: OAuthClient) => {
  confirm.require({
    message: t('apps.deleteConfirm', { name: data.app_name || data.client_id }),
    header: t('common.confirmDelete'),
    icon: 'pi pi-exclamation-triangle',
    rejectLabel: t('common.cancel'),
    acceptLabel: t('common.delete'),
    rejectClass: 'p-button-text p-button-sm',
    acceptClass: 'p-button-danger p-button-sm',
    accept: async () => {
      try {
        await clientService.deleteClient(data.client_id);
        toast.add({ severity: 'success', summary: t('common.success'), detail: 'Application deleted successfully', life: 3000 });
        loadApps();
      } catch (err) {
        toast.add({ severity: 'error', summary: t('common.error'), detail: 'Failed to delete application', life: 3000 });
      }
    }
  });
};

onMounted(() => {
  loadApps();
});

defineExpose({
  openCreateDialog
});
</script>
