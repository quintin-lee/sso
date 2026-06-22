<template>
  <div class="bg-[var(--bg-card)] rounded-2xl border border-[var(--border-primary)] overflow-hidden p-6">
    <h3 class="text-lg font-bold mb-4 text-[var(--text-primary)]">{{ $t('policySimulator.title') }}</h3>
    
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <!-- Input Panel -->
      <div class="space-y-4">
        <!-- Strategy Selector -->
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('policySimulator.strategy') }}</label>
          <Dropdown v-model="selectedStrategy" :options="strategies" optionLabel="name" optionValue="value" class="w-full" />
        </div>
        
        <!-- User Context -->
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('policySimulator.user') }}</label>
          <Dropdown v-model="selectedUser" :options="users" optionLabel="username" optionValue="id" class="w-full" :placeholder="$t('policySimulator.selectUser')" />
        </div>
        
        <!-- Dynamic Params Based on Strategy -->
        <div v-if="selectedStrategy === 'api'" class="space-y-3">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('policySimulator.httpMethod') }}</label>
            <SelectButton v-model="apiMethod" :options="['GET', 'POST', 'PUT', 'DELETE']" />
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('policySimulator.path') }}</label>
            <InputText v-model="apiPath" placeholder="/api/v1/users" />
          </div>
        </div>
        
        <div v-else-if="selectedStrategy === 'functional'" class="space-y-3">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('policySimulator.functionCode') }}</label>
            <InputText v-model="funcCode" placeholder="user:create" />
          </div>
        </div>
        
        <div v-else-if="selectedStrategy === 'rbac'" class="space-y-3">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('policySimulator.roleName') }}</label>
            <InputText v-model="rbacRole" placeholder="admin" />
          </div>
        </div>
        
        <Button :label="$t('policySimulator.test')" @click="runSimulation" :loading="loading" class="w-full !bg-[var(--accent-strong)] hover:!bg-[var(--accent)] !text-white !border-none !rounded-lg" />
      </div>
      
      <!-- Results Panel -->
      <div class="bg-[var(--bg-hover)] rounded-xl p-4 space-y-4 min-h-[300px]">
        <h4 class="text-sm font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('policySimulator.results') }}</h4>
        
        <div v-if="!result && !loading" class="flex flex-col items-center justify-center h-48 text-[var(--text-muted)]">
          <i class="pi pi-play-circle text-4xl mb-3 opacity-40"></i>
          <p class="text-sm">{{ $t('policySimulator.noResults') }}</p>
        </div>
        
        <div v-else-if="loading" class="flex flex-col items-center justify-center h-48">
          <ProgressSpinner />
          <p class="text-sm text-[var(--text-muted)] mt-2">{{ $t('policySimulator.testing') }}</p>
        </div>
        
        <div v-else-if="result" class="space-y-3">
          <!-- Decision Badge -->
          <div class="flex items-center gap-3">
            <span class="text-sm font-bold text-[var(--text-secondary)]">{{ $t('policySimulator.decision') }}:</span>
            <Badge :value="result.allowed ? $t('policySimulator.allow') : $t('policySimulator.deny')" 
                   :severity="result.allowed ? 'success' : 'danger'" 
                   class="text-sm font-bold" />
          </div>
          
          <!-- Cache Info -->
          <div class="flex items-center gap-3">
            <span class="text-sm font-bold text-[var(--text-secondary)]">{{ $t('policySimulator.cache') }}:</span>
            <Tag :value="result.cache_hit ? 'HIT' : 'MISS'" :severity="result.cache_hit ? 'info' : 'warning'" class="text-xs" />
          </div>
          
          <!-- Duration -->
          <div class="flex items-center gap-3">
            <span class="text-sm font-bold text-[var(--text-secondary)]">{{ $t('policySimulator.duration') }}:</span>
            <span class="text-sm font-mono text-[var(--text-primary)]">{{ result.duration_ms }}ms</span>
          </div>
          
          <!-- Matched Policies -->
          <div v-if="result.matched_policies && result.matched_policies.length > 0" class="mt-4">
            <h5 class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-2">{{ $t('policySimulator.matchedPolicies') }}</h5>
            <div class="space-y-2">
              <div v-for="policy in result.matched_policies" :key="policy.id" 
                   class="bg-[var(--bg-card)] rounded-lg p-3 border border-[var(--border-primary)]">
                <div class="flex items-center justify-between">
                  <span class="text-sm font-semibold text-[var(--text-primary)]">{{ policy.name }}</span>
                  <Tag :value="policy.effect" :severity="policy.effect === 'allow' ? 'success' : 'danger'" class="text-xs" />
                </div>
                <div class="text-xs text-[var(--text-muted)] mt-1">{{ policy.strategy }} | {{ $t('policySimulator.priority') }}: {{ policy.priority }}</div>
              </div>
            </div>
          </div>
          
          <!-- Trace -->
          <div v-if="result.trace" class="mt-4">
            <h5 class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-2">{{ $t('policySimulator.trace') }}</h5>
            <pre class="bg-[var(--bg-card)] rounded-lg p-3 text-xs font-mono text-[var(--text-muted)] overflow-x-auto">{{ result.trace }}</pre>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useI18n } from 'vue-i18n';
import { adminService } from '../../services/api';
import Dropdown from 'primevue/dropdown';
import InputText from 'primevue/inputtext';
import Button from 'primevue/button';
import Badge from 'primevue/badge';
import Tag from 'primevue/tag';
import SelectButton from 'primevue/selectbutton';
import ProgressSpinner from 'primevue/progressspinner';

/* ------------------------------------------------------------------ */
/*  Local state                                                         */
/* ------------------------------------------------------------------ */
const { t } = useI18n();
const loading = ref(false);
const users = ref<{ id: number; username: string }[]>([]);
const selectedUser = ref<number | null>(null);
const selectedStrategy = ref('api');
const result = ref<any>(null);

/* Strategy-specific params */
const apiMethod = ref('GET');
const apiPath = ref('/api/v1/users');
const funcCode = ref('');
const rbacRole = ref('');

const strategies = computed(() => [
    { name: t('policySimulator.strategies.api'), value: 'api' },
    { name: t('policySimulator.strategies.functional'), value: 'functional' },
    { name: t('policySimulator.strategies.rbac'), value: 'rbac' },
    { name: t('policySimulator.strategies.data'), value: 'data' },
    { name: t('policySimulator.strategies.location'), value: 'location' },
    { name: t('policySimulator.strategies.abac'), value: 'abac' },
    { name: t('policySimulator.strategies.lbac'), value: 'lbac' },
  ]);

/* ------------------------------------------------------------------ */
/*  Methods                                                             */
/* ------------------------------------------------------------------ */
const loadUsers = async () => {
  try {
    const res = await adminService.listUsers(1, 100);
    users.value = res.items.map((u: any) => ({ id: u.id, username: u.username }));
  } catch (err) {
    console.error('Failed to load users:', err);
  }
};

const runSimulation = async () => {
  if (!selectedUser.value) return;
  loading.value = true;
  result.value = null;

  try {
    const payload: any = {
      user_id: selectedUser.value,
      strategy: selectedStrategy.value,
    };

    if (selectedStrategy.value === 'api') {
      payload.method = apiMethod.value;
      payload.path = apiPath.value;
    } else if (selectedStrategy.value === 'functional') {
      payload.function_code = funcCode.value;
    } else if (selectedStrategy.value === 'rbac') {
      payload.role_name = rbacRole.value;
    }

    /* Mock result for now - in production this would call a real /check endpoint */
    await new Promise(resolve => setTimeout(resolve, 500));
    
    result.value = {
      allowed: Math.random() > 0.3,
      cache_hit: Math.random() > 0.5,
      duration_ms: Math.floor(Math.random() * 5) + 1,
      matched_policies: [
        { id: 1, name: 'Default Allow', effect: 'allow', strategy: selectedStrategy.value, priority: 100 },
      ],
      trace: `perm_engine_evaluate()
  L2 cache: miss
  L1 resolution: 2 policies
  Strategy: ${selectedStrategy.value}
  Result: ${Math.random() > 0.3 ? 'ALLOW' : 'DENY'}`,
    };
  } catch (err) {
    console.error('Simulation failed:', err);
  } finally {
    loading.value = false;
  }
};

onMounted(() => {
  loadUsers();
});
</script>
