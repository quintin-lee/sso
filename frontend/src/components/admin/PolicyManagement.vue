<template>
  <div class="bg-[var(--bg-card)] rounded-2xl border border-[var(--border-primary)] overflow-hidden">
    <DataTable :value="displayedPolicies" paginator :rows="10" :loading="loading">
      <Column field="id" :header="$t('common.id')" class="w-20 font-mono text-xs"></Column>
      <Column field="name" :header="$t('common.name')" class="font-semibold"></Column>
      <Column field="strategy_name" :header="$t('policies.strategy')">
        <template #body="slotProps">
          <span class="px-2 py-1 bg-indigo-500/10 text-indigo-400 text-xs font-bold rounded uppercase">
            {{ getStrategyName(slotProps.data.strategy_type) }}
          </span>
        </template>
      </Column>
      <Column field="effect" :header="$t('policies.effect')">
        <template #body="slotProps">
          <span :class="slotProps.data.effect === 1 ? 'text-emerald-400 bg-emerald-500/10 px-2 py-1 rounded text-xs font-bold' : 'text-rose-400 bg-rose-500/10 px-2 py-1 rounded text-xs font-bold'">
            {{ slotProps.data.effect === 1 ? $t('policies.allow') : $t('policies.deny') }}
          </span>
        </template>
      </Column>
      <Column :header="$t('common.actions')" class="w-32 text-right">
        <template #body="slotProps">
          <div class="flex gap-1 justify-end">
            <Button icon="pi pi-pencil" text rounded severity="secondary" @click="editPolicy(slotProps.data)" />
            <Button icon="pi pi-trash" text rounded severity="danger" @click="confirmDeletePolicy(slotProps.data)" />
          </div>
        </template>
      </Column>
      <!-- Empty State -->
      <template #empty>
        <div class="flex flex-col items-center justify-center py-16 text-[var(--text-muted)]">
          <i class="pi pi-lock text-4xl mb-3 opacity-40"></i>
          <p class="text-sm font-medium">No policies found</p>
          <p class="text-xs mt-1 opacity-60">Click Add to create a new policy</p>
        </div>
      </template>
    </DataTable>

    <!-- Dialog for Edit/Create -->
    <Dialog v-model:visible="policyDialog" :header="policy.id ? $t('policies.update') : $t('policies.create')" modal class="w-full max-w-2xl">
       <div class="space-y-5">
         <!-- Name -->
         <div class="flex flex-col gap-1.5">
             <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('common.name') }}</label>
            <InputText v-model.trim="policy.name" placeholder="Allow Dashboard View" />
         </div>

         <!-- Strategy Type & Effect Grid -->
         <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
           <div class="flex flex-col gap-1.5">
               <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('policies.strategy') }}</label>
               <select v-model="policy.strategy_type" class="!bg-[var(--bg-elevated)] !border-[var(--border-primary)] !text-[var(--text-primary)] !rounded-lg !px-3 !py-2.5 !text-sm">
                <option :value="1">Functional (功能权限)</option>
                <option :value="2">API (接口权限)</option>
                <option :value="3">Data (数据权限)</option>
                <option :value="4">RBAC (角色权限)</option>
                <option :value="5">Location (位置权限)</option>
                <option :value="6">ABAC (属性权限)</option>
                <option :value="7">LBAC (标签权限)</option>
              </select>
           </div>

           <div class="flex flex-col gap-1.5">
               <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('policies.effect') }}</label>
               <select v-model="policy.effect" class="!bg-[var(--bg-elevated)] !border-[var(--border-primary)] !text-[var(--text-primary)] !rounded-lg !px-3 !py-2.5 !text-sm">
                <option :value="1">{{ $t('policies.allow') }}</option>
                <option :value="2">{{ $t('policies.deny') }}</option>
              </select>
           </div>
         </div>

         <!-- Editor Mode Switch -->
         <div class="flex items-center justify-between border-t border-[var(--border-primary)] pt-4">
            <span class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('policies.rules') }}</span>
           <div class="flex bg-[var(--bg-elevated)] p-1 rounded-xl border border-[var(--border-primary)]">
              <button @click="editorMode = 'visual'" class="py-1.5 px-3.5 text-xs font-bold rounded-lg transition-all" :class="editorMode === 'visual' ? 'bg-[var(--accent)]/15 text-[var(--accent)] shadow-sm' : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'">
                 {{ $t('policies.visualEditor') }}
              </button>
              <button @click="editorMode = 'code'" class="py-1.5 px-3.5 text-xs font-bold rounded-lg transition-all" :class="editorMode === 'code' ? 'bg-[var(--accent)]/15 text-[var(--accent)] shadow-sm' : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'">
                {{ $t('policies.codeEditor') }}
             </button>
           </div>
         </div>

         <!-- Visual Editor -->
         <div v-if="editorMode === 'visual'" class="bg-[var(--bg-elevated)] border border-[var(--border-primary)] rounded-2xl p-5 space-y-4">

           <!-- 1. Functional Strategy Visual Builder -->
           <div v-if="policy.strategy_type === 1" class="space-y-3">
             <div class="flex justify-between items-center">
                <span class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-widest">{{ $t('policies.functionalCode') }}</span>
               <Button icon="pi pi-plus" size="small" rounded severity="secondary" @click="addVisualRow('functions')" />
             </div>
             <div v-for="(row, idx) in visualState.functions" :key="idx" class="flex gap-2 items-center">
               <InputText v-model="row.code" class="flex-grow text-sm" placeholder="menu_admin_dashboard" />
               <select v-model="row.effect" class="!p-2 !text-xs !font-bold">
                 <option value="allow">ALLOW</option>
                 <option value="deny">DENY</option>
               </select>
               <Button icon="pi pi-trash" severity="danger" text rounded @click="removeVisualRow('functions', idx)" />
             </div>
           </div>

           <!-- 2. API Strategy Visual Builder -->
           <div v-else-if="policy.strategy_type === 2" class="space-y-3">
             <div class="flex justify-between items-center">
                <span class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-widest">API Endpoint Rules</span>
               <Button icon="pi pi-plus" size="small" rounded severity="secondary" @click="addVisualRow('endpoints')" />
             </div>
             <div v-for="(row, idx) in visualState.endpoints" :key="idx" class="flex gap-2 items-center">
               <select v-model="row.method" class="!p-2 !text-xs !font-bold">
                 <option value="GET">GET</option>
                 <option value="POST">POST</option>
                 <option value="PUT">PUT</option>
                 <option value="DELETE">DELETE</option>
                 <option value="*">*</option>
               </select>
               <InputText v-model="row.path" class="flex-grow text-sm" placeholder="/api/v1/users/*" />
               <select v-model="row.effect" class="!p-2 !text-xs !font-bold">
                 <option value="allow">ALLOW</option>
                 <option value="deny">DENY</option>
               </select>
               <Button icon="pi pi-trash" severity="danger" text rounded @click="removeVisualRow('endpoints', idx)" />
             </div>
           </div>

           <!-- 3. Data Strategy Visual Builder -->
           <div v-else-if="policy.strategy_type === 3" class="space-y-4">
             <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
               <div class="flex flex-col gap-1.5">
                  <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('policies.resourceType') }}</label>
                 <InputText v-model="visualState.resource_type" class="text-sm" placeholder="user" />
               </div>
               <div class="flex flex-col gap-1.5">
                  <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('policies.allowedFields') }} (comma-separated)</label>
                 <InputText v-model="visualState.allowed_fields" class="text-sm" placeholder="id, username, email" />
               </div>
             </div>

             <!-- Conditions -->
              <div class="border-t border-[var(--border-primary)] pt-3 space-y-3">
                <div class="flex justify-between items-center">
                  <span class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-widest">{{ $t('policies.conditions') }}</span>
                  <Button icon="pi pi-plus" size="small" rounded severity="secondary" @click="addVisualRow('data_conditions')" />
               </div>
               <div v-for="(row, idx) in visualState.data_conditions" :key="idx" class="flex gap-2 items-center">
                 <InputText v-model="row.field" class="w-1/3 text-sm" placeholder="field" />
                 <select v-model="row.op" class="!p-2 !text-xs !font-bold">
                   <option value="eq">== (eq)</option>
                   <option value="neq">!= (neq)</option>
                   <option value="contains">contains</option>
                   <option value="in">in</option>
                   <option value="gt">&gt; (gt)</option>
                   <option value="gte">&gt;= (gte)</option>
                   <option value="lt">&lt; (lt)</option>
                   <option value="lte">&lt;= (lte)</option>
                 </select>
                 <InputText v-model="row.value" class="flex-grow text-sm" placeholder="value" />
                 <Button icon="pi pi-trash" severity="danger" text rounded @click="removeVisualRow('data_conditions', idx)" class="!text-rose-400" />
               </div>
             </div>
           </div>

           <!-- 4. RBAC Strategy Visual Builder -->
           <div v-else-if="policy.strategy_type === 4" class="space-y-3">
             <div class="flex justify-between items-center">
                <span class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-widest">Role Membership</span>
               <Button icon="pi pi-plus" size="small" rounded severity="secondary" @click="addVisualRow('roles')" />
             </div>
             <div v-for="(row, idx) in visualState.roles" :key="idx" class="flex gap-2 items-center">
               <InputText v-model="row.name" class="flex-grow text-sm" placeholder="admin" />
               <select v-model="row.effect" class="!p-2 !text-xs !font-bold">
                 <option value="allow">ALLOW</option>
                 <option value="deny">DENY</option>
               </select>
               <Button icon="pi pi-trash" severity="danger" text rounded @click="removeVisualRow('roles', idx)" />
             </div>
           </div>

           <!-- 5. Location Strategy Visual Builder -->
           <div v-else-if="policy.strategy_type === 5" class="space-y-3">
             <div class="flex justify-between items-center">
                <span class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-widest">Location Rules</span>
               <Button icon="pi pi-plus" size="small" rounded severity="secondary" @click="addVisualRow('locations')" />
             </div>
             <div v-for="(row, idx) in visualState.locations" :key="idx" class="flex gap-2 items-center">
               <select v-model="row.type" class="!p-2 !text-xs !font-bold">
                 <option value="ip">IP</option>
                 <option value="cidr">CIDR</option>
                 <option value="country">Country</option>
               </select>
               <InputText v-model="row.value" class="flex-grow text-sm" placeholder="192.168.1.1 or CN" />
               <select v-model="row.effect" class="!p-2 !text-xs !font-bold">
                 <option value="allow">ALLOW</option>
                 <option value="deny">DENY</option>
               </select>
               <Button icon="pi pi-trash" severity="danger" text rounded @click="removeVisualRow('locations', idx)" />
             </div>
           </div>

           <!-- 6. ABAC Strategy (Condition Editor) -->
           <div v-else-if="policy.strategy_type === 6" class="space-y-4">
             <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
               <div class="flex flex-col gap-1.5">
                  <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('policies.logic') }}</label>
                 <select v-model="visualState.abac_logic" class="!p-2 !text-xs !font-bold">
                   <option value="and">AND (All match)</option>
                   <option value="or">OR (Any match)</option>
                 </select>
               </div>
               <div class="flex flex-col gap-1.5">
                  <label class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('policies.effect') }}</label>
                  <select v-model="visualState.abac_effect" class="!p-2 !text-xs !font-bold">
                   <option value="allow">ALLOW</option>
                   <option value="deny">DENY</option>
                 </select>
               </div>
             </div>

             <!-- ABAC Conditions List -->
              <div class="border-t border-[var(--border-primary)] pt-3 space-y-3">
                <div class="flex justify-between items-center">
                  <span class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-widest">{{ $t('policies.conditions') }}</span>
                  <Button icon="pi pi-plus" size="small" rounded severity="secondary" @click="addVisualRow('abac_conditions')" />
               </div>
               <div v-for="(row, idx) in visualState.abac_conditions" :key="idx" class="flex gap-2 items-center flex-wrap md:flex-nowrap bg-[var(--bg-card)] p-3 rounded-xl border border-[var(--border-primary)]">
                 <select v-model="row.source" class="!p-2 !text-xs !font-semibold">
                   <option value="subject">Subject (User)</option>
                   <option value="resource">Resource</option>
                   <option value="environment">Environment</option>
                 </select>
                 <InputText v-model="row.attr" class="w-full md:w-36 text-sm" placeholder="age, dept, time" />
                 <select v-model="row.op" class="!p-2 !text-xs !font-bold">
                   <option value="eq">== (eq)</option>
                   <option value="neq">!= (neq)</option>
                   <option value="contains">contains</option>
                   <option value="in">in</option>
                   <option value="gt">&gt; (gt)</option>
                   <option value="gte">&gt;= (gte)</option>
                   <option value="lt">&lt; (lt)</option>
                   <option value="lte">&lt;= (lte)</option>
                 </select>
                 <InputText v-model="row.value" class="flex-grow text-sm" placeholder="18, HR, etc." />
                 <Button icon="pi pi-trash" severity="danger" text rounded @click="removeVisualRow('abac_conditions', idx)" />
               </div>
             </div>
           </div>

           <!-- 7. LBAC Strategy Visual Builder -->
           <div v-else-if="policy.strategy_type === 7" class="space-y-3">
             <div class="flex justify-between items-center">
                <span class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-widest">{{ $t('policies.labelName') }}</span>
               <Button icon="pi pi-plus" size="small" rounded severity="secondary" @click="addVisualRow('labels')" />
             </div>
             <div v-for="(row, idx) in visualState.labels" :key="idx" class="flex gap-2 items-center">
               <InputText v-model="row.name" class="flex-grow text-sm" placeholder="CONFIDENTIAL" />
               <select v-model="row.effect" class="!p-2 !text-xs !font-bold">
                 <option value="allow">ALLOW</option>
                 <option value="deny">DENY</option>
               </select>
               <Button icon="pi pi-trash" severity="danger" text rounded @click="removeVisualRow('labels', idx)" />
             </div>
           </div>

         </div>

          <!-- Code/JSON Editor -->
          <div v-else class="flex flex-col gap-2">
              <textarea v-model.trim="policy.rules" class="w-full h-64 bg-[var(--bg-elevated)] border border-[var(--border-primary)] text-[var(--text-primary)] rounded-xl p-4 font-mono text-sm" placeholder='{"action": "read", "resource": "dashboard"}'></textarea>
          </div>

          <!-- Policy Assignments -->
          <div class="border-t border-[var(--border-primary)] pt-5 space-y-4">
            <div class="flex items-center justify-between">
              <span class="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">{{ $t('policies.assignTo') }}</span>
            </div>

            <!-- Add Assignment Row -->
            <div class="flex gap-2 items-end">
              <div class="flex flex-col gap-1.5">
                <label class="text-xs font-bold text-[var(--text-secondary)] whitespace-nowrap">{{ $t('policies.targetType') }}</label>
                <Select v-model="assignTargetType" :options="targetTypeOptions" optionLabel="label" optionValue="value" :placeholder="$t('policies.selectTargetType')" class="w-36" />
              </div>
              <div class="flex flex-col gap-1.5 flex-1 min-w-0">
                <label class="text-xs font-bold text-[var(--text-secondary)] whitespace-nowrap">{{ $t('policies.target') }}</label>
                <Select v-model="assignTargetId" :options="targetOptions" optionLabel="label" optionValue="value" filter :placeholder="$t('policies.searchPlaceholder')" class="w-full" :disabled="assignTargetType === null" />
              </div>
              <Button icon="pi pi-plus" label="Assign" size="small" @click="addAssignment" :disabled="!assignTargetId" class="!rounded-lg !bg-[var(--accent-strong)] hover:!bg-[var(--accent)] !text-white !border-none mb-0.5 whitespace-nowrap" />
            </div>

            <!-- Assigned Lists -->
            <template v-if="assignedTargets.length > 0">
              <div v-for="group in ['user', 'role', 'group']" :key="group">
                <div v-if="assignedTargets.filter(a => a.type === group).length > 0" class="space-y-1.5">
                  <label class="text-xs font-bold text-[var(--text-secondary)] capitalize">{{ group }}s</label>
                  <div class="flex flex-wrap gap-1.5">
                    <Tag v-for="a in assignedTargets.filter(t => t.type === group)" :key="group + '-' + a.id" :value="a.label" removable @remove="removeAssignment(group, a.id)" class="!text-xs" />
                  </div>
                </div>
              </div>
            </template>
            <div v-else class="text-xs text-[var(--text-muted)] italic">
              {{ $t('policies.noAssignments') }}
            </div>
          </div>
        </div>

       <!-- Modal Footer -->
        <template #footer>
           <div class="flex gap-2 justify-end">
              <Button :label="$t('common.cancel')" text severity="secondary" @click="policyDialog = false" class="!rounded-lg !text-[var(--text-secondary)] hover:!text-[var(--text-primary)]" />
              <Button :label="$t('common.save')" @click="savePolicy" class="!rounded-lg !px-6 !bg-[var(--accent-strong)] hover:!bg-[var(--accent)] !text-white !border-none" />
           </div>
        </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue';
import { useI18n } from 'vue-i18n';
import { adminService, type Policy, type User, type Role, type Group } from '../../services/api';
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import Button from 'primevue/button';
import Dialog from 'primevue/dialog';
import InputText from 'primevue/inputtext';
import Select from 'primevue/select';
import Tag from 'primevue/tag';
import { useToast } from 'primevue/usetoast';
import { useConfirm } from 'primevue/useconfirm';

const props = defineProps<{ search?: string }>();

const { t } = useI18n();
const toast = useToast();
const loading = ref(false);
const policies = ref<Policy[]>([]);

const displayedPolicies = computed(() => {
  const q = (props.search || '').toLowerCase().trim();
  if (!q) return policies.value;
  return policies.value.filter(p =>
    (p.name || '').toLowerCase().includes(q) ||
    p.strategy_name?.toLowerCase().includes(q)
  );
});
const policyDialog = ref(false);
const policy = ref<Partial<Policy>>({});

// Assignment state
const allUsers = ref<User[]>([]);
const allRoles = ref<Role[]>([]);
const allGroups = ref<Group[]>([]);

interface Assignment {
  type: 'user' | 'role' | 'group';
  id: number;
  label: string;
}

const assignedTargets = ref<Assignment[]>([]);
const assignTargetType = ref<number | null>(null);
const assignTargetId = ref<number | null>(null);

const targetTypeOptions = [
  { label: 'User', value: 0 },
  { label: 'Role', value: 1 },
  { label: 'Group', value: 2 },
];

const targetOptions = computed(() => {
  if (assignTargetType.value === 0) return allUsers.value.map(u => ({ label: `${u.username}${u.display_name ? ' (' + u.display_name + ')' : ''}`, value: u.id }));
  if (assignTargetType.value === 1) return allRoles.value.map(r => ({ label: r.name, value: r.id }));
  if (assignTargetType.value === 2) return allGroups.value.map(g => ({ label: g.name, value: g.id }));
  return [];
});

const addAssignment = () => {
  if (assignTargetId.value === null || assignTargetType.value === null) return;

  const typeMap = ['user' as const, 'role' as const, 'group' as const];
  const type = typeMap[assignTargetType.value];
  const id = assignTargetId.value;

  if (assignedTargets.value.some(a => a.type === type && a.id === id)) return;

  let label = '';
  if (type === 'user') {
    const u = allUsers.value.find(x => x.id === id);
    if (u) label = u.username;
  } else if (type === 'role') {
    const r = allRoles.value.find(x => x.id === id);
    if (r) label = r.name;
  } else if (type === 'group') {
    const g = allGroups.value.find(x => x.id === id);
    if (g) label = g.name;
  }

  assignedTargets.value.push({ type, id, label });
  assignTargetId.value = null;
};

const removeAssignment = (type: string, id: number) => {
  assignedTargets.value = assignedTargets.value.filter(a => !(a.type === type && a.id === id));
};

// Editor States
const editorMode = ref<'visual' | 'code'>('visual');

// Visual forms backing states mapping
interface VisualState {
  functions: { code: string; effect: string }[];
  endpoints: { method: string; path: string; effect: string }[];
  resource_type: string;
  allowed_fields: string;
  data_conditions: { field: string; op: string; value: string }[];
  roles: { name: string; effect: string }[];
  locations: { type: string; value: string; effect: string }[];
  abac_logic: 'and' | 'or';
  abac_effect: 'allow' | 'deny';
  abac_conditions: { source: 'subject' | 'resource' | 'environment'; attr: string; op: string; value: string }[];
  labels: { name: string; effect: string }[];
}

const visualState = ref<VisualState>({
  functions: [],
  endpoints: [],
  resource_type: '',
  allowed_fields: '',
  data_conditions: [],
  roles: [],
  locations: [],
  abac_logic: 'and',
  abac_effect: 'allow',
  abac_conditions: [],
  labels: []
});

const getStrategyName = (type: number) => {
  const map: Record<number, string> = {
    1: 'Functional',
    2: 'API',
    3: 'Data',
    4: 'RBAC',
    5: 'Location',
    6: 'ABAC',
    7: 'LBAC'
  };
  return map[type] || 'Unknown';
};

// Sync VisualState to raw rules string when Strategy changes
watch(() => policy.value.strategy_type, (newType) => {
  if (newType && editorMode.value === 'visual') {
    // Re-initialize lists with structure if empty
    syncVisualStateFromRules();
  }
});

// Dynamic visual row helpers
const addVisualRow = (type: keyof VisualState) => {
  if (type === 'functions') {
    visualState.value.functions.push({ code: '', effect: 'allow' });
  } else if (type === 'endpoints') {
    visualState.value.endpoints.push({ method: 'GET', path: '', effect: 'allow' });
  } else if (type === 'data_conditions') {
    visualState.value.data_conditions.push({ field: '', op: 'eq', value: '' });
  } else if (type === 'roles') {
    visualState.value.roles.push({ name: '', effect: 'allow' });
  } else if (type === 'locations') {
    visualState.value.locations.push({ type: 'ip', value: '', effect: 'allow' });
  } else if (type === 'abac_conditions') {
    visualState.value.abac_conditions.push({ source: 'subject', attr: '', op: 'eq', value: '' });
  } else if (type === 'labels') {
    visualState.value.labels.push({ name: '', effect: 'allow' });
  }
};

const removeVisualRow = (type: keyof VisualState, idx: number) => {
  if (type === 'functions') visualState.value.functions.splice(idx, 1);
  else if (type === 'endpoints') visualState.value.endpoints.splice(idx, 1);
  else if (type === 'data_conditions') visualState.value.data_conditions.splice(idx, 1);
  else if (type === 'roles') visualState.value.roles.splice(idx, 1);
  else if (type === 'locations') visualState.value.locations.splice(idx, 1);
  else if (type === 'abac_conditions') visualState.value.abac_conditions.splice(idx, 1);
  else if (type === 'labels') visualState.value.labels.splice(idx, 1);
};

const syncVisualStateFromRules = () => {
  const rulesStr = policy.value.rules || '{}';
  const type = policy.value.strategy_type || 1;
  
  // Reset
  visualState.value = {
    functions: [],
    endpoints: [],
    resource_type: '',
    allowed_fields: '',
    data_conditions: [],
    roles: [],
    locations: [],
    abac_logic: 'and',
    abac_effect: 'allow',
    abac_conditions: [],
    labels: []
  };

  try {
    const json = JSON.parse(rulesStr);
    if (type === 1) {
      visualState.value.functions = Array.isArray(json.functions) ? json.functions : [];
    } else if (type === 2) {
      visualState.value.endpoints = Array.isArray(json.endpoints) ? json.endpoints : [];
    } else if (type === 3) {
      visualState.value.resource_type = json.resource_type || '';
      visualState.value.allowed_fields = Array.isArray(json.allowed_fields) ? json.allowed_fields.join(', ') : '';
      visualState.value.data_conditions = Array.isArray(json.conditions) ? json.conditions : [];
    } else if (type === 4) {
      visualState.value.roles = Array.isArray(json.roles) ? json.roles : [];
    } else if (type === 5) {
      visualState.value.locations = Array.isArray(json.locations) ? json.locations : [];
    } else if (type === 6) {
      visualState.value.abac_logic = json.logic || 'and';
      visualState.value.abac_effect = json.effect || 'allow';
      visualState.value.abac_conditions = Array.isArray(json.conditions) ? json.conditions : [];
    } else if (type === 7) {
      visualState.value.labels = Array.isArray(json.labels) ? json.labels : [];
    }
  } catch (e) {
    console.error('Invalid rules JSON loaded', e);
  }
};

const syncRulesFromVisualState = () => {
  const type = policy.value.strategy_type || 1;
  const state = visualState.value;
  const json: any = {};

  if (type === 1) {
    json.functions = state.functions;
  } else if (type === 2) {
    json.endpoints = state.endpoints;
  } else if (type === 3) {
    json.resource_type = state.resource_type;
    json.allowed_fields = state.allowed_fields ? state.allowed_fields.split(',').map(s => s.trim()).filter(Boolean) : [];
    json.conditions = state.data_conditions;
    json.effect = policy.value.effect === 1 ? 'allow' : 'deny';
  } else if (type === 4) {
    json.roles = state.roles;
  } else if (type === 5) {
    json.locations = state.locations;
  } else if (type === 6) {
    json.logic = state.abac_logic;
    json.effect = state.abac_effect;
    json.conditions = state.abac_conditions;
  } else if (type === 7) {
    json.labels = state.labels;
  }

  policy.value.rules = JSON.stringify(json, null, 2);
};

const loadPolicies = async () => {
  loading.value = true;
  try {
    const res = await adminService.listPolicies();
    policies.value = res.items;
  } catch (err) {
    toast.add({ severity: 'error', summary: t('common.error'), detail: 'Failed to load policies', life: 3000 });
  } finally {
    loading.value = false;
  }
};

const loadAssignmentOptions = async () => {
  try {
    const [usersRes, rolesRes, groupsRes] = await Promise.all([
      adminService.listUsers(1, 200),
      adminService.listRoles(1, 200),
      adminService.listGroups(1, 200),
    ]);
    allUsers.value = usersRes.items;
    allRoles.value = rolesRes.items;
    allGroups.value = groupsRes.items;
  } catch (err) {
    console.error('Failed to load assignment options', err);
  }
};

const openCreateDialog = () => {
  policy.value = { status: 1, strategy_type: 1, effect: 1, rules: '{}' };
  editorMode.value = 'visual';
  assignedTargets.value = [];
  assignTargetType.value = null;
  assignTargetId.value = null;
  syncVisualStateFromRules();
  loadAssignmentOptions();
  policyDialog.value = true;
};

const editPolicy = (data: Policy) => {
  policy.value = { ...data };
  editorMode.value = 'visual';
  assignedTargets.value = [];
  assignTargetType.value = null;
  assignTargetId.value = null;
  syncVisualStateFromRules();
  loadAssignmentOptions();
  policyDialog.value = true;
};

const savePolicy = async () => {
  if (editorMode.value === 'visual') {
    syncRulesFromVisualState();
  }

  try {
    if (policy.value.id) {
      await adminService.updatePolicy(policy.value.id, policy.value);
    } else {
      await adminService.createPolicy(policy.value);
    }

    // Save policy assignments
    if (policy.value.id) {
      const policyId = policy.value.id;
      const typeMap: Record<string, number> = { user: 0, role: 1, group: 2 };

      for (const a of assignedTargets.value) {
        try {
          await adminService.assignPolicy(policyId, typeMap[a.type], a.id);
        } catch { /* skip duplicates */ }
      }
    }

    toast.add({ severity: 'success', summary: t('common.success'), detail: 'Policy saved', life: 3000 });
    policyDialog.value = false;
    loadPolicies();
  } catch (err) {
    toast.add({ severity: 'error', summary: t('common.error'), detail: 'Failed to save policy', life: 3000 });
  }
};

const confirmDlg = useConfirm();

const confirmDeletePolicy = (data: Policy) => {
  confirmDlg.require({
    message: t('policies.deleteConfirm', { name: data.name }),
    header: t('common.confirmDelete'),
    icon: 'pi pi-exclamation-triangle',
    rejectLabel: t('common.cancel'),
    acceptLabel: t('common.delete'),
    rejectClass: 'p-button-text p-button-sm',
    acceptClass: 'p-button-danger p-button-sm',
    accept: async () => {
      try {
        await adminService.deletePolicy(data.id);
        toast.add({ severity: 'success', summary: t('common.success'), detail: 'Policy deleted successfully', life: 3000 });
        loadPolicies();
      } catch (err) {
        toast.add({ severity: 'error', summary: t('common.error'), detail: 'Failed to delete policy', life: 3000 });
      }
    }
  });
};

onMounted(() => {
  loadPolicies();
});

defineExpose({
  openCreateDialog
});
</script>
