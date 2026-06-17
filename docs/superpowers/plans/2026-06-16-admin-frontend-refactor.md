# Admin Frontend Refactoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the large `Admin.vue` component into smaller sub-components and implement `ToastService` for better UI notifications.

**Architecture:** Decomposed components under `src/components/admin/`, global layout in `Admin.vue`, and PrimeVue `ToastService` for notifications.

**Tech Stack:** Vue 3, PrimeVue 4, Tailwind CSS, TypeScript.

---

### Task 1: Setup ToastService

**Files:**
- Modify: `frontend/src/main.ts`
- Modify: `frontend/src/App.vue`

- [ ] **Step 1: Configure ToastService in main.ts**

```typescript
import { createApp } from 'vue'
import PrimeVue from 'primevue/config'
import ToastService from 'primevue/toastservice'
import 'primeicons/primeicons.css'
import './style.css'
import App from './App.vue'
import router from './router'

const app = createApp(App)
app.use(PrimeVue)
app.use(ToastService)
app.use(router)
app.mount('#app')
```

- [ ] **Step 2: Add Toast component to App.vue**

```vue
<script setup lang="ts">
import Toast from 'primevue/toast';
</script>

<template>
  <Toast />
  <router-view />
</template>
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/main.ts frontend/src/App.vue
git commit -m "feat(frontend): 🍞 setup PrimeVue ToastService"
```

### Task 2: Create UserManagement Component

**Files:**
- Create: `frontend/src/components/admin/UserManagement.vue`

- [ ] **Step 1: Implement UserManagement.vue**
(Move User related logic and UI from Admin.vue, use Toast instead of alert)

- [ ] **Step 2: Commit**

```bash
git add frontend/src/components/admin/UserManagement.vue
git commit -m "refactor(frontend): 👥 create UserManagement component"
```

### Task 3: Create RoleManagement Component

**Files:**
- Create: `frontend/src/components/admin/RoleManagement.vue`

- [ ] **Step 1: Implement RoleManagement.vue**
(Move Role related logic and UI from Admin.vue, use Toast instead of alert)

- [ ] **Step 2: Commit**

```bash
git add frontend/src/components/admin/RoleManagement.vue
git commit -m "refactor(frontend): 🎭 create RoleManagement component"
```

### Task 4: Create GroupManagement Component

**Files:**
- Create: `frontend/src/components/admin/GroupManagement.vue`

- [ ] **Step 1: Implement GroupManagement.vue**
(Move Group related logic and UI from Admin.vue, use Toast instead of alert)

- [ ] **Step 2: Commit**

```bash
git add frontend/src/components/admin/GroupManagement.vue
git commit -m "refactor(frontend): 🏗️ create GroupManagement component"
```

### Task 5: Create PolicyManagement Component

**Files:**
- Create: `frontend/src/components/admin/PolicyManagement.vue`

- [ ] **Step 1: Implement PolicyManagement.vue**
(Move Policy related logic and UI from Admin.vue, use Toast instead of alert)

- [ ] **Step 2: Commit**

```bash
git add frontend/src/components/admin/PolicyManagement.vue
git commit -m "refactor(frontend): 📜 create PolicyManagement component"
```

### Task 6: Create AuditLogViewer Component

**Files:**
- Create: `frontend/src/components/admin/AuditLogViewer.vue`

- [ ] **Step 1: Implement AuditLogViewer.vue**
(Move Log related logic and UI from Admin.vue)

- [ ] **Step 2: Commit**

```bash
git add frontend/src/components/admin/AuditLogViewer.vue
git commit -m "refactor(frontend): 🕵️ create AuditLogViewer component"
```

### Task 7: Refactor Admin.vue

**Files:**
- Modify: `frontend/src/views/Admin.vue`

- [ ] **Step 1: Update Admin.vue to use sub-components**
(Remove moved logic, import and render sub-components based on currentTab)

- [ ] **Step 2: Commit**

```bash
git add frontend/src/views/Admin.vue
git commit -m "refactor(frontend): 🏛️ clean up Admin.vue view"
```

### Task 8: Verification & Build

**Files:**
- None

- [ ] **Step 1: Run build**
`cd frontend && npm run build`

- [ ] **Step 2: Final Commit / Amend**
`git add . && git commit --amend --no-edit`
