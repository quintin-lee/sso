# Admin Frontend Refactoring Design

## Goal
Decompose the "God Component" `Admin.vue` into smaller, maintainable sub-components and improve user feedback using PrimeVue `ToastService`.

## Architecture
- **Layout Shell (`Admin.vue`)**: Manages navigation (sidebar), global header, and tab switching.
- **Management Components (`frontend/src/components/admin/`)**:
    - `UserManagement.vue`
    - `RoleManagement.vue`
    - `GroupManagement.vue`
    - `PolicyManagement.vue`
    - `AuditLogViewer.vue`
- **Data Fetching**: Each component uses `adminService` or `auditService` for its specific domain.
- **Feedback System**: PrimeVue `ToastService` replaces `alert()`.

## Detailed Component Breakdown

### 1. UserManagement.vue
- **Responsibilities**: 
    - Fetch and display users in a `DataTable`.
    - Handle pagination.
    - Create/Edit/Delete users via a `Dialog`.
    - Show success/error toasts.

### 2. RoleManagement.vue
- **Responsibilities**: 
    - Fetch and display roles.
    - Create/Edit/Delete roles via a `Dialog`.
    - Show success/error toasts.

### 3. GroupManagement.vue
- **Responsibilities**: 
    - Fetch and display groups.
    - Create/Edit/Delete groups via a `Dialog`.
    - Show success/error toasts.

### 4. PolicyManagement.vue
- **Responsibilities**: 
    - Fetch and display policies.
    - Create/Edit/Delete policies via a `Dialog`.
    - Show success/error toasts.

### 5. AuditLogViewer.vue
- **Responsibilities**: 
    - Fetch and display audit logs.
    - No create/edit actions.

## Integration & Layout
- `Admin.vue` will import all sub-components.
- Uses a `v-if` or `component :is` to render the active management component.
- The sidebar buttons update the `currentTab` ref.

## Notification Setup
- **main.ts**: `import ToastService from 'primevue/toastservice'; app.use(ToastService);`
- **App.vue**: Add `<Toast />` component.
- **Components**: `import { useToast } from "primevue/usetoast"; const toast = useToast();`

## Verification Plan
- Run `npm run build` in `frontend/` to ensure no type errors or build failures.
- Check that all management tabs still function correctly.
- Verify that toasts appear instead of browser alerts.
