# Decoupled Vue.js Frontend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a standalone Vue.js frontend in `/frontend`, remove embedded HTML from the C backend, and containerize the system using Nginx.

**Architecture:** We will initialize a Vite + Vue 3 project, implement the Login and Admin views using PrimeVue, and update Nginx to serve the built assets while proxying API requests to the C backend.

**Tech Stack:** Vue 3, Vite, TypeScript, PrimeVue, Tailwind CSS, Nginx, Docker.

---

### Task 1: Initialize Frontend Project

**Files:**
- Create: `frontend/*`

- [ ] **Step 1: Scaffold Vite project in `/frontend`**
- [ ] **Step 2: Install PrimeVue and Tailwind CSS**
- [ ] **Step 3: Commit**

```bash
git add frontend/
git commit -m "feat(frontend): 🏗️ initialize vue.js project with vite"
```

---

### Task 2: Implement Authentication & Login View

**Files:**
- Create: `frontend/src/views/Login.vue`
- Create: `frontend/src/services/api.ts`

- [ ] **Step 1: Implement API service for Login/MFA**
- [ ] **Step 2: Build the Login/MFA UI**
- [ ] **Step 3: Commit**

```bash
git add frontend/
git commit -m "feat(frontend): ✨ implement login and MFA UI"
```

---

### Task 3: Implement Admin Dashboard

**Files:**
- Create: `frontend/src/views/Admin.vue`

- [ ] **Step 1: Implement Users/Roles/Groups management tables**
- [ ] **Step 2: Implement Policy editor**
- [ ] **Step 3: Commit**

```bash
git add frontend/
git commit -m "feat(frontend): ✨ build admin dashboard"
```

---

### Task 4: Backend Cleanup & Nginx Containerization

**Files:**
- Modify: `Dockerfile`
- Modify: `docker-compose.yml`
- Modify: `nginx.conf`
- Delete: `src/login_page.h`, `src/admin_page.h`

- [ ] **Step 1: Remove embedded HTML and corresponding routes from `main.c`**
- [ ] **Step 2: Update Nginx configuration for static assets**
- [ ] **Step 3: Create multi-stage Dockerfile**
- [ ] **Step 4: Commit**

```bash
git add .
git commit -m "feat(deploy): 📦 decouple frontend and finalize containerization"
```
