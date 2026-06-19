import { createRouter, createWebHistory } from 'vue-router';
import { authService } from '../services/api';
const Login = () => import('../views/Login.vue');
const Admin = () => import('../views/Admin.vue');
const Portal = () => import('../views/Portal.vue');

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: Login,
      meta: { guest: true }
    },
    {
      path: '/admin',
      name: 'admin',
      component: Admin,
      meta: { requiresAuth: true }
    },
    {
      path: '/',
      name: 'portal',
      component: Portal,
      meta: { requiresAuth: true }
    }
  ]
});

router.beforeEach((to, _from, next) => {
  const isAuthenticated = authService.isAuthenticated();

  if (to.meta.requiresAuth && !isAuthenticated) {
    next({ name: 'login' });
  } else if (to.meta.guest && isAuthenticated) {
    next({ name: 'portal' });
  } else {
    next();
  }
});

export default router;
