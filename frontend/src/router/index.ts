import { createRouter, createWebHistory } from 'vue-router';
import { authService } from '../services/api';
import Login from '../views/Login.vue';

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
      path: '/',
      name: 'home',
      component: () => import('../components/HelloWorld.vue'),
      meta: { requiresAuth: true }
    }
  ]
});

router.beforeEach((to, from, next) => {
  const isAuthenticated = authService.isAuthenticated();

  if (to.meta.requiresAuth && !isAuthenticated) {
    next({ name: 'login' });
  } else if (to.meta.guest && isAuthenticated) {
    next({ name: 'home' });
  } else {
    next();
  }
});

export default router;
