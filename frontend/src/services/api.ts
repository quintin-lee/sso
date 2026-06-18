import axios from 'axios';

const API_BASE = '/api/v1';

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add access token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token') || localStorage.getItem('sso_token');
  if (token) {
    if (config.headers && typeof config.headers.set === 'function') {
      config.headers.set('Authorization', `Bearer ${token}`);
    } else {
      config.headers = config.headers || {};
      config.headers['Authorization'] = `Bearer ${token}`;
    }
  }
  return config;
});

let isRefreshing = false;
let failedQueue: any[] = [];

const processQueue = (error: any, token: string | null = null) => {
  failedQueue.forEach((prom) => {
    if (token) {
      prom.resolve(token);
    } else {
      prom.reject(error);
    }
  });
  failedQueue = [];
};

// Response interceptor to capture tokens from headers and handle 401 token refresh
api.interceptors.response.use(
  (response) => {
    const getHeader = (name: string) => {
      if (response.headers && typeof response.headers.get === 'function') {
        return response.headers.get(name);
      }
      return response.headers ? (response.headers[name] || response.headers[name.toLowerCase()]) : undefined;
    };

    const accessToken = getHeader('X-SSO-Access-Token') || getHeader('x-sso-access-token');
    const refreshToken = getHeader('X-SSO-Refresh-Token') || getHeader('x-sso-refresh-token');

    if (accessToken) {
      localStorage.setItem('access_token', accessToken);
      localStorage.setItem('sso_token', accessToken);
    }
    if (refreshToken) {
      localStorage.setItem('refresh_token', refreshToken);
    }

    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    // Check if it's a 401 and not already a retry or login/refresh request
    if (
      error.response &&
      error.response.status === 401 &&
      originalRequest &&
      !originalRequest._retry &&
      !originalRequest.url?.includes('/auth/login') &&
      !originalRequest.url?.includes('/auth/refresh')
    ) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then((token) => {
            if (originalRequest.headers) {
              if (typeof originalRequest.headers.set === 'function') {
                originalRequest.headers.set('Authorization', `Bearer ${token}`);
              } else {
                originalRequest.headers['Authorization'] = `Bearer ${token}`;
              }
            }
            return api(originalRequest);
          })
          .catch((err) => Promise.reject(err));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const storedRefreshToken = localStorage.getItem('refresh_token');
        if (!storedRefreshToken) {
          throw new Error('No refresh token available');
        }

        const { headers } = await axios.post('/api/v1/auth/refresh', {
          refresh_token: storedRefreshToken,
        });

        const getHeader = (h: any, name: string) => {
          return h ? (h[name] || h[name.toLowerCase()]) : undefined;
        };
        const newAccessToken = getHeader(headers, 'X-SSO-Access-Token') || getHeader(headers, 'x-sso-access-token');
        const newRefreshToken = getHeader(headers, 'X-SSO-Refresh-Token') || getHeader(headers, 'x-sso-refresh-token');

        if (newAccessToken) {
          localStorage.setItem('access_token', newAccessToken);
          localStorage.setItem('sso_token', newAccessToken);
        }
        if (newRefreshToken) {
          localStorage.setItem('refresh_token', newRefreshToken);
        }

        const token = newAccessToken || localStorage.getItem('access_token');
        processQueue(null, token);

        if (token && originalRequest.headers) {
          if (typeof originalRequest.headers.set === 'function') {
            originalRequest.headers.set('Authorization', `Bearer ${token}`);
          } else {
            originalRequest.headers['Authorization'] = `Bearer ${token}`;
          }
        }
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('sso_token');
        window.location.href = '/login';
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    // For other 401 errors (e.g. login failed, refresh failed)
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      localStorage.removeItem('sso_token');
      window.location.href = '/login';
    }

    return Promise.reject(error);
  }
);


export interface LoginResponse {
  mfa_required?: boolean;
  mfa_token?: string;
  user_id?: number;
  username?: string;
  display_name?: string;
  expires_in?: number;
}

export interface User {
  id: number;
  username: string;
  email: string;
  display_name: string;
  phone?: string;
  status: number;
  password?: string;
  roles?: Role[];
  groups?: Group[];
  created_at: number;
}

export interface Role {
  id: number;
  name: string;
  description: string;
  parent_role_id?: number;
  parent_name?: string;
  status: number;
  created_at: number;
}

export interface Group {
  id: number;
  name: string;
  description: string;
  parent_group_id?: number;
  parent_name?: string;
  status: number;
  created_at: number;
}

export interface Policy {
  id: number;
  name: string;
  strategy_type: number;
  strategy_name: string;
  effect: number;
  priority: number;
  status: number;
  rules: string;
  created_at: number;
}

export interface AuditLog {
  timestamp_ms: number;
  user_id: number;
  decision: string;
  duration_ms: number;
  cache_hit: boolean;
  trace: string;
  id?: number;
  timestamp?: number;
  username?: string;
  action?: string;
  resource?: string;
  status?: string;
  ip_address?: string;
  details?: string;
}

export interface PaginatedResponse<T> {
  total: number;
  page: number;
  limit: number;
  items: T[];
}

export const authService = {
  async login(username: string, password: string): Promise<LoginResponse> {
    const { data } = await api.post<LoginResponse>('/auth/login', { username, password });
    return data;
  },

  async mfaVerify(mfaToken: string, code: string): Promise<LoginResponse> {
    const { data } = await api.post<LoginResponse>('/auth/mfa/verify', {
      mfa_token: mfaToken,
      code,
    });
    return data;
  },

  async register(username: string, password: string, email?: string, displayName?: string) {
    const { data } = await api.post('/auth/register', {
      username,
      password,
      email,
      display_name: displayName,
    });
    return data;
  },

  async sendSms(phone: string) {
    const { data } = await api.post('/auth/send_sms', { phone });
    return data;
  },

  async me(): Promise<User> {
    const { data } = await api.get<User>('/auth/me');
    return data;
  },

  async logout() {
    await api.post('/auth/logout');
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('sso_token');
  },

  isAuthenticated(): boolean {
    return !!(localStorage.getItem('access_token') || localStorage.getItem('sso_token'));
  }
};

export const adminService = {
  // Users
  async listUsers(page = 1, limit = 10, q = ''): Promise<PaginatedResponse<User>> {
    const { data } = await api.get<PaginatedResponse<User>>(`/users?page=${page}&limit=${limit}&q=${q}`);
    return data;
  },
  async createUser(user: Partial<User>) {
    const { data } = await api.post('/users', user);
    return data;
  },
  async updateUser(id: number, user: Partial<User>) {
    const { data } = await api.put(`/users/${id}`, user);
    return data;
  },
  async deleteUser(id: number) {
    const { data } = await api.delete(`/users/${id}`);
    return data;
  },

  // Roles
  async listRoles(page = 1, limit = 10, q = ''): Promise<PaginatedResponse<Role>> {
    const { data } = await api.get<PaginatedResponse<Role>>(`/roles?page=${page}&limit=${limit}&q=${q}`);
    return data;
  },
  async createRole(role: Partial<Role>) {
    const { data } = await api.post('/roles', role);
    return data;
  },
  async updateRole(id: number, role: Partial<Role>) {
    const { data } = await api.put(`/roles/${id}`, role);
    return data;
  },
  async deleteRole(id: number) {
    const { data } = await api.delete(`/roles/${id}`);
    return data;
  },
  async assignRole(roleId: number, userId: number) {
    const { data } = await api.post(`/roles/${roleId}/assign`, { user_id: userId });
    return data;
  },
  async unassignRole(roleId: number, userId: number) {
    const { data } = await api.post(`/roles/${roleId}/unassign`, { user_id: userId });
    return data;
  },

  // Groups
  async listGroups(page = 1, limit = 10, q = ''): Promise<PaginatedResponse<Group>> {
    const { data } = await api.get<PaginatedResponse<Group>>(`/groups?page=${page}&limit=${limit}&q=${q}`);
    return data;
  },
  async createGroup(group: Partial<Group>) {
    const { data } = await api.post('/groups', group);
    return data;
  },
  async updateGroup(id: number, group: Partial<Group>) {
    const { data } = await api.put(`/groups/${id}`, group);
    return data;
  },
  async deleteGroup(id: number) {
    const { data } = await api.delete(`/groups/${id}`);
    return data;
  },
  async addGroupMember(groupId: number, userId: number) {
    const { data } = await api.post(`/groups/${groupId}/members`, { user_id: userId });
    return data;
  },
  async removeGroupMember(groupId: number, userId: number) {
    const { data } = await api.delete(`/groups/${groupId}/members/${userId}`);
    return data;
  },

  // Policies
  async listPolicies(page = 1, limit = 10, q = ''): Promise<PaginatedResponse<Policy>> {
    const { data } = await api.get<PaginatedResponse<Policy>>(`/policies?page=${page}&limit=${limit}&q=${q}`);
    return data;
  },
  async createPolicy(policy: Partial<Policy>) {
    const { data } = await api.post('/policies', policy);
    return data;
  },
  async updatePolicy(id: number, policy: Partial<Policy>) {
    const { data } = await api.put(`/policies/${id}`, policy);
    return data;
  },
  async deletePolicy(id: number) {
    const { data } = await api.delete(`/policies/${id}`);
    return data;
  },
  async assignPolicy(policyId: number, targetType: number, targetId: number) {
    const { data } = await api.post(`/policies/${policyId}/assign`, {
      target_type: targetType,
      target_id: targetId
    });
    return data;
  }
};

export const auditService = {
  async listLogs(page = 1, limit = 20): Promise<PaginatedResponse<AuditLog>> {
    const { data } = await api.get<any>(`/audit/logs?page=${page}&limit=${limit}`);
    const items = Array.isArray(data) ? data : [];
    return {
      total: items.length,
      page,
      limit,
      items
    };
  }
};

export const systemService = {
  async getStatus() {
    const { data } = await api.get('/admin/status');
    return data;
  }
};

export default api;
