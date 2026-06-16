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
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers['Authorization'] = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor to capture tokens from headers
api.interceptors.response.use((response) => {
  const accessToken = response.headers['x-sso-access-token'];
  const refreshToken = response.headers['x-sso-refresh-token'];

  if (accessToken) {
    localStorage.setItem('access_token', accessToken);
  }
  if (refreshToken) {
    localStorage.setItem('refresh_token', refreshToken);
  }

  return response;
});

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
  id: number;
  timestamp: number;
  user_id?: number;
  username?: string;
  action: string;
  resource: string;
  status: string;
  ip_address: string;
  details: string;
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
  },

  isAuthenticated(): boolean {
    return !!localStorage.getItem('access_token');
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
    const { data } = await api.get<PaginatedResponse<AuditLog>>(`/audit/logs?page=${page}&limit=${limit}`);
    return data;
  }
};

export const systemService = {
  async getStatus() {
    const { data } = await api.get('/admin/status');
    return data;
  }
};

export default api;
