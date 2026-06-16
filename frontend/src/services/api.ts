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

export default api;
