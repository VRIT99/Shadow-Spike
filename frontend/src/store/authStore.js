import { create } from 'zustand'
import api from '../utils/api'

const useAuthStore = create((set, get) => ({
  user: null,
  tempToken: null,

  setTempToken: (token) => set({ tempToken: token }),

  fetchMe: async () => {
    const { data } = await api.get('/auth/me')
    set({ user: data })
    return data
  },

  logout: async () => {
    try {
      await api.post('/auth/logout')
    } catch {}
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    set({ user: null, tempToken: null })
  },

  isAdmin: () => get().user?.role === 'admin',
  isLoggedIn: () => !!localStorage.getItem('access_token'),
}))

export default useAuthStore