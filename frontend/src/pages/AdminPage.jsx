import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import api from '../utils/api'
import useAuthStore from '../store/authStore'

export default function AdminPage() {
  const navigate = useNavigate()
  const { user, fetchMe, logout, isAdmin } = useAuthStore()
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState('stats')
  const [stats, setStats] = useState(null)
  const [users, setUsers] = useState([])
  const [logs, setLogs] = useState([])
  const [search, setSearch] = useState('')
  const [actionLoading, setActionLoading] = useState(null)

  useEffect(() => {
    const init = async () => {
      const u = await fetchMe()
      if (!u) { navigate('/login'); return }
      if (u.role !== 'admin') { navigate('/dashboard'); return }
      setLoading(false)
      loadStats()
      loadUsers()
      loadLogs()
    }
    init()
  }, [])

  const loadStats = async () => {
    try {
      const { data } = await api.get('/admin/stats')
      setStats(data)
    } catch (e) {
      toast.error('Failed to load stats')
    }
  }

  const loadUsers = async (q = '') => {
    try {
      const { data } = await api.get('/admin/users', { params: { search: q || undefined, per_page: 50 } })
      setUsers(data.users)
    } catch (e) {
      toast.error('Failed to load users')
    }
  }

  const loadLogs = async () => {
    try {
      const { data } = await api.get('/admin/audit-logs', { params: { per_page: 50 } })
      setLogs(data.logs)
    } catch (e) {}
  }

  const handleBan = async (u) => {
    setActionLoading(u.id)
    try {
      if (u.is_banned) {
        await api.post(`/admin/users/${u.id}/unban`)
        toast.success(`${u.username} unbanned`, { style: { background: '#010204', color: '#00ff88', border: '1px solid #00ff88' } })
      } else {
        await api.post(`/admin/users/${u.id}/ban`, { reason: 'Banned by admin' })
        toast.success(`${u.username} banned`, { style: { background: '#010204', color: 'var(--error-color)', border: '1px solid var(--error-color)' } })
      }
      loadUsers(search)
    } catch (e) {
      toast.error(e.response?.data?.detail || 'Action failed')
    } finally {
      setActionLoading(null)
    }
  }

  const handleToggleActive = async (u) => {
    setActionLoading(u.id + '_active')
    try {
      await api.post(`/admin/users/${u.id}/toggle-active`)
      toast.success(`${u.username} status toggled`, { style: { background: '#010204', color: '#ffb347', border: '1px solid #ffb347' } })
      loadUsers(search)
    } catch (e) {
      toast.error(e.response?.data?.detail || 'Action failed')
    } finally {
      setActionLoading(null)
    }
  }

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  if (loading) return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#b983ff', fontSize: 13, letterSpacing: 4 }}>
      ESTABLISHING SECURE ADMIN LINK...
    </div>
  )

  const tabBtn = (id, label) => (
    <button
      key={id}
      onClick={() => setTab(id)}
      style={{
        padding: '12px 24px', fontSize: 12, textTransform: 'uppercase',
        letterSpacing: 3, cursor: 'pointer', borderRadius: 30,
        background: tab === id ? 'rgba(185,131,255,0.1)' : 'transparent',
        border: tab === id ? '1px solid rgba(185,131,255,0.4)' : '1px solid transparent',
        color: tab === id ? '#b983ff' : 'rgba(255,255,255,0.5)',
        transition: 'all 0.3s ease', outline: 'none'
      }}
      onMouseEnter={(e) => { if (tab !== id) e.target.style.color = '#fff' }}
      onMouseLeave={(e) => { if (tab !== id) e.target.style.color = 'rgba(255,255,255,0.5)' }}
    >
      {label}
    </button>
  )

  return (
    <div style={{ minHeight: '100vh', paddingTop: 60, paddingBottom: 60 }}>

      {/* Topbar */}
      <div style={{
        position: 'fixed', top: 0, left: 0, right: 0,
        display: 'flex', alignItems: 'center', padding: '0 30px',
        height: 60, background: 'rgba(1,2,4,0.9)', borderBottom: '1px solid rgba(185,131,255,0.2)', gap: 15, zIndex: 100, backdropFilter: 'blur(10px)'
      }}>
        <div style={{ fontSize: 18, fontWeight: 300, color: '#fff', letterSpacing: 5 }}>
          SHADOW SPIKE
        </div>
        <span style={{
          background: 'rgba(185,131,255,0.1)', border: '1px solid rgba(185,131,255,0.3)',
          color: '#b983ff', fontSize: 10, padding: '3px 10px', borderRadius: 20, letterSpacing: 2
        }}>ADMIN_PROTOCOL</span>

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 12 }}>
          <button onClick={() => navigate('/dashboard')} className="btn-eclipse btn-secondary" style={{ padding: '6px 15px', fontSize: 10 }}>
            ← USER DASHBOARD
          </button>
          <div style={{
            border: '1px solid rgba(185,131,255,0.3)', background: 'rgba(185,131,255,0.05)',
            borderRadius: 30, color: '#b983ff', padding: '6px 15px',
            fontSize: 11, letterSpacing: 1, display: 'flex', alignItems: 'center', gap: 8
          }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#b983ff', boxShadow: '0 0 10px #b983ff' }}></span>
            {user?.username}
          </div>
          <button onClick={handleLogout} style={{
            background: 'transparent', border: 'none',
            color: 'var(--error-color)', padding: '6px 10px',
            fontSize: 11, cursor: 'pointer', letterSpacing: 2, transition: '0.3s'
          }} onMouseEnter={(e) => e.target.style.textShadow = '0 0 10px var(--error-color)'} onMouseLeave={(e) => e.target.style.textShadow = 'none'}>
            LOGOUT
          </button>
        </div>
      </div>

      <div style={{ padding: '40px 24px', maxWidth: 1300, margin: '0 auto' }}>

        {/* Header */}
        <div style={{ marginBottom: 35, display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center' }}>
          <h1 style={{ fontSize: 28, fontWeight: 300, color: '#fff', letterSpacing: 5 }}>
            NETWORK <span style={{ color: '#b983ff' }}>COMMAND</span> CENTER
          </h1>
          <p style={{ color: 'rgba(255,255,255,0.5)', fontSize: 13, marginTop: 10, letterSpacing: 1 }}>
            Global user administration, activity monitoring, and system metrics.
          </p>
        </div>

        {/* Tabs */}
        <div style={{ display: 'flex', gap: 10, marginBottom: 40, justifyContent: 'center', background: 'var(--glass-bg)', padding: 10, borderRadius: 40, border: '1px solid var(--glass-border)', width: 'fit-content', margin: '0 auto 40px' }}>
          {tabBtn('stats', 'SYSTEM STATS')}
          {tabBtn('users', 'OPERATIVES')}
          {tabBtn('logs', 'AUDIT LOGS')}
        </div>

        {/* ── STATS TAB ── */}
        {tab === 'stats' && stats && (
          <div style={{ animation: 'fade-up 0.4s ease-out' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 20, marginBottom: 30 }}>
              {[
                { label: 'Total Users', val: stats.total_users, color: '#00f2fe' },
                { label: 'Active Users', val: stats.active_users, color: '#00ff88' },
                { label: 'Banned Users', val: stats.banned_users, color: 'var(--error-color)' },
                { label: 'Network Admins', val: stats.admin_count, color: '#b983ff' },
              ].map(s => (
                <div key={s.label} className="eclipse-card" style={{ padding: '30px', display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center' }}>
                  <div style={{ fontSize: 11, letterSpacing: 2, color: 'rgba(255,255,255,0.5)', textTransform: 'uppercase', marginBottom: 15 }}>
                    {s.label}
                  </div>
                  <div style={{ fontSize: 40, fontWeight: 300, color: s.color, textShadow: `0 0 20px ${s.color}66` }}>
                    {s.val}
                  </div>
                </div>
              ))}
            </div>
            
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 20 }}>
              {[
                { label: 'Total Security Scans', val: stats.total_scans, color: '#00f2fe' },
                { label: 'Scans Today', val: stats.scans_today, color: '#ffb347' },
                { label: 'Pending Executions', val: stats.pending_scans, color: 'var(--error-color)' },
              ].map(s => (
                <div key={s.label} className="eclipse-card" style={{ padding: '25px 30px', display: 'flex', alignItems: 'center', gap: 20 }}>
                  <div style={{ width: 12, height: 12, borderRadius: '50%', background: s.color, flexShrink: 0, boxShadow: `0 0 15px ${s.color}` }} />
                  <div>
                    <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.5)', letterSpacing: 2, textTransform: 'uppercase', marginBottom: 5 }}>{s.label}</div>
                    <div style={{ fontSize: 26, fontWeight: 300, color: '#fff' }}>{s.val}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── USERS TAB ── */}
        {tab === 'users' && (
          <div style={{ animation: 'fade-up 0.4s ease-out' }}>
            <div style={{ marginBottom: 25, display: 'flex', justifyContent: 'flex-end' }}>
              <input
                type="text"
                placeholder="SEARCH OPERATIVES..."
                value={search}
                onChange={e => { setSearch(e.target.value); loadUsers(e.target.value) }}
                className="eclipse-input"
                style={{ width: '100%', maxWidth: 400, margin: 0, borderRadius: 30 }}
              />
            </div>

            <div className="eclipse-card" style={{ padding: 0 }}>
              <div style={{
                display: 'grid', gridTemplateColumns: '2fr 2fr 1fr 1fr 1fr 1fr auto',
                gap: 15, padding: '20px', borderBottom: '1px solid var(--glass-border)', background: 'rgba(0,0,0,0.5)'
              }}>
                {['USERNAME', 'EMAIL', 'CLEARANCE', 'STATUS', 'RESTRICTION', 'ESTABLISHED', 'ACTIONS'].map(h => (
                  <div key={h} style={{ fontSize: 10, letterSpacing: 2, color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase' }}>{h}</div>
                ))}
              </div>

              {users.length === 0 ? (
                <div style={{ padding: 50, textAlign: 'center', color: 'rgba(255,255,255,0.3)', fontSize: 13, letterSpacing: 2 }}>
                  NO OPERATIVES FOUND MATCHING CRITERIA.
                </div>
              ) : users.map((u, i) => (
                <div key={u.id} style={{
                  display: 'grid', gridTemplateColumns: '2fr 2fr 1fr 1fr 1fr 1fr auto',
                  gap: 15, padding: '15px 20px', alignItems: 'center',
                  borderBottom: i < users.length - 1 ? '1px solid rgba(255,255,255,0.05)' : 'none',
                  background: u.id === user?.id ? 'rgba(0,242,254,0.02)' : 'transparent',
                  transition: 'background 0.2s'
                }}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
                  onMouseLeave={e => e.currentTarget.style.background = u.id === user?.id ? 'rgba(0,242,254,0.02)' : 'transparent'}
                >
                  <div style={{ fontSize: 13, color: u.id === user?.id ? 'var(--accent-cyan)' : '#fff', letterSpacing: 1 }}>
                    {u.username} {u.id === user?.id && <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.4)' }}>(you)</span>}
                  </div>
                  <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.6)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {u.email}
                  </div>
                  <div>
                    <span style={{
                      fontSize: 10, padding: '4px 10px', borderRadius: 20,
                      background: u.role === 'admin' ? 'rgba(185,131,255,0.1)' : 'rgba(0,242,254,0.05)',
                      border: `1px solid ${u.role === 'admin' ? 'rgba(185,131,255,0.3)' : 'rgba(0,242,254,0.2)'}`,
                      color: u.role === 'admin' ? '#b983ff' : 'var(--accent-cyan)', letterSpacing: 1
                    }}>
                      {u.role?.toUpperCase()}
                    </span>
                  </div>
                  <div>
                    <span style={{
                      fontSize: 10, padding: '4px 10px', borderRadius: 20,
                      background: u.is_active ? 'rgba(0,255,136,0.1)' : 'rgba(255,51,102,0.1)',
                      border: `1px solid ${u.is_active ? 'rgba(0,255,136,0.3)' : 'rgba(255,51,102,0.3)'}`,
                      color: u.is_active ? '#00ff88' : 'var(--error-color)', letterSpacing: 1
                    }}>
                      {u.is_active ? 'ACTIVE' : 'INACTIVE'}
                    </span>
                  </div>
                  <div>
                    {u.is_banned ? (
                      <span style={{
                        fontSize: 10, padding: '4px 10px', borderRadius: 20,
                        background: 'rgba(255,51,102,0.1)', border: '1px solid rgba(255,51,102,0.3)',
                        color: 'var(--error-color)', letterSpacing: 1
                      }}>BANNED</span>
                    ) : <span style={{ color: 'rgba(255,255,255,0.2)' }}>—</span>}
                  </div>
                  <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.5)' }}>
                    {u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    {u.id !== user?.id && (
                      <>
                        <button
                          onClick={() => handleToggleActive(u)}
                          disabled={actionLoading === u.id + '_active'}
                          style={{
                            padding: '6px 12px', fontSize: 10, letterSpacing: 1, textTransform: 'uppercase',
                            cursor: 'pointer', borderRadius: 20, background: 'transparent',
                            border: `1px solid ${u.is_active ? 'rgba(255,179,71,0.5)' : 'rgba(0,255,136,0.4)'}`,
                            color: u.is_active ? '#ffb347' : '#00ff88',
                            opacity: actionLoading === u.id + '_active' ? 0.5 : 1, transition: '0.2s'
                          }}
                          onMouseEnter={e => e.target.style.background = u.is_active ? 'rgba(255,179,71,0.1)' : 'rgba(0,255,136,0.1)'}
                          onMouseLeave={e => e.target.style.background = 'transparent'}
                        >
                          {u.is_active ? 'Suspend' : 'Activate'}
                        </button>
                        <button
                          onClick={() => handleBan(u)}
                          disabled={actionLoading === u.id}
                          style={{
                            padding: '6px 12px', fontSize: 10, letterSpacing: 1, textTransform: 'uppercase',
                            cursor: 'pointer', borderRadius: 20, background: 'transparent',
                            border: `1px solid ${u.is_banned ? 'rgba(0,255,136,0.5)' : 'rgba(255,51,102,0.5)'}`,
                            color: u.is_banned ? '#00ff88' : 'var(--error-color)',
                            opacity: actionLoading === u.id ? 0.5 : 1, transition: '0.2s'
                          }}
                          onMouseEnter={e => e.target.style.background = u.is_banned ? 'rgba(0,255,136,0.1)' : 'rgba(255,51,102,0.1)'}
                          onMouseLeave={e => e.target.style.background = 'transparent'}
                        >
                          {actionLoading === u.id ? '...' : u.is_banned ? 'Unban' : 'Ban'}
                        </button>
                      </>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── AUDIT LOGS TAB ── */}
        {tab === 'logs' && (
          <div style={{ animation: 'fade-up 0.4s ease-out' }}>
            <div className="eclipse-card" style={{ padding: 0 }}>
              <div style={{
                display: 'grid', gridTemplateColumns: '2fr 1.5fr 1fr 1fr 1fr',
                gap: 15, padding: '20px', borderBottom: '1px solid var(--glass-border)', background: 'rgba(0,0,0,0.5)'
              }}>
                {['ACTIVITY DESC', 'AFFECTED RESOURCE', 'NETWORK IP', 'RESOLUTION', 'TIMESTAMP'].map(h => (
                  <div key={h} style={{ fontSize: 10, letterSpacing: 2, color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase' }}>{h}</div>
                ))}
              </div>

              {logs.length === 0 ? (
                <div style={{ padding: 50, textAlign: 'center', color: 'rgba(255,255,255,0.3)', fontSize: 13, letterSpacing: 2 }}>
                  NO IMMINENT SYSTEM ACTIVITIES REGISTERED.
                </div>
              ) : logs.map((l, i) => (
                <div key={l.id} style={{
                  display: 'grid', gridTemplateColumns: '2fr 1.5fr 1fr 1fr 1fr',
                  gap: 15, padding: '15px 20px', alignItems: 'center',
                  borderBottom: i < logs.length - 1 ? '1px solid rgba(255,255,255,0.05)' : 'none',
                  fontSize: 12
                }}>
                  <div style={{ color: '#fff', letterSpacing: 1 }}>{l.action}</div>
                  <div style={{ color: 'var(--accent-cyan)', opacity: 0.8 }}>{l.resource || '—'}</div>
                  <div style={{ color: 'rgba(255,255,255,0.5)' }}>{l.ip_address || '—'}</div>
                  <div>
                    <span style={{
                      fontSize: 10, padding: '4px 10px', borderRadius: 20,
                      background: l.status === 'success' ? 'rgba(0,255,136,0.1)' : 'rgba(255,51,102,0.1)',
                      border: `1px solid ${l.status === 'success' ? 'rgba(0,255,136,0.2)' : 'rgba(255,51,102,0.2)'}`,
                      color: l.status === 'success' ? '#00ff88' : 'var(--error-color)', letterSpacing: 1
                    }}>
                      {l.status?.toUpperCase()}
                    </span>
                  </div>
                  <div style={{ color: 'rgba(255,255,255,0.4)', fontSize: 11, letterSpacing: 1 }}>
                    {new Date(l.created_at).toLocaleString()}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

      </div>
    </div>
  )
}
