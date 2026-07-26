import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import api from '../utils/api'
import useAuthStore from '../store/authStore'

const MODULES = [
  { id: 'port_scan', label: 'Port Scanner', desc: 'Scan open ports & services', color: '#ff3366', path: '/tools/port-scanner', ready: true },
  { id: 'subdomain', label: 'Subdomain Enum', desc: 'Discover subdomains', color: '#00f2fe', path: '/tools/subdomain', ready: true },
  // MITM Proxy and Repeater are hidden from the UI (code preserved, routes still functional internally)
  // { id: 'proxy', label: 'HTTP Proxy', desc: 'Intercept & modify requests', color: '#00ff88', path: '/tools/proxy', ready: true, hidden: true },
  // { id: 'repeater', label: 'Repeater', desc: 'Replay & modify requests', color: '#ffb347', path: '/tools/repeater', ready: true, hidden: true },
  { id: 'decoder', label: 'Decoder', desc: 'Encode / Decode any format', color: '#4facfe', path: '/tools/decoder', ready: true },
  { id: 'xss', label: 'XSS Scanner', desc: 'Find XSS injection points', color: '#a855f7', path: '/tools/xss-scanner', ready: true },
  { id: 'sqli', label: 'SQLi Scanner', desc: 'Detect database vulnerabilities', color: '#ff3366', path: '/tools/sqli-scanner', ready: true },
]

export default function DashboardPage() {
  const navigate = useNavigate()
  const { user, fetchMe, logout, isAdmin } = useAuthStore()
  const [loading, setLoading] = useState(true)
  const [stats, setStats] = useState({ total: 0, done: 0, running: 0, high_risk: 0 })
  const [activities, setActivities] = useState([])
  const [activeFilter, setActiveFilter] = useState('total')
  const [activityLoading, setActivityLoading] = useState(false)

  useEffect(() => {
    const init = async () => {
      const u = await fetchMe()
      if (!u) { navigate('/login'); return }
      await loadDashboardData()
      setLoading(false)
    }
    init()
  }, [])

  const loadDashboardData = async () => {
    try {
      const { data: s } = await api.get('/dashboard/stats')
      setStats(s)
      await fetchActivities(activeFilter)
    } catch (err) {
      console.error('Failed to load dashboard data', err)
    }
  }

  const fetchActivities = async (filter) => {
    setActivityLoading(true)
    try {
      const { data: a } = await api.get(`/dashboard/activity?activity_filter=${filter}`)
      setActivities(a)
    } catch (err) {
      console.error('Failed to fetch activities', err)
    } finally {
      setActivityLoading(false)
    }
  }

  // Refetch activities when filter changes
  useEffect(() => {
    if (!loading) fetchActivities(activeFilter)
  }, [activeFilter])

  const handleLogout = async () => {
    await logout()
    navigate('/login')
    toast.success('Logged out successfully', { style: { background: '#010204', color: '#00f2fe', border: '1px solid #00f2fe' } })
  }

  if (loading) return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-cyan)', fontSize: 13, letterSpacing: 4 }}>
      INITIALIZING WORKSPACE...
    </div>
  )

  return (
    <div style={{ minHeight: '100vh', paddingTop: 60, paddingBottom: 60 }}>

      {/* Topbar */}
      <div style={{
        position: 'fixed', top: 0, left: 0, right: 0,
        display: 'flex', alignItems: 'center', padding: '0 30px',
        height: 60, background: 'rgba(1,2,4,0.8)', borderBottom: '1px solid var(--glass-border)', gap: 15, zIndex: 100, backdropFilter: 'blur(10px)'
      }}>
        <div style={{ fontSize: 18, fontWeight: 300, color: '#fff', letterSpacing: 5 }}>
          SHADOW SPIKE
        </div>
        <span style={{
          background: 'rgba(0,242,254,0.1)', border: '1px solid rgba(0,242,254,0.3)',
          color: 'var(--accent-cyan)', fontSize: 10, padding: '3px 10px', borderRadius: 20, letterSpacing: 2
        }}>v1.0.0</span>

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 12 }}>
          {isAdmin() && (
            <button onClick={() => navigate('/admin')} className="btn-eclipse" style={{ padding: '6px 15px', fontSize: 10, width: 'auto' }}>
              ⚡ ADMIN PANEL
            </button>
          )}
          <div style={{
            background: 'var(--glass-bg)', border: '1px solid var(--glass-border)',
            borderRadius: 30, color: '#fff', padding: '6px 15px',
            fontSize: 11, letterSpacing: 1, display: 'flex', alignItems: 'center', gap: 8
          }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#00ff88', boxShadow: '0 0 10px #00ff88' }}></span>
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

      <div style={{ padding: '40px 24px', maxWidth: 1200, margin: '0 auto' }}>

        {/* Welcome */}
        <div style={{ marginBottom: 40, animation: 'fade-up 0.5s ease-out' }}>
          <h1 style={{ fontSize: 28, fontWeight: 300, color: '#fff', letterSpacing: 3, margin: 0 }}>
            Welcome back, <span style={{ color: 'var(--accent-cyan)' }}>{user?.username}</span>
          </h1>
          <p style={{ color: 'rgba(255,255,255,0.6)', fontSize: 13, marginTop: 10, letterSpacing: 1 }}>
            Access granted to Shadow Spike command center. Select a module below to commence operations.
          </p>
        </div>

        {/* Stats */}
        <div style={{ marginBottom: 50 }}>
          <div style={{ fontSize: 11, letterSpacing: 3, color: 'var(--accent-cyan)', textTransform: 'uppercase', marginBottom: 15, opacity: 0.8 }}>
            System Overview
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 20 }}>
            {[
              { id: 'total', label: 'Total Scans', val: stats.total, color: 'var(--accent-cyan)' },
              { id: 'done', label: 'Completed', val: stats.done, color: '#00ff88' },
              { id: 'running', label: 'Running', val: stats.running, color: '#ffb347' },
              { id: 'high_risk', label: 'High Risk', val: stats.high_risk, color: 'var(--error-color)' },
            ].map(s => (
              <div 
                key={s.id} 
                onClick={() => {
                  setActiveFilter(activeFilter === s.id ? 'total' : s.id);
                  // Smooth scroll to activity log
                  document.getElementById('activity-log-header')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }}
                className={`eclipse-card ${activeFilter === s.id ? 'active-stat-card' : ''}`} 
                style={{ 
                  padding: '25px', display: 'flex', flexDirection: 'column', gap: 10,
                  cursor: 'pointer',
                  border: activeFilter === s.id ? `2px solid ${s.color}` : '1px solid var(--glass-border)',
                  boxShadow: activeFilter === s.id ? `0 0 30px ${s.color}44` : 'none',
                  transform: activeFilter === s.id ? 'translateY(-5px)' : 'none',
                  transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                  position: 'relative',
                  overflow: 'hidden'
                }}
              >
                {activeFilter === s.id && (
                  <div style={{
                    position: 'absolute', top: 0, right: 0, padding: '4px 10px',
                    background: s.color, color: '#000', fontSize: 8, fontWeight: 'bold',
                    letterSpacing: 1, borderRadius: '0 0 0 10px'
                  }}>ACTIVE FILTER</div>
                )}
                <div style={{ fontSize: 11, letterSpacing: 2, color: 'rgba(255,255,255,0.6)', textTransform: 'uppercase' }}>
                  {s.label}
                </div>
                <div style={{ fontSize: 32, fontWeight: 300, color: s.color, textShadow: `0 0 20px ${s.color}` }}>
                  {s.val}
                </div>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 15, fontSize: 10, color: 'rgba(255,255,255,0.3)', letterSpacing: 1, display: 'flex', gap: 15 }}>
            <span>• <b>HIGH RISK:</b> Flagged only when critical services (SSH, FTP, DB, RDP, etc.) are found open.</span>
            <span>• <b>SUBDOMAINS:</b> Categorized as informative (Low Risk) discovery.</span>
          </div>
        </div>

        {/* Modules */}
        <div style={{ marginBottom: 50 }}>
          <div style={{ fontSize: 11, letterSpacing: 3, color: 'var(--accent-cyan)', textTransform: 'uppercase', marginBottom: 15, opacity: 0.8 }}>
            Available Modules
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 20 }}>
            {MODULES.map(m => (
              <div key={m.id} onClick={() => m.ready ? navigate(m.path) : toast('Module initialization required in next phase!', { style: { background: '#010204', color: m.color, border: `1px solid ${m.color}` }})}
                style={{
                  background: 'var(--glass-bg)', border: '1px solid var(--glass-border)',
                  borderLeft: `3px solid ${m.color}`,
                  borderRadius: 12, padding: '20px 25px',
                  cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 20,
                  transition: 'all 0.3s ease', backdropFilter: 'blur(10px)'
                }}
                onMouseEnter={e => {
                  e.currentTarget.style.background = 'rgba(255,255,255,0.05)'
                  e.currentTarget.style.transform = 'translateY(-2px)'
                  e.currentTarget.style.boxShadow = `0 10px 30px rgba(0,0,0,0.5), inset 0 0 20px ${m.color}22`
                }}
                onMouseLeave={e => {
                  e.currentTarget.style.background = 'var(--glass-bg)'
                  e.currentTarget.style.transform = 'translateY(0)'
                  e.currentTarget.style.boxShadow = 'none'
                }}
              >
                <div style={{ width: 12, height: 12, borderRadius: '50%', background: m.color, flexShrink: 0, boxShadow: `0 0 15px ${m.color}` }}></div>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 400, color: '#fff', letterSpacing: 1 }}>{m.label}</div>
                  <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.5)', marginTop: 6 }}>{m.desc}</div>
                </div>
                <div style={{ marginLeft: 'auto', color: 'rgba(255,255,255,0.2)', fontSize: 18, transition: '0.3s' }}>▶</div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Scans */}
        <div>
          <div id="activity-log-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 15 }}>
            <div style={{ fontSize: 11, letterSpacing: 3, color: 'var(--accent-cyan)', textTransform: 'uppercase', opacity: 0.8 }}>
              Recent Activity Log {activeFilter !== 'total' && <span style={{ color: '#fff', marginLeft: 10, opacity: 0.5 }}>— {activeFilter.toUpperCase()} ONLY</span>}
            </div>
            {activeFilter !== 'total' && (
              <button 
                onClick={() => setActiveFilter('total')}
                style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: 'var(--accent-cyan)', fontSize: 9, cursor: 'pointer', letterSpacing: 1, padding: '4px 10px', borderRadius: 4, transition: '0.2s' }}
                onMouseEnter={e => e.target.style.background = 'rgba(255,255,255,0.1)'}
                onMouseLeave={e => e.target.style.background = 'rgba(255,255,255,0.05)'}
              >
                VIEW ALL HISTORY
              </button>
            )}
          </div>
          
          {activityLoading ? (
            <div className="eclipse-card" style={{ padding: 40, textAlign: 'center' }}>
              <div className="spinner" style={{ margin: '0 auto 15px' }} />
              <div style={{ color: 'rgba(255,255,255,0.3)', fontSize: 11, letterSpacing: 2 }}>FETCHING CLASSIFIED LOGS...</div>
            </div>
          ) : activities.length === 0 ? (
            <div className="eclipse-card" style={{ padding: 40, textAlign: 'center' }}>
              <div style={{ color: 'rgba(255,255,255,0.4)', fontSize: 13, letterSpacing: 2 }}>
                {activeFilter === 'total' ? 'AWAITING MODULE EXECUTION.' : `NO ${activeFilter.toUpperCase()} ACTIVITY FOUND.`}
              </div>
            </div>
          ) : (
            <div className="eclipse-card" style={{ padding: 0, animation: 'fade-in 0.3s' }}>
              {activities.map((a, i) => {
                const isHighRisk = a.result_summary?.toLowerCase().includes('high');
                const path = a.action.toLowerCase().includes('port') ? '/tools/port-scanner' : '/tools/subdomain';
                
                return (
                  <div key={a.id} 
                    onClick={() => navigate(`${path}?scan_id=${a.id}`)}
                    style={{
                      padding: '15px 25px', 
                      borderBottom: i < activities.length - 1 ? '1px solid var(--glass-border)' : 'none',
                      display: 'flex', alignItems: 'center', gap: 20,
                      cursor: 'pointer',
                      transition: 'all 0.2s',
                    }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', width: 80 }}>
                      {new Date(a.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <div style={{ fontSize: 13, color: '#fff', letterSpacing: 1 }}>{a.action}</div>
                        {isHighRisk && (
                          <span style={{ fontSize: 9, color: 'var(--error-color)', border: '1px solid var(--error-color)', padding: '1px 6px', borderRadius: 4, letterSpacing: 1, fontWeight: 'bold' }}>HIGH RISK</span>
                        )}
                      </div>
                      <div style={{ fontSize: 11, color: isHighRisk ? 'var(--error-color)' : 'rgba(255,255,255,0.5)', marginTop: 2, opacity: isHighRisk ? 0.8 : 1 }}>
                        {isHighRisk ? a.result_summary : `Target: ${a.target}`}
                      </div>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      <div style={{ 
                        fontSize: 10, padding: '3px 10px', borderRadius: 20, 
                        background: a.status === 'completed' ? 'rgba(0,255,136,0.1)' : 'rgba(255,179,71,0.1)',
                        border: `1px solid ${a.status === 'completed' ? 'rgba(0,255,136,0.2)' : 'rgba(255,179,71,0.2)'}`,
                        color: a.status === 'completed' ? '#00ff88' : '#ffb347'
                      }}>
                        {a.status.toUpperCase()}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

      </div>
    </div>
  )
}