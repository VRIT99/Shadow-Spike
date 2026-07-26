import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import api from '../utils/api'
import useAuthStore from '../store/authStore'
import { sanitizeDomain, sanitizePorts } from '../utils/sanitize'

const SCAN_TYPES = [
  { id: 'quick', label: 'QUICK SCAN', desc: 'Top 100 ports', time: '~10s' },
  { id: 'standard', label: 'STANDARD', desc: 'Top 1000+ ports', time: '~60s' },
  { id: 'full', label: 'FULL SWEEP', desc: 'All 65535 ports', time: '~5min' },
  { id: 'custom', label: 'CUSTOM', desc: 'Specify ports', time: 'varies' },
]

const RISK_COLORS = {
  critical: '#ff0040',
  high: '#ff3366',
  medium: '#ffb347',
  low: '#00ff88',
}

export default function PortScannerPage() {
  const navigate = useNavigate()
  const { user, fetchMe, logout } = useAuthStore()
  const [loading, setLoading] = useState(true)

  // Scan config
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('quick')
  const [customPorts, setCustomPorts] = useState('')
  const [scanning, setScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [activeWs, setActiveWs] = useState(null)

  // Results
  const [currentResult, setCurrentResult] = useState(null)

  // History
  const [history, setHistory] = useState([])
  const [showHistory, setShowHistory] = useState(false)

  useEffect(() => {
    const init = async () => {
      const u = await fetchMe()
      if (!u) { navigate('/login'); return }
      setLoading(false)
      loadHistory()
      
      // Auto-load scan if scan_id is in URL
      const params = new URLSearchParams(window.location.search);
      const scanId = params.get('scan_id');
      if (scanId) {
        loadScan(scanId);
      }
    }
    init()
  }, [])

  const loadHistory = async () => {
    try {
      const { data } = await api.get('/scanner/scans')
      setHistory(data.scans)
    } catch {}
  }

  const handleScan = async () => {
    if (!target.trim()) {
      toast.error('Enter a target IP or hostname', { style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } })
      return
    }
    setScanning(true)
    setScanProgress(0)

    const token = localStorage.getItem('access_token')
    if (!token) {
      toast.error('Unauthorized: No access token found');
      setScanning(false);
      return;
    }

    let liveResult = {
      target: target.trim(),
      scan_type: scanType,
      ports: [],
      total_open: 0,
      total_closed: 0,
      total_filtered: 0,
      risk_level: 'low',
      scan_duration: null
    };
    setCurrentResult(liveResult);

    const wsUrl = 'ws://127.0.0.1:8000/api/v1/scanner/ws/scan'
    const ws = new WebSocket(wsUrl);
    setActiveWs(ws)

    ws.onopen = () => {
      ws.send(JSON.stringify({
        token,
        target: target.trim(),
        scan_type: scanType,
        ports: scanType === 'custom' ? customPorts : undefined
      }));
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.error) {
          toast.error(msg.error, { style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } });
          ws.close();
          setScanning(false);
          return;
        }

        if (msg.type === 'progress') {
          setScanProgress(msg.progress);
        } else if (msg.type === 'port_found') {
          setCurrentResult(prev => {
            if (!prev) return prev;
            if (prev.ports.some(p => p.port === msg.data.port)) return prev;
            return {
              ...prev,
              ports: [...prev.ports, msg.data].sort((a,b) => a.port - b.port),
              total_open: prev.total_open + 1
            };
          });
        } else if (msg.type === 'port_updated') {
          setCurrentResult(prev => {
            if (!prev) return prev;
            const newPorts = prev.ports.map(p => p.port === msg.data.port ? msg.data : p);
            return { ...prev, ports: newPorts };
          });
        } else if (msg.type === 'complete') {
          setCurrentResult(msg.data);
          setScanProgress(100);
          setScanning(false);
          loadHistory();
          toast.success(`Scan complete: ${msg.data.total_open} open ports found`, { style: { background: '#010204', color: '#00f2fe', border: '1px solid #00f2fe' } });
          ws.close();
        }
      } catch (e) {
        console.error("WS parse error", e);
      }
    };

    ws.onerror = (error) => {
      toast.error('WebSocket connection lost', { style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } });
      setScanning(false);
      ws.close();
    };

    ws.onclose = () => {
      setScanning(false);
      setActiveWs(null);
    };
  }

  const handleCancel = () => {
    if (activeWs && activeWs.readyState === WebSocket.OPEN) {
      activeWs.send(JSON.stringify({ action: "stop" }));
      toast('Cancelling scan...', { icon: '🛑', style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } });
    }
  }

  const loadScan = async (scanId) => {
    try {
      const { data } = await api.get(`/scanner/scans/${scanId}`)
      setCurrentResult(data)
      setShowHistory(false)
    } catch {
      toast.error('Failed to load scan')
    }
  }

  const deleteScan = async (scanId) => {
    try {
      await api.delete(`/scanner/scans/${scanId}`)
      toast.success('Scan deleted', { style: { background: '#010204', color: '#00f2fe', border: '1px solid #00f2fe' } })
      loadHistory()
      if (currentResult?.id === scanId) setCurrentResult(null)
    } catch {
      toast.error('Delete failed')
    }
  }

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  if (loading) return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-cyan)', fontSize: 13, letterSpacing: 4 }}>
      INITIALIZING PORT SCANNER...
    </div>
  )

  return (
    <div style={{ minHeight: '100vh', paddingTop: 60, paddingBottom: 60 }}>

      {/* Topbar */}
      <div style={{
        position: 'fixed', top: 0, left: 0, right: 0,
        display: 'flex', alignItems: 'center', padding: '0 30px',
        height: 60, background: 'rgba(1,2,4,0.9)', borderBottom: '1px solid var(--glass-border)', gap: 15, zIndex: 100, backdropFilter: 'blur(10px)'
      }}>
        <div onClick={() => navigate('/dashboard')} style={{ fontSize: 18, fontWeight: 300, color: '#fff', letterSpacing: 5, cursor: 'pointer' }}>
          SHADOW SPIKE
        </div>
        <span style={{ color: 'rgba(255,255,255,0.3)' }}>›</span>
        <span style={{
          background: 'rgba(255,51,102,0.1)', border: '1px solid rgba(255,51,102,0.3)',
          color: '#ff3366', fontSize: 10, padding: '3px 10px', borderRadius: 20, letterSpacing: 2
        }}>PORT SCANNER</span>

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 12 }}>
          <button onClick={() => setShowHistory(!showHistory)} className="btn-eclipse" style={{ padding: '6px 15px', fontSize: 10, width: 'auto', background: showHistory ? 'rgba(0,242,254,0.1)' : 'transparent' }}>
            📋 HISTORY ({history.length})
          </button>
          <button onClick={() => navigate('/dashboard')} className="btn-eclipse btn-secondary" style={{ padding: '6px 15px', fontSize: 10 }}>
            ← DASHBOARD
          </button>
        </div>
      </div>

      <div style={{ padding: '30px 24px', maxWidth: 1300, margin: '0 auto' }}>

        {/* Page Title */}
        <div style={{ marginBottom: 35 }}>
          <h1 style={{ fontSize: 26, fontWeight: 300, color: '#fff', letterSpacing: 4, margin: 0 }}>
            PORT <span style={{ color: '#ff3366' }}>SCANNER</span>
          </h1>
          <p style={{ color: 'rgba(255,255,255,0.5)', fontSize: 13, marginTop: 10, letterSpacing: 1 }}>
            Analyze target network surfaces for open ports, running services, and security vulnerabilities.
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: showHistory ? '1fr 350px' : '1fr', gap: 25 }}>
          <div>
            {/* Scan Configuration */}
            <div className="eclipse-card" style={{ marginBottom: 25, padding: 30 }}>
              <div style={{ fontSize: 11, letterSpacing: 3, color: '#ff3366', textTransform: 'uppercase', marginBottom: 20 }}>
                SCAN CONFIGURATION
              </div>

              {/* Target Input */}
              <div style={{ marginBottom: 20 }}>
                <label style={{ display: 'block', color: '#a1c4fd', fontSize: 11, letterSpacing: 2, marginBottom: 8, textTransform: 'uppercase' }}>
                  TARGET HOST
                </label>
                <input
                  type="text"
                  className="eclipse-input"
                  value={target}
                  onChange={e => setTarget(sanitizeDomain(e.target.value))}
                  placeholder="127.0.0.1 or scanme.nmap.org"
                  disabled={scanning}
                  style={{ marginBottom: 0, fontSize: 16, letterSpacing: 2 }}
                  onKeyDown={e => e.key === 'Enter' && !scanning && handleScan()}
                />
              </div>

              {/* Scan Type */}
              <div style={{ marginBottom: 20 }}>
                <label style={{ display: 'block', color: '#a1c4fd', fontSize: 11, letterSpacing: 2, marginBottom: 12, textTransform: 'uppercase' }}>
                  SCAN MODE
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
                  {SCAN_TYPES.map(st => (
                    <div
                      key={st.id}
                      onClick={() => !scanning && setScanType(st.id)}
                      style={{
                        padding: '15px', borderRadius: 10, cursor: scanning ? 'not-allowed' : 'pointer',
                        background: scanType === st.id ? 'rgba(255,51,102,0.1)' : 'var(--glass-bg)',
                        border: `1px solid ${scanType === st.id ? 'rgba(255,51,102,0.4)' : 'var(--glass-border)'}`,
                        transition: 'all 0.3s', textAlign: 'center'
                      }}
                    >
                      <div style={{ fontSize: 12, color: scanType === st.id ? '#ff3366' : '#fff', letterSpacing: 2, marginBottom: 4 }}>{st.label}</div>
                      <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.4)' }}>{st.desc}</div>
                      <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.25)', marginTop: 4 }}>{st.time}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Custom Ports */}
              {scanType === 'custom' && (
                <div style={{ marginBottom: 20 }}>
                  <label style={{ display: 'block', color: '#a1c4fd', fontSize: 11, letterSpacing: 2, marginBottom: 8, textTransform: 'uppercase' }}>
                    PORT RANGE
                  </label>
                  <input
                    type="text"
                    className="eclipse-input"
                    value={customPorts}
                    onChange={e => setCustomPorts(sanitizePorts(e.target.value))}
                    placeholder="80, 443, 8000-8100"
                    disabled={scanning}
                    style={{ marginBottom: 0 }}
                  />
                </div>
              )}

              {/* Scan Button */}
              {scanning ? (
                <button
                  onClick={handleCancel}
                  className="btn-eclipse"
                  style={{
                    background: 'rgba(255,51,102,0.15)',
                    borderColor: '#ff3366', color: '#ff3366',
                    marginTop: 5
                  }}
                >
                  🛑 CANCEL SCAN
                </button>
              ) : (
                <button
                  onClick={handleScan}
                  disabled={scanning}
                  className="btn-eclipse"
                  style={{
                    background: 'rgba(255,51,102,0.1)',
                    borderColor: '#ff3366', color: '#ff3366',
                    marginTop: 5
                  }}
                >
                  ▶ INITIATE PORT SCAN
                </button>
              )}

              {/* Progress Bar */}
              {scanning && (
                <div style={{ marginTop: 20 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                    <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.5)', letterSpacing: 2 }}>SCANNING IN PROGRESS</span>
                    <span style={{ fontSize: 10, color: '#ff3366', letterSpacing: 1 }}>{Math.round(scanProgress)}%</span>
                  </div>
                  <div style={{ width: '100%', height: 3, background: 'rgba(255,255,255,0.05)', borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{
                      width: `${scanProgress}%`, height: '100%',
                      background: 'linear-gradient(90deg, #ff3366, #ff0040)',
                      boxShadow: '0 0 10px #ff3366',
                      transition: 'width 0.3s ease', borderRadius: 2
                    }} />
                  </div>
                </div>
              )}
            </div>

            {/* Results */}
            {currentResult && (
              <div style={{ animation: 'fade-up 0.4s ease-out' }}>

                {/* Stats Row */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 15, marginBottom: 25 }}>
                  <div className="eclipse-card" style={{ padding: 20, textAlign: 'center' }}>
                    <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.5)', letterSpacing: 2, marginBottom: 8 }}>OPEN PORTS</div>
                    <div style={{ fontSize: 32, fontWeight: 300, color: '#00ff88', textShadow: '0 0 15px rgba(0,255,136,0.4)' }}>{currentResult.total_open}</div>
                  </div>
                  <div className="eclipse-card" style={{ padding: 20, textAlign: 'center' }}>
                    <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.5)', letterSpacing: 2, marginBottom: 8 }}>CLOSED</div>
                    <div style={{ fontSize: 32, fontWeight: 300, color: 'rgba(255,255,255,0.3)' }}>{currentResult.total_closed}</div>
                  </div>
                  <div className="eclipse-card" style={{ padding: 20, textAlign: 'center' }}>
                    <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.5)', letterSpacing: 2, marginBottom: 8 }}>FILTERED</div>
                    <div style={{ fontSize: 32, fontWeight: 300, color: '#ffb347' }}>{currentResult.total_filtered}</div>
                  </div>
                  <div className="eclipse-card" style={{ padding: 20, textAlign: 'center' }}>
                    <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.5)', letterSpacing: 2, marginBottom: 8 }}>RISK LEVEL</div>
                    <div style={{
                      fontSize: 18, fontWeight: 400, letterSpacing: 3,
                      color: RISK_COLORS[currentResult.risk_level] || '#fff',
                      textShadow: `0 0 15px ${RISK_COLORS[currentResult.risk_level]}66`
                    }}>
                      {(currentResult.risk_level || 'N/A').toUpperCase()}
                    </div>
                  </div>
                  {currentResult.scan_duration && (
                    <div className="eclipse-card" style={{ padding: 20, textAlign: 'center' }}>
                      <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.5)', letterSpacing: 2, marginBottom: 8 }}>DURATION</div>
                      <div style={{ fontSize: 24, fontWeight: 300, color: 'var(--accent-cyan)' }}>{currentResult.scan_duration}s</div>
                    </div>
                  )}
                </div>

                {/* Port Table */}
                {currentResult.ports && currentResult.ports.length > 0 ? (
                  <div className="eclipse-card" style={{ padding: 0 }}>
                    <div style={{ padding: '20px 25px', borderBottom: '1px solid var(--glass-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ fontSize: 11, letterSpacing: 3, color: '#ff3366', textTransform: 'uppercase' }}>
                        OPEN PORT ANALYSIS — {currentResult.target}
                      </div>
                      <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.4)', letterSpacing: 1 }}>
                        {currentResult.ports.length} PORT{currentResult.ports.length !== 1 ? 'S' : ''} FOUND
                      </div>
                    </div>

                    {/* Table Header */}
                    <div style={{
                      display: 'grid', gridTemplateColumns: '100px 100px 1fr 1fr',
                      gap: 15, padding: '15px 25px', borderBottom: '1px solid var(--glass-border)', background: 'rgba(0,0,0,0.3)'
                    }}>
                      {['PORT', 'STATE', 'SERVICE', 'VERSION'].map(h => (
                        <div key={h} style={{ fontSize: 10, letterSpacing: 2, color: 'rgba(255,255,255,0.4)' }}>{h}</div>
                      ))}
                    </div>

                    {/* Table Rows */}
                    {currentResult.ports.map((p, i) => (
                      <div key={p.port} style={{
                        display: 'grid', gridTemplateColumns: '100px 100px 1fr 1fr',
                        gap: 15, padding: '12px 25px', alignItems: 'center',
                        borderBottom: i < currentResult.ports.length - 1 ? '1px solid rgba(255,255,255,0.03)' : 'none',
                        transition: 'background 0.2s'
                      }}
                        onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
                        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                      >
                        <div style={{ fontSize: 14, color: '#fff', fontFamily: 'monospace', letterSpacing: 2 }}>{p.port}</div>
                        <div>
                          <span style={{
                            fontSize: 10, padding: '3px 10px', borderRadius: 20, letterSpacing: 1,
                            background: p.state === 'open' ? 'rgba(0,255,136,0.1)' : p.state === 'filtered' ? 'rgba(255,179,71,0.1)' : 'rgba(255,51,102,0.1)',
                            border: `1px solid ${p.state === 'open' ? 'rgba(0,255,136,0.3)' : p.state === 'filtered' ? 'rgba(255,179,71,0.3)' : 'rgba(255,51,102,0.3)'}`,
                            color: p.state === 'open' ? '#00ff88' : p.state === 'filtered' ? '#ffb347' : '#ff3366'
                          }}>
                            {p.state.toUpperCase()}
                          </span>
                        </div>
                        <div style={{ fontSize: 13, color: 'var(--accent-cyan)', letterSpacing: 1 }}>{p.service}</div>
                        <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.4)' }}>{p.version || '—'}</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="eclipse-card" style={{ padding: 50, textAlign: 'center' }}>
                    <div style={{ fontSize: 14, color: 'rgba(255,255,255,0.4)', letterSpacing: 2 }}>
                      NO OPEN PORTS DETECTED ON TARGET.
                    </div>
                    <div style={{ fontSize: 11, color: '#00ff88', marginTop: 10, letterSpacing: 2 }}>
                      TARGET APPEARS SECURE.
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Empty state */}
            {!currentResult && !scanning && (
              <div className="eclipse-card" style={{ padding: 80, textAlign: 'center' }}>
                <div style={{ fontSize: 50, marginBottom: 20, opacity: 0.2 }}>⚡</div>
                <div style={{ fontSize: 16, color: 'rgba(255,255,255,0.4)', letterSpacing: 3, marginBottom: 10 }}>
                  AWAITING TARGET DESIGNATION
                </div>
                <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.25)', letterSpacing: 1 }}>
                  Enter a target IP address or hostname above and initiate a scan.
                </div>
              </div>
            )}
          </div>

          {/* History Sidebar */}
          {showHistory && (
            <div style={{ animation: 'fade-up 0.3s ease-out' }}>
              <div style={{ fontSize: 11, letterSpacing: 3, color: 'var(--accent-cyan)', textTransform: 'uppercase', marginBottom: 15 }}>
                SCAN HISTORY
              </div>
              {history.length === 0 ? (
                <div className="eclipse-card" style={{ padding: 30, textAlign: 'center' }}>
                  <div style={{ color: 'rgba(255,255,255,0.3)', fontSize: 12, letterSpacing: 2 }}>NO PREVIOUS SCANS</div>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {history.map(h => (
                    <div key={h.id} className="eclipse-card" style={{
                      padding: 18, cursor: 'pointer',
                      borderLeft: `3px solid ${RISK_COLORS[h.risk_level] || 'var(--glass-border)'}`,
                    }}
                      onClick={() => loadScan(h.id)}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                        <div style={{ fontSize: 13, color: '#fff', letterSpacing: 1 }}>{h.target}</div>
                        <button onClick={(e) => { e.stopPropagation(); deleteScan(h.id) }} style={{
                          background: 'transparent', border: 'none', color: 'rgba(255,255,255,0.2)',
                          cursor: 'pointer', fontSize: 14, padding: '2px 5px', transition: '0.2s'
                        }}
                          onMouseEnter={e => e.target.style.color = '#ff3366'}
                          onMouseLeave={e => e.target.style.color = 'rgba(255,255,255,0.2)'}
                        >✕</button>
                      </div>
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                        <span style={{
                          fontSize: 9, padding: '2px 8px', borderRadius: 10,
                          background: 'rgba(255,51,102,0.1)', border: '1px solid rgba(255,51,102,0.2)', color: '#ff3366', letterSpacing: 1
                        }}>{h.scan_type}</span>
                        <span style={{
                          fontSize: 9, padding: '2px 8px', borderRadius: 10,
                          background: `${RISK_COLORS[h.risk_level]}15`, border: `1px solid ${RISK_COLORS[h.risk_level]}40`,
                          color: RISK_COLORS[h.risk_level], letterSpacing: 1
                        }}>{h.risk_level?.toUpperCase() || 'N/A'}</span>
                        <span style={{ fontSize: 9, color: 'rgba(255,255,255,0.3)', letterSpacing: 1 }}>
                          {h.total_open} open
                        </span>
                      </div>
                      <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.25)', marginTop: 8, letterSpacing: 1 }}>
                        {new Date(h.created_at).toLocaleString()}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

      </div>
    </div>
  )
}
