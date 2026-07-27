import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import api from '../utils/api'
import useAuthStore from '../store/authStore'
import { sanitizeDomain } from '../utils/sanitize'
import { getWsUrl } from '../utils/api'

const SCAN_TYPES = [
  { id: 'quick', label: 'QUICK', desc: '~50 common subdomains', time: '~15s' },
  { id: 'standard', label: 'STANDARD', desc: '~170 subdomains', time: '~45s' },
  { id: 'deep', label: 'DEEP RECON', desc: '250+ with variants', time: '~2min' },
]

const STATUS_COLORS = {
  200: '#00ff88', 201: '#00ff88', 204: '#00ff88',
  301: '#4facfe', 302: '#4facfe', 304: '#4facfe',
  401: '#ffb347', 403: '#ffb347',
  404: '#ff3366', 500: '#ff3366', 502: '#ff3366', 503: '#ff3366',
}

export default function SubdomainPage() {
  const navigate = useNavigate()
  const { fetchMe } = useAuthStore()
  const [loading, setLoading] = useState(true)

  const [domain, setDomain] = useState('')
  const [scanType, setScanType] = useState('quick')
  const [useCrtsh, setUseCrtsh] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [activeWs, setActiveWs] = useState(null)

  const [currentResult, setCurrentResult] = useState(null)
  const [history, setHistory] = useState([])
  const [showHistory, setShowHistory] = useState(false)
  const [filter, setFilter] = useState('all') // all, live, crtsh

  // Dynamic column resizing
  const DEFAULT_WIDTHS = [280, 160, 100, 200, 120]
  const [columnWidths, setColumnWidths] = useState(DEFAULT_WIDTHS)
  const isResizing = useRef(-1)
  const startX = useRef(0)
  const startWidth = useRef(0)

  const handleMouseDown = (index, e) => {
    isResizing.current = index
    startX.current = e.clientX
    startWidth.current = columnWidths[index]
    document.addEventListener('mousemove', handleMouseMove)
    document.addEventListener('mouseup', handleMouseUp)
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
  }

  const handleMouseMove = (e) => {
    if (isResizing.current === -1) return
    const diff = e.clientX - startX.current
    const newWidths = [...columnWidths]
    newWidths[isResizing.current] = Math.max(80, startWidth.current + diff)
    setColumnWidths(newWidths)
  }

  const handleMouseUp = () => {
    isResizing.current = -1
    document.removeEventListener('mousemove', handleMouseMove)
    document.removeEventListener('mouseup', handleMouseUp)
    document.body.style.cursor = 'default'
    document.body.style.userSelect = 'auto'
  }

  const gridTemplateColumns = columnWidths.map(w => `${w}px`).join(' ')

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
      const { data } = await api.get('/subdomain/scans')
      setHistory(data.scans)
    } catch {}
  }

  const handleScan = async () => {
    if (!domain.trim()) {
      toast.error('Enter a target domain', { style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } })
      return
    }

    const token = localStorage.getItem('access_token')
    if (!token) {
      toast.error('Unauthorized: No access token found');
      return;
    }

    setScanning(true)
    setScanProgress(0)

    let liveResult = {
      domain: domain.trim(),
      scan_type: scanType,
      subdomains: [],
      total_found: 0,
      scan_duration: null
    };
    setCurrentResult(liveResult);

    const wsUrl = getWsUrl('/api/v1/subdomain/ws/scan')
    const ws = new WebSocket(wsUrl);
    setActiveWs(ws);

    ws.onopen = () => {
      ws.send(JSON.stringify({
        token,
        domain: domain.trim(),
        scan_type: scanType
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
          // Progress can be emitted if we want, but currently not handled for subdomain.
          // Wait, subdomain doesn't emit 'progress' yet, we can ignore or add later.
        } else if (msg.type === 'subdomain_found') {
          setCurrentResult(prev => {
            if (!prev) return prev;
            if (prev.subdomains.some(s => s.subdomain === msg.data.subdomain)) return prev;
            return {
              ...prev,
              subdomains: [...prev.subdomains, msg.data].sort((a,b) => a.subdomain.localeCompare(b.subdomain)),
              total_found: prev.total_found + 1
            };
          });
        } else if (msg.type === 'subdomain_updated') {
          setCurrentResult(prev => {
            if (!prev) return prev;
            const newSubs = prev.subdomains.map(s => s.subdomain === msg.data.subdomain ? { ...s, ...msg.data } : s);
            return { ...prev, subdomains: newSubs };
          });
        } else if (msg.type === 'complete') {
          setCurrentResult(msg.data);
          setScanProgress(100);
          setScanning(false);
          loadHistory();
          toast.success(`Scan complete: ${msg.data.total_found} subdomains found`, { style: { background: '#010204', color: '#00f2fe', border: '1px solid #00f2fe' } });
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
      toast('Cancelling scan...', { icon: '🛑', style: { background: '#010204', color: '#00f2fe', border: '1px solid #00f2fe' } });
    }
  }

  const loadScan = async (scanId) => {
    try {
      const { data } = await api.get(`/subdomain/scans/${scanId}`)
      setCurrentResult(data)
      setShowHistory(false)
    } catch { toast.error('Failed to load scan') }
  }

  const deleteScan = async (scanId) => {
    try {
      await api.delete(`/subdomain/scans/${scanId}`)
      toast.success('Scan deleted', { style: { background: '#010204', color: '#00f2fe', border: '1px solid #00f2fe' } })
      loadHistory()
      if (currentResult?.id === scanId) setCurrentResult(null)
    } catch { toast.error('Delete failed') }
  }

  const getStatusColor = (code) => STATUS_COLORS[code] || 'rgba(255,255,255,0.3)'

  const filteredSubs = currentResult?.subdomains?.filter(s => {
    if (filter === 'live') return s.status_code && s.status_code < 400
    if (filter === 'osint') return s.source === 'crtsh' || s.source === 'osint'
    return true
  }) || []

  if (loading) return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#00f2fe', fontSize: 13, letterSpacing: 4 }}>
      INITIALIZING SUBDOMAIN RECON...
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
          background: 'rgba(0,242,254,0.1)', border: '1px solid rgba(0,242,254,0.3)',
          color: '#00f2fe', fontSize: 10, padding: '3px 10px', borderRadius: 20, letterSpacing: 2
        }}>SUBDOMAIN ENUM</span>

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

        {/* Title */}
        <div style={{ marginBottom: 35 }}>
          <h1 style={{ fontSize: 26, fontWeight: 300, color: '#fff', letterSpacing: 4, margin: 0 }}>
            SUBDOMAIN <span style={{ color: '#00f2fe' }}>ENUMERATION</span>
          </h1>
          <p style={{ color: 'rgba(255,255,255,0.5)', fontSize: 13, marginTop: 10, letterSpacing: 1 }}>
            Discover hidden subdomains via DNS brute-force and Certificate Transparency log analysis.
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: showHistory ? '1fr 350px' : '1fr', gap: 25 }}>
          <div>
            {/* Config */}
            <div className="eclipse-card" style={{ marginBottom: 25, padding: 30 }}>
              <div style={{ fontSize: 11, letterSpacing: 3, color: '#00f2fe', textTransform: 'uppercase', marginBottom: 20 }}>
                TARGET CONFIGURATION
              </div>

              <div style={{ marginBottom: 20 }}>
                <label style={{ display: 'block', color: '#a1c4fd', fontSize: 11, letterSpacing: 2, marginBottom: 8, textTransform: 'uppercase' }}>
                  TARGET DOMAIN
                </label>
                <input type="text" className="eclipse-input" value={domain} onChange={e => setDomain(sanitizeDomain(e.target.value))} placeholder="example.com" disabled={scanning} style={{ marginBottom: 0, fontSize: 16, letterSpacing: 2 }} onKeyDown={e => e.key === 'Enter' && !scanning && handleScan()} />
              </div>

              {/* Scan Type */}
              <div style={{ marginBottom: 20 }}>
                <label style={{ display: 'block', color: '#a1c4fd', fontSize: 11, letterSpacing: 2, marginBottom: 12, textTransform: 'uppercase' }}>
                  RECON DEPTH
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
                  {SCAN_TYPES.map(st => (
                    <div key={st.id} onClick={() => !scanning && setScanType(st.id)} style={{
                      padding: '15px', borderRadius: 10, cursor: scanning ? 'not-allowed' : 'pointer',
                      background: scanType === st.id ? 'rgba(0,242,254,0.1)' : 'var(--glass-bg)',
                      border: `1px solid ${scanType === st.id ? 'rgba(0,242,254,0.4)' : 'var(--glass-border)'}`,
                      transition: 'all 0.3s', textAlign: 'center'
                    }}>
                      <div style={{ fontSize: 12, color: scanType === st.id ? '#00f2fe' : '#fff', letterSpacing: 2, marginBottom: 4 }}>{st.label}</div>
                      <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.4)' }}>{st.desc}</div>
                      <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.25)', marginTop: 4 }}>{st.time}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* crt.sh toggle */}
              <div style={{ marginBottom: 20, display: 'flex', alignItems: 'center', gap: 12 }}>
                <div onClick={() => !scanning && setUseCrtsh(!useCrtsh)} style={{
                  width: 44, height: 24, borderRadius: 12, cursor: scanning ? 'not-allowed' : 'pointer',
                  background: useCrtsh ? 'rgba(0,242,254,0.3)' : 'rgba(255,255,255,0.1)',
                  border: `1px solid ${useCrtsh ? 'rgba(0,242,254,0.5)' : 'var(--glass-border)'}`,
                  position: 'relative', transition: 'all 0.3s'
                }}>
                  <div style={{
                    width: 18, height: 18, borderRadius: '50%', position: 'absolute', top: 2,
                    left: useCrtsh ? 22 : 2, transition: 'all 0.3s',
                    background: useCrtsh ? '#00f2fe' : 'rgba(255,255,255,0.4)',
                    boxShadow: useCrtsh ? '0 0 10px #00f2fe' : 'none'
                  }} />
                </div>
                <div>
                  <div style={{ fontSize: 12, color: '#fff', letterSpacing: 1 }}>Certificate Transparency</div>
                  <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.4)', marginTop: 2 }}>Query crt.sh public logs for additional subdomains</div>
                </div>
              </div>

              {scanning ? (
                <button onClick={handleCancel} className="btn-eclipse" style={{
                  background: 'rgba(255,51,102,0.15)',
                  borderColor: '#ff3366', color: '#ff3366', marginTop: 5
                }}>
                  🛑 CANCEL SCAN
                </button>
              ) : (
                <button onClick={handleScan} disabled={scanning} className="btn-eclipse" style={{
                  background: 'rgba(0,242,254,0.1)',
                  borderColor: '#00f2fe', color: '#00f2fe', marginTop: 5
                }}>
                  ▶ START ENUMERATION
                </button>
              )}

              {scanning && (
                <div style={{ marginTop: 20 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                    <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.5)', letterSpacing: 2 }}>RESOLVING DNS RECORDS</span>
                    <span style={{ fontSize: 10, color: '#00f2fe', letterSpacing: 1 }}>{Math.round(scanProgress)}%</span>
                  </div>
                  <div style={{ width: '100%', height: 3, background: 'rgba(255,255,255,0.05)', borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{
                      width: `${scanProgress}%`, height: '100%',
                      background: 'linear-gradient(90deg, #00f2fe, #4facfe)',
                      boxShadow: '0 0 10px #00f2fe', transition: 'width 0.3s ease', borderRadius: 2
                    }} />
                  </div>
                </div>
              )}
            </div>

            {/* Results */}
            {currentResult && (
              <div style={{ animation: 'fade-up 0.4s ease-out' }}>
                {/* Stats */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 15, marginBottom: 25 }}>
                  <div className="eclipse-card" style={{ padding: 20, textAlign: 'center' }}>
                    <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.5)', letterSpacing: 2, marginBottom: 8 }}>SUBDOMAINS FOUND</div>
                    <div style={{ fontSize: 32, fontWeight: 300, color: '#00f2fe', textShadow: '0 0 15px rgba(0,242,254,0.4)' }}>{currentResult.total_found}</div>
                  </div>
                  <div className="eclipse-card" style={{ padding: 20, textAlign: 'center' }}>
                    <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.5)', letterSpacing: 2, marginBottom: 8 }}>LIVE (HTTP OK)</div>
                    <div style={{ fontSize: 32, fontWeight: 300, color: '#00ff88' }}>
                      {currentResult.subdomains?.filter(s => s.status_code && s.status_code < 400).length || 0}
                    </div>
                  </div>
                  <div className="eclipse-card" style={{ padding: 20, textAlign: 'center' }}>
                    <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.5)', letterSpacing: 2, marginBottom: 8 }}>FROM OSINT</div>
                    <div style={{ fontSize: 32, fontWeight: 300, color: '#b983ff' }}>
                      {currentResult.subdomains?.filter(s => s.source === 'crtsh' || s.source === 'osint').length || 0}
                    </div>
                  </div>
                  {currentResult.scan_duration && (
                    <div className="eclipse-card" style={{ padding: 20, textAlign: 'center' }}>
                      <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.5)', letterSpacing: 2, marginBottom: 8 }}>DURATION</div>
                      <div style={{ fontSize: 24, fontWeight: 300, color: 'var(--accent-cyan)' }}>{currentResult.scan_duration}s</div>
                    </div>
                  )}
                </div>

                {/* Filter tabs */}
                <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
                  {[
                    { id: 'all', label: `ALL (${currentResult.subdomains?.length || 0})` },
                    { id: 'live', label: `LIVE (${currentResult.subdomains?.filter(s => s.status_code && s.status_code < 400).length || 0})` },
                    { id: 'osint', label: `OSINT (${currentResult.subdomains?.filter(s => s.source === 'crtsh' || s.source === 'osint').length || 0})` },
                  ].map(f => (
                    <button key={f.id} onClick={() => setFilter(f.id)} style={{
                      padding: '8px 16px', fontSize: 10, letterSpacing: 2, borderRadius: 20, cursor: 'pointer',
                      background: filter === f.id ? 'rgba(0,242,254,0.1)' : 'transparent',
                      border: `1px solid ${filter === f.id ? 'rgba(0,242,254,0.4)' : 'var(--glass-border)'}`,
                      color: filter === f.id ? '#00f2fe' : 'rgba(255,255,255,0.5)', transition: 'all 0.3s', outline: 'none'
                    }}>{f.label}</button>
                  ))}
                </div>

                {/* Table */}
                {filteredSubs.length > 0 ? (
                  <div className="eclipse-card" style={{ padding: 0, overflowX: 'auto' }}>
                    <div style={{ padding: '20px 25px', borderBottom: '1px solid var(--glass-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', minWidth: 'fit-content' }}>
                      <div style={{ fontSize: 11, letterSpacing: 3, color: '#00f2fe', textTransform: 'uppercase' }}>
                        DISCOVERED SUBDOMAINS — {currentResult.domain}
                      </div>
                    </div>

                    {/* Table Header */}
                    <div style={{
                      display: 'grid', gridTemplateColumns,
                      gap: 0, padding: '0', borderBottom: '1px solid var(--glass-border)', background: 'rgba(0,0,0,0.3)',
                      minWidth: 'fit-content'
                    }}>
                      {['SUBDOMAIN', 'IP ADDRESS', 'STATUS', 'SERVER', 'SOURCE'].map((h, i) => (
                        <div key={h} style={{ 
                          fontSize: 10, letterSpacing: 2, color: 'rgba(255,255,255,0.4)', 
                          padding: '15px 20px', position: 'relative', borderRight: '1px solid rgba(255,255,255,0.05)',
                          display: 'flex', alignItems: 'center'
                        }}>
                          {h}
                          {i < 4 && (
                            <div 
                              onMouseDown={(e) => handleMouseDown(i, e)}
                              style={{
                                position: 'absolute', right: -3, top: 0, bottom: 0, width: 6,
                                cursor: 'col-resize', zIndex: 10,
                                transition: '0.2s'
                              }}
                              onMouseEnter={e => e.target.style.background = 'rgba(0,242,254,0.3)'}
                              onMouseLeave={e => e.target.style.background = 'transparent'}
                            />
                          )}
                        </div>
                      ))}
                    </div>

                    {/* Table Rows */}
                    <div style={{ minWidth: 'fit-content' }}>
                      {filteredSubs.map((s, i) => (
                        <div key={s.subdomain} style={{
                          display: 'grid', gridTemplateColumns,
                          gap: 0, padding: '0', alignItems: 'center',
                          borderBottom: i < filteredSubs.length - 1 ? '1px solid rgba(255,255,255,0.03)' : 'none',
                          transition: 'background 0.2s'
                        }}
                          onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
                          onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                        >
                          <div style={{ fontSize: 13, color: '#fff', letterSpacing: 1, padding: '12px 20px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', borderRight: '1px solid rgba(255,255,255,0.03)' }}>
                            {s.subdomain}
                          </div>
                          <div style={{ fontSize: 12, color: s.ip ? 'rgba(255,255,255,0.7)' : 'rgba(255,255,255,0.2)', fontFamily: 'monospace', padding: '12px 20px', borderRight: '1px solid rgba(255,255,255,0.03)' }}>
                            {s.ip || '—'}
                          </div>
                          <div style={{ padding: '12px 20px', borderRight: '1px solid rgba(255,255,255,0.03)' }}>
                            {s.status_code ? (
                              <span style={{
                                fontSize: 10, padding: '3px 8px', borderRadius: 20, letterSpacing: 1,
                                background: `${getStatusColor(s.status_code)}15`,
                                border: `1px solid ${getStatusColor(s.status_code)}40`,
                                color: getStatusColor(s.status_code)
                              }}>{s.status_code}</span>
                            ) : <span style={{ color: 'rgba(255,255,255,0.2)', fontSize: 11 }}>—</span>}
                          </div>
                          <div style={{ fontSize: 12, color: s.server ? 'var(--accent-cyan)' : 'rgba(255,255,255,0.2)', padding: '12px 20px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', borderRight: '1px solid rgba(255,255,255,0.03)' }}>
                            {s.server || '—'}
                          </div>
                          <div style={{ padding: '12px 20px' }}>
                            <span style={{
                              fontSize: 9, padding: '2px 8px', borderRadius: 10, letterSpacing: 1,
                              background: s.source !== 'bruteforce' ? 'rgba(185,131,255,0.1)' : 'rgba(255,179,71,0.1)',
                              border: `1px solid ${s.source !== 'bruteforce' ? 'rgba(185,131,255,0.3)' : 'rgba(255,179,71,0.3)'}`,
                              color: s.source !== 'bruteforce' ? '#b983ff' : '#ffb347'
                            }}>{s.source === 'bruteforce' ? 'DNS' : 'OSINT'}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="eclipse-card" style={{ padding: 50, textAlign: 'center' }}>
                    <div style={{ fontSize: 14, color: 'rgba(255,255,255,0.4)', letterSpacing: 2 }}>
                      NO SUBDOMAINS MATCH CURRENT FILTER.
                    </div>
                  </div>
                )}
              </div>
            )}


            {!currentResult && !scanning && (
              <div className="eclipse-card" style={{ padding: 80, textAlign: 'center' }}>
                <div style={{ fontSize: 50, marginBottom: 20, opacity: 0.2 }}>🌐</div>
                <div style={{ fontSize: 16, color: 'rgba(255,255,255,0.4)', letterSpacing: 3, marginBottom: 10 }}>
                  AWAITING DOMAIN TARGET
                </div>
                <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.25)', letterSpacing: 1 }}>
                  Enter a domain above to discover its subdomains via DNS & certificate logs.
                </div>
              </div>
            )}
          </div>

          {/* History */}
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
                    <div key={h.id} className="eclipse-card" style={{ padding: 18, cursor: 'pointer', borderLeft: '3px solid #00f2fe' }} onClick={() => loadScan(h.id)}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                        <div style={{ fontSize: 13, color: '#fff', letterSpacing: 1 }}>{h.domain}</div>
                        <button onClick={(e) => { e.stopPropagation(); deleteScan(h.id) }} style={{
                          background: 'transparent', border: 'none', color: 'rgba(255,255,255,0.2)',
                          cursor: 'pointer', fontSize: 14, padding: '2px 5px', transition: '0.2s'
                        }}
                          onMouseEnter={e => e.target.style.color = '#ff3366'}
                          onMouseLeave={e => e.target.style.color = 'rgba(255,255,255,0.2)'}
                        >✕</button>
                      </div>
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                        <span style={{ fontSize: 9, padding: '2px 8px', borderRadius: 10, background: 'rgba(0,242,254,0.1)', border: '1px solid rgba(0,242,254,0.2)', color: '#00f2fe', letterSpacing: 1 }}>{h.scan_type}</span>
                        <span style={{ fontSize: 9, color: 'rgba(255,255,255,0.3)', letterSpacing: 1 }}>{h.total_found} found</span>
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
