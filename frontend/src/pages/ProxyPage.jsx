import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import api from '../utils/api'
import useAuthStore from '../store/authStore'
import { sanitizeMultiline } from '../utils/sanitize'
import { getWsUrl } from '../utils/api'

export default function ProxyPage() {
  const navigate = useNavigate()
  const { fetchMe } = useAuthStore()
  const [loading, setLoading] = useState(true)
  const [proxyRunning, setProxyRunning] = useState(false)
  const [traffic, setTraffic] = useState([])
  const [selectedReq, setSelectedReq] = useState(null)
  const [ws, setWs] = useState(null)
  const [interceptEnabled, setInterceptEnabled] = useState(false)
  const [interceptQueue, setInterceptQueue] = useState([]) // Array of intercepted requests
  const [selectedIntercept, setSelectedIntercept] = useState(null) // ID of current being edited
  const [modifiedData, setModifiedData] = useState("")
  const [sidebarWidth, setSidebarWidth] = useState(300)
  const isDragging = useRef(false)
  const trafficEndRef = useRef(null)

  useEffect(() => {
    const init = async () => {
      const u = await fetchMe()
      if (!u) { navigate('/login'); return }
      await checkStatus()
      await loadHistory()
      setLoading(false)
    }
    init()
    return () => {
      if (ws) ws.close()
    }
  }, [])

  // Drag-to-resize sidebar
  const startDrag = (e) => {
    e.preventDefault()
    isDragging.current = true
    const onMove = (e) => {
      if (!isDragging.current) return
      const newWidth = Math.min(500, Math.max(180, e.clientX))
      setSidebarWidth(newWidth)
    }
    const stopDrag = () => { isDragging.current = false }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', stopDrag, { once: true })
  }

  const checkStatus = async () => {
    try {
      const { data } = await api.get('/proxy/status')
      setProxyRunning(data.is_running)
      setInterceptEnabled(data.intercept_enabled)
      if (data.is_running) connectWs()
    } catch {}
  }

  const loadHistory = async () => {
    try {
      const { data } = await api.get('/proxy/history')
      setTraffic(data.history)
    } catch {}
  }

  const connectWs = () => {
    const token = localStorage.getItem('access_token')
    const socket = new WebSocket(getWsUrl('/api/v1/proxy/ws/traffic'))
    
    socket.onopen = () => {
      socket.send(JSON.stringify({ token }))
    }

    socket.onmessage = (event) => {
      const msg = JSON.parse(event.data)
      if (msg.type === 'capture') {
        setTraffic(prev => [msg.data, ...prev].slice(0, 200))
      } else if (msg.type === 'intercept') {
        const newIntercept = msg.data
        setInterceptQueue(prev => [...prev, newIntercept])
        
        // If nothing selected, select this one automatically if it's the first
        setSelectedIntercept(prev => prev || newIntercept.id)
        
        // Auto-fill editor if this is the first one or we just selected it
        const originalReq = `${newIntercept.method} ${newIntercept.url} HTTP/1.1\r\n${Object.entries(newIntercept.headers).map(([k,v]) => `${k}: ${v}`).join('\r\n')}\r\n\r\n${newIntercept.body}`
        
        // Only update editor if we don't have something active
        setModifiedData(prev => prev || originalReq)
        
        toast('New Intercept Queued', { icon: '🛡️', style: { background: 'rgba(0,183,255,0.1)', color: '#00f2fe', border: '1px solid #00f2fe', fontSize: '10px' } })
      }
    }

    socket.onclose = () => {
      // Reconnect if proxy still running? 
    }

    setWs(socket)
  }

  const handleToggleProxy = async () => {
    try {
      if (proxyRunning) {
        await api.post('/proxy/stop')
        setProxyRunning(false)
        if (ws) ws.close()
        toast.success('Proxy listener stopped', { style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } })
      } else {
        await api.post('/proxy/start')
        setProxyRunning(true)
        connectWs()
        toast.success('Proxy listener active on port 8080', { style: { background: '#010204', color: '#00ff88', border: '1px solid #00ff88' } })
      }
    } catch (err) {
      toast.error('Failed to command proxy listener')
    }
  }

  const clearAll = async () => {
    if (!window.confirm('Clear ALL traffic history and drop ALL pending intercepts?')) return
    try {
      await api.delete('/proxy/clear-all')
      setTraffic([])
      setSelectedReq(null)
      setInterceptQueue([])
      setSelectedIntercept(null)
      setModifiedData('')
      toast.success('All cleared — history and intercepts dropped.', {
        icon: '🗑️',
        style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' }
      })
    } catch {
      toast.error('Failed to clear')
    }
  }

  const dropAllIntercepts = async () => {
    try {
      await proxy_manager_clear() // drop via backend
    } catch {}
    setInterceptQueue([])
    setSelectedIntercept(null)
    setModifiedData('')
    toast('All pending intercepts dropped.', { icon: '🚫', style: { background: '#010204', color: '#ffb347', border: '1px solid #ffb347' } })
  }

  const handleToggleIntercept = async () => {
    try {
      const { data } = await api.post('/proxy/intercept/toggle')
      setInterceptEnabled(data.intercept_enabled)
      toast.success(`Interception ${data.intercept_enabled ? 'ENABLED' : 'DISABLED'}`)
    } catch {}
  }

  const handleInterceptAction = async (action, id) => {
    try {
      // Send raw modified HTTP request as plain text body
      await api.post(
        `/proxy/intercept/action?action=${action}&request_id=${id}`,
        action === 'forward' ? modifiedData : '',
        { headers: { 'Content-Type': 'text/plain' } }
      )
      
      const newQueue = interceptQueue.filter(r => r.id !== id)
      setInterceptQueue(newQueue)
      
      if (newQueue.length > 0) {
        const next = newQueue[0]
        setSelectedIntercept(next.id)
        const nextReq = `${next.method} ${next.url} HTTP/1.1\r\n${Object.entries(next.headers).map(([k,v]) => `${k}: ${v}`).join('\r\n')}\r\n\r\n${next.body}`
        setModifiedData(nextReq)
      } else {
        setSelectedIntercept(null)
        setModifiedData("")
      }
      
      toast.success(`Request ${action === 'forward' ? 'forwarded ✓' : 'dropped ✗'}`, {
        style: { background: '#010204', color: action === 'forward' ? '#00ff88' : '#ff3366', border: `1px solid ${action === 'forward' ? '#00ff88' : '#ff3366'}` }
      })
    } catch {}
  }

  const handleForwardAll = async () => {
    try {
      const { data } = await api.post('/proxy/intercept/forward-all')
      setInterceptQueue([])
      setSelectedIntercept(null)
      setModifiedData('')
      toast.success(`Forwarded ${data.forwarded} request(s)`, {
        icon: '⚡',
        style: { background: '#010204', color: '#00ff88', border: '1px solid #00ff88' }
      })
    } catch {}
  }

  const selectPendingIntercept = (req) => {
    setSelectedIntercept(req.id)
    const raw = `${req.method} ${req.url} HTTP/1.1\r\n${Object.entries(req.headers).map(([k,v]) => `${k}: ${v}`).join('\r\n')}\r\n\r\n${req.body}`
    setModifiedData(raw)
  }

  const sendToRepeater = (req) => {
    const repeaterReq = {
      method: req.method,
      url: req.url,
      headers: typeof req.request_headers === 'string' ? JSON.parse(req.request_headers) : req.headers || {},
      body: req.request_body || req.body || ""
    }
    localStorage.setItem('repeater_req', JSON.stringify(repeaterReq))
    navigate('/tools/repeater')
    toast.success('Sent to Repeater')
  }

  const handleDownloadCA = async () => {
    try {
      const response = await api.get('/proxy/ca/download', { responseType: 'blob' })
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', 'ShadowSpike_CA.crt')
      document.body.appendChild(link)
      link.click()
      toast.success('CA Certificate Downloaded. Please install and trust it in your browser settings.')
    } catch {
      toast.error('Failed to download CA. Make sure the proxy has been started at least once.')
    }
  }

  if (loading) return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-cyan)', fontSize: 13, letterSpacing: 4 }}>
      INITIALIZING PROXY...
    </div>
  )

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: '#010204' }}>
      
      {/* Topbar */}
      <div style={{
        height: 60, background: 'rgba(1,2,4,0.9)', borderBottom: '1px solid var(--glass-border)',
        display: 'flex', alignItems: 'center', padding: '0 25px', gap: 15, zIndex: 100
      }}>
        <div onClick={() => navigate('/dashboard')} style={{ fontSize: 16, fontWeight: 300, color: '#fff', letterSpacing: 4, cursor: 'pointer' }}>
          SHADOW SPIKE
        </div>
        <span style={{ color: 'rgba(255,255,255,0.2)' }}>/</span>
        <span style={{ color: 'var(--accent-cyan)', fontSize: 10, letterSpacing: 2 }}>HTTP PROXY</span>

        <div style={{ marginLeft: 'auto', display: 'flex', gap: 12 }}>
          <button 
            onClick={handleDownloadCA}
            className="btn-eclipse btn-secondary"
            style={{ padding: '6px 15px', fontSize: 10, color: 'var(--accent-cyan)', borderColor: 'var(--accent-cyan)' }}
          >
            📥 DOWNLOAD CA
          </button>
          <button 
            onClick={handleToggleIntercept}
            className="btn-eclipse"
            style={{
              padding: '6px 15px', fontSize: 10,
              background: interceptEnabled ? 'rgba(0,242,254,0.1)' : 'transparent',
              borderColor: interceptEnabled ? 'var(--accent-cyan)' : 'rgba(255,255,255,0.2)',
              color: interceptEnabled ? 'var(--accent-cyan)' : 'rgba(255,255,255,0.5)'
            }}
          >
            🛡️ INTERCEPT IS {interceptEnabled ? 'ON' : 'OFF'}
          </button>
          <button onClick={clearAll} className="btn-eclipse" style={{ padding: '6px 15px', fontSize: 10, color: '#ff3366', borderColor: 'rgba(255,51,102,0.6)', background: 'rgba(255,51,102,0.08)' }}>🗑 CLEAR ALL</button>
          <button 
            onClick={handleToggleProxy} 
            className="btn-eclipse" 
            style={{ 
              padding: '6px 20px', fontSize: 10, 
              background: proxyRunning ? 'rgba(255,51,102,0.1)' : 'rgba(0,255,136,0.1)',
              borderColor: proxyRunning ? '#ff3366' : '#00ff88',
              color: proxyRunning ? '#ff3366' : '#00ff88'
            }}
          >
            {proxyRunning ? '🛑 STOP LISTENER' : '▶ START LISTENER (8888)'}
          </button>
        </div>
      </div>

      {/* CA Warning Banner - shows when proxy is running */}
      {proxyRunning && (
        <div style={{
          background: 'rgba(255,179,71,0.07)', borderBottom: '1px solid rgba(255,179,71,0.25)',
          padding: '8px 25px', display: 'flex', alignItems: 'center', gap: 12, fontSize: 11
        }}>
          <span style={{ color: '#ffb347', fontSize: 13 }}>⚠️</span>
          <span style={{ color: '#ffb347', letterSpacing: 1 }}>HTTPS INTERCEPT REQUIRES CA TRUST:</span>
          <span style={{ color: 'rgba(255,255,255,0.5)' }}>Download the CA cert → install it in your browser → set proxy to <b style={{ color: '#fff' }}>127.0.0.1:8888</b></span>
          <button onClick={handleDownloadCA} style={{ marginLeft: 'auto', background: 'rgba(255,179,71,0.1)', border: '1px solid rgba(255,179,71,0.4)', color: '#ffb347', padding: '4px 14px', borderRadius: 20, fontSize: 10, cursor: 'pointer', letterSpacing: 1 }}>📥 GET CA CERT</button>
        </div>
      )}

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        
        {/* Intercept Sidebar (Left) */}
        {interceptEnabled && (
          <div style={{ width: sidebarWidth, minWidth: 180, maxWidth: 500, borderRight: '1px solid var(--glass-border)', display: 'flex', flexDirection: 'column', background: 'rgba(0,183,255,0.02)', position: 'relative', flexShrink: 0 }}>
            {/* Drag Handle */}
            <div
              onMouseDown={startDrag}
              style={{
                position: 'absolute', right: 0, top: 0, bottom: 0, width: 4,
                cursor: 'col-resize', background: 'transparent', zIndex: 10,
                transition: 'background 0.2s'
              }}
              onMouseEnter={e => e.currentTarget.style.background = 'rgba(0,242,254,0.4)'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
            />
            <div style={{ padding: '12px 15px', fontSize: 10, color: 'var(--accent-cyan)', letterSpacing: 2, borderBottom: '1px solid var(--glass-border)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: interceptQueue.length > 0 ? 8 : 0 }}>
                <span>PENDING <span style={{ color: '#fff' }}>{interceptQueue.length}</span></span>
                {interceptQueue.length > 0 && (
                  <button
                    onClick={async () => {
                      await api.delete('/proxy/clear-all')
                      setInterceptQueue([])
                      setSelectedIntercept(null)
                      setModifiedData('')
                      toast('All intercepts dropped.', { icon: '🚫', style: { background: '#010204', color: '#ffb347', border: '1px solid #ffb347' } })
                    }}
                    style={{
                      background: 'rgba(255,51,102,0.1)', border: '1px solid rgba(255,51,102,0.4)',
                      color: '#ff3366', fontSize: 9, padding: '3px 10px', borderRadius: 20,
                      cursor: 'pointer', letterSpacing: 1
                    }}
                  >
                    DROP ALL
                  </button>
                )}
              </div>
              {interceptQueue.length > 0 && (
                <button
                  onClick={handleForwardAll}
                  style={{
                    width: '100%', background: 'rgba(0,255,136,0.08)', border: '1px solid rgba(0,255,136,0.35)',
                    color: '#00ff88', fontSize: 9, padding: '5px 0', borderRadius: 20,
                    cursor: 'pointer', letterSpacing: 2, textTransform: 'uppercase'
                  }}
                >
                  ⚡ FORWARD ALL ({interceptQueue.length})
                </button>
              )}
            </div>
            <div style={{ flex: 1, overflowY: 'auto' }}>
              {interceptQueue.map(req => (
                <div 
                  key={req.id}
                  onClick={() => selectPendingIntercept(req)}
                  style={{
                    padding: '10px 15px', borderBottom: '1px solid rgba(0,242,254,0.08)', cursor: 'pointer',
                    background: selectedIntercept === req.id ? 'rgba(0,242,254,0.08)' : 'transparent',
                    transition: 'background 0.2s'
                  }}
                >
                  <div style={{ fontSize: 9, color: req.method === 'POST' ? '#ff3366' : '#00ff88', marginBottom: 4, fontWeight: 'bold', letterSpacing: 1 }}>{req.method}</div>
                  <div style={{ fontSize: 10, color: selectedIntercept === req.id ? '#00f2fe' : 'rgba(255,255,255,0.7)', wordBreak: 'break-all', lineHeight: 1.5 }}>{req.url}</div>
                </div>
              ))}

              {interceptQueue.length === 0 && (
                <div style={{ padding: 40, textAlign: 'center', color: 'rgba(255,255,255,0.1)', fontSize: 10, letterSpacing: 1 }}>
                  NO PENDING REQUESTS
                </div>
              )}
            </div>
          </div>
        )}

        {/* Main Area: Editor or Traffic List */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          
          {selectedIntercept ? (
            /* Intercept Editor Mode */
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', background: '#05070a' }}>
              <div style={{ padding: '15px 25px', borderBottom: '1px solid var(--glass-border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ fontSize: 11, color: 'var(--accent-cyan)', letterSpacing: 2 }}>EDITING INTERCEPTED REQUEST</div>
                <div style={{ display: 'flex', gap: 10 }}>
                  <button 
                    onClick={() => {
                       const current = interceptQueue.find(r => r.id === selectedIntercept);
                       if(current) sendToRepeater(current);
                    }} 
                    className="btn-eclipse btn-secondary" 
                    style={{ padding: '5px 15px', fontSize: 10, color: '#ffb347', borderColor: '#ffb347' }}
                  >
                    🚀 REPEATER
                  </button>
                  <button onClick={() => handleInterceptAction('forward', selectedIntercept)} className="btn-eclipse" style={{ padding: '5px 15px', fontSize: 10, background: 'rgba(0,255,136,0.1)', color: '#00ff88', borderColor: '#00ff88' }}>FORWARD</button>
                  <button onClick={() => handleInterceptAction('drop', selectedIntercept)} className="btn-eclipse" style={{ padding: '5px 15px', fontSize: 10, background: 'rgba(255,51,102,0.1)', color: '#ff3366', borderColor: '#ff3366' }}>DROP</button>
                </div>
              </div>
              <textarea 
                value={modifiedData}
                onChange={(e) => setModifiedData(sanitizeMultiline(e.target.value))}
                style={{
                  flex: 1, background: '#05070a', border: 'none', color: '#00f2fe',
                  padding: 25, fontSize: 13, fontFamily: 'monospace', outline: 'none',
                  resize: 'none', lineHeight: 1.6
                }}
              />
            </div>
          ) : (
            /* Standard Traffic List Mode */
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
              <div style={{ padding: '10px 20px', background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid var(--glass-border)', display: 'flex', fontSize: 10, color: 'rgba(255,255,255,0.4)', letterSpacing: 1 }}>
                <div style={{ width: '80px' }}>METHOD</div>
                <div style={{ width: '400px' }}>URL</div>
                <div style={{ width: '80px' }}>STATUS</div>
                <div style={{ flex: 1 }}>TIME</div>
              </div>
              
              <div style={{ flex: 1, overflowY: 'auto' }}>
                {traffic.length === 0 ? (
                  <div style={{ padding: 100, textAlign: 'center', color: 'rgba(255,255,255,0.2)', fontSize: 12, letterSpacing: 2 }}>
                    AWAITING TRAFFIC...
                  </div>
                ) : (
                  traffic.map((req, idx) => (
                    <div 
                      key={req.id || idx}
                      onClick={() => setSelectedReq(req)}
                      style={{
                        display: 'flex', padding: '12px 20px', borderBottom: '1px solid rgba(255,255,255,0.05)',
                        cursor: 'pointer', transition: '0.2s', fontSize: 12,
                        background: selectedReq?.id === req.id ? 'rgba(0,242,254,0.05)' : 'transparent'
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
                      onMouseLeave={e => e.currentTarget.style.background = selectedReq?.id === req.id ? 'rgba(0,242,254,0.05)' : 'transparent'}
                    >
                      <div style={{ width: '80px', color: req.method === 'POST' ? '#ff3366' : '#00ff88', fontWeight: 'bold' }}>{req.method}</div>
                      <div style={{ width: '400px', color: '#fff', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', paddingRight: 20 }}>{req.url}</div>
                      <div style={{ width: '80px', color: req.status_code < 400 ? '#00ff88' : '#ff3366' }}>{req.status_code || '—'}</div>
                      <div style={{ flex: 1, color: 'rgba(255,255,255,0.3)', fontSize: 10 }}>{new Date(req.created_at).toLocaleTimeString()}</div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* Inspector Pane (Right) - Only show when NOT editing an intercept */}
        {!selectedIntercept && (
          <div style={{ width: '500px', display: 'flex', flexDirection: 'column', background: '#020408', borderLeft: '1px solid var(--glass-border)' }}>
            {selectedReq ? (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                <div style={{ padding: 20, borderBottom: '1px solid var(--glass-border)' }}>
                  <div style={{ fontSize: 10, color: 'var(--accent-cyan)', letterSpacing: 2, marginBottom: 10 }}>REQUEST DETAILS</div>
                  <div style={{ fontSize: 14, color: '#fff', fontFamily: 'monospace', wordBreak: 'break-all' }}>{selectedReq.url}</div>
                </div>
                
                <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
                  {/* Headers */}
                  <div style={{ color: 'rgba(255,255,255,0.5)', fontSize: 11, marginBottom: 10, letterSpacing: 1 }}>HEADERS</div>
                  <div style={{ background: '#080c14', padding: 15, borderRadius: 8, border: '1px solid var(--glass-border)', marginBottom: 20 }}>
                    <pre style={{ margin: 0, fontSize: 11, color: '#a1c4fd', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                      {selectedReq.request_headers ? JSON.stringify(JSON.parse(selectedReq.request_headers), null, 2) : 'No headers captured'}
                    </pre>
                  </div>

                  {/* Body */}
                  <div style={{ color: 'rgba(255,255,255,0.5)', fontSize: 11, marginBottom: 10, letterSpacing: 1 }}>BODY</div>
                  <div style={{ background: '#080c14', padding: 15, borderRadius: 8, border: '1px solid var(--glass-border)', marginBottom: 20 }}>
                    <pre style={{ margin: 0, fontSize: 11, color: '#e2e8f0', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                      {selectedReq.request_body || 'Empty Body'}
                    </pre>
                  </div>

                  <button 
                    onClick={() => sendToRepeater(selectedReq)}
                    className="btn-eclipse" 
                    style={{ width: '100%', padding: '12px', fontSize: 11, background: 'rgba(255,179,71,0.1)', borderColor: '#ffb347', color: '#ffb347' }}
                  >
                    🚀 SEND TO REPEATER
                  </button>
                </div>
              </div>
            ) : (
              <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'rgba(255,255,255,0.1)', fontSize: 12, letterSpacing: 2 }}>
                SELECT A REQUEST TO INSPECT
              </div>
            )}
          </div>
        )}

      </div>



    </div>
  )
}
