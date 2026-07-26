import React, { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../utils/api'
import toast from 'react-hot-toast'
import useAuthStore from '../store/authStore'
import { sanitizeUrl } from '../utils/sanitize'

const SEVERITY_COLORS = { CRITICAL: '#ff0040', HIGH: '#ff3366', MEDIUM: '#ffb347', LOW: '#00ff88' }

const SCAN_MODES = [
  { id: 'quick', label: 'QUICK SCAN', desc: 'Core SQLi patterns & error detection', time: '~2min' },
  { id: 'deep', label: 'DEEP SCAN', desc: 'Full time-based & WAF bypass suite', time: '~15min' },
]

export default function SQLiPage() {
  const navigate = useNavigate()
  const { user, fetchMe } = useAuthStore()
  const [loading, setLoading] = useState(true)

  const [target, setTarget] = useState('')
  const [scanMode, setScanMode] = useState('quick')
  const [scanning, setScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [statusMsg, setStatusMsg] = useState('')
  const [activeWs, setActiveWs] = useState(null)

  const [currentResult, setCurrentResult] = useState(null)
  const [liveVulns, setLiveVulns] = useState([])

  const [history, setHistory] = useState([])
  const [showHistory, setShowHistory] = useState(false)

  const resultsRef = useRef(null)

  useEffect(() => {
    const init = async () => {
      const u = await fetchMe()
      if (!u) { navigate('/login'); return }
      setLoading(false)
      loadHistory()
    }
    init()
  }, [])

  const loadHistory = async () => {
    try {
      const { data } = await api.get('/sqli/scans')
      setHistory(data.scans)
    } catch {}
  }

  const handleScan = async () => {
    if (!target.trim()) {
      toast.error('Please enter a target URL', { style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } })
      return
    }
    setScanning(true)
    setScanProgress(0)
    setStatusMsg('Connecting...')
    setCurrentResult(null)
    setLiveVulns([])

    const token = localStorage.getItem('access_token')
    if (!token) { toast.error('Unauthorized'); setScanning(false); return }

    const wsUrl = 'ws://127.0.0.1:8000/api/v1/sqli/ws/scan'
    const ws = new WebSocket(wsUrl)
    setActiveWs(ws)

    ws.onopen = () => {
      ws.send(JSON.stringify({ token, target: target.trim(), scan_mode: scanMode }))
      setStatusMsg('Identifying SQL injection points...')
    }

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        if (msg.error) {
          toast.error(msg.error, { style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } })
          ws.close()
          setScanning(false)
          return
        }

        if (msg.type === 'status') {
          setStatusMsg(msg.message)
        } else if (msg.type === 'progress') {
          setScanProgress(msg.progress)
        } else if (msg.type === 'vuln_found') {
          setLiveVulns(prev => [...prev, msg.data])
          toast.success('SQLi vulnerability found!', { icon: '🔥', style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } })
        } else if (msg.type === 'complete') {
          setScanning(false)
          setCurrentResult(msg.data)
          loadHistory()
          toast.success('SQLi Scan Finished')
          ws.close()
        }
      } catch (err) { console.error(err) }
    }

    ws.onclose = () => {
      setScanning(false)
      setActiveWs(null)
    }
    ws.onerror = () => {
        toast.error('Connection failed! Target might be down or blocking scan.')
        setScanning(false)
    }
  }

  const handleCancel = () => {
    if (activeWs && activeWs.readyState === WebSocket.OPEN) {
      activeWs.send(JSON.stringify({ action: 'stop' }))
      toast('Cancelling SQLi scan...', { icon: '🛑', style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } })
    }
  }

  const exportResults = () => {
    const vulns = scanning ? liveVulns : (currentResult?.vulnerabilities || liveVulns)
    if (!vulns.length) return
    const lines = [
      'SQL INJECTION SCAN REPORT — Shadow Spike',
      `Target: ${currentResult?.target || target}`,
      `Scan Mode: ${currentResult?.scan_mode || scanMode}`,
      `Total Vulnerabilities: ${vulns.length}`,
      '─'.repeat(60),
      ...vulns.map((v, i) => {
        let reproduce = ""
        if (v.type.includes("Error")) {
          reproduce = `\n    How to Execute: This is an Error-based injection. Access the endpoint with the payload. The database will leak structure in the response.`
        } else if (v.type.includes("Time")) {
          reproduce = `\n    How to Execute: This is a Time-based injection. The server will take a significant amount of time (8s+) to respond due to the SLEEP command.`
        }
        return `[${i + 1}] ${v.severity} | ${v.type}\n    Vulnerable Location: ${v.endpoint} [${v.method}]\n    Vulnerable Parameter: ${v.parameter}${reproduce}\n    Payload: ${v.payload}\n    Evidence: ${v.evidence || 'N/A'}\n`
      })
    ]
    const blob = new Blob([lines.join('\n')], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'sqli_report.txt'
    a.click()
  }

  const copyPayload = (payload) => {
    navigator.clipboard.writeText(payload)
    toast.success('Payload copied!', { style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } })
  }

  const executeLaunch = (v) => {
    // 1. URL Parameter
    if (v.point_type === "url_param" || v.vulnerable_url) {
      window.open(v.vulnerable_url || v.endpoint, '_blank')
      return
    }

    // 2. Form Field injection
    if (v.point_type === "form_field") {
      // Build a dynamic HTML document in a new tab that automatically submits the form
      const newTab = window.open("", "_blank")
      if (!newTab) {
        toast.error("Popup blocked! Allow popups to execute launching.")
        return
      }

      const fields = v.form_fields || {}
      fields[v.parameter] = v.payload

      let inputsHtml = ""
      for (const [name, val] of Object.entries(fields)) {
        inputsHtml += `<input type="hidden" name="${name}" value="${val.toString().replace(/"/g, '&quot;')}" />`
      }

      const htmlContent = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>Shadow Spike - SQLi Form Exploit</title>
          <style>
            body { background: #010204; color: #fff; font-family: monospace; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
            .container { border: 1px dashed #ff3366; padding: 30px; border-radius: 8px; text-align: center; }
            h2 { color: #ff3366; letter-spacing: 2px; }
          </style>
        </head>
        <body>
          <div class="container">
            <h2>Executing SQLi POST Payload...</h2>
            <p>Target: ${v.endpoint}</p>
            <p>Parameter: ${v.parameter}</p>
            <p>Please wait while Shadow Spike automatically submits the form...</p>
            <form id="exploitForm" action="${v.endpoint}" method="${v.method || 'POST'}">
              ${inputsHtml}
            </form>
          </div>
          <script>
            document.getElementById('exploitForm').submit();
          </script>
        </body>
        </html>
      `
      newTab.document.open()
      newTab.document.write(htmlContent)
      newTab.document.close()
      return
    }

    // 3. Header or Cookie (Informative notification on execution details)
    toast.error(`For ${v.point_type.replace('_', ' ').toUpperCase()} injections, use an interception tool or extension to inject the payload.`, {
      style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366', maxWidth: 450 }
    })
  }

  if (loading) return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#ff3366', fontSize: 13, letterSpacing: 4 }}>
      INITIALIZING SQLI SCANNER...
    </div>
  )

  const displayVulns = scanning ? liveVulns : (currentResult?.vulnerabilities || liveVulns)

  return (
    <div style={{ minHeight: '100vh', paddingTop: 60, paddingBottom: 60 }}>

      {/* Topbar */}
      <div style={{
        position: 'fixed', top: 0, left: 0, right: 0,
        display: 'flex', alignItems: 'center', padding: '0 30px',
        height: 60, background: 'rgba(1,2,4,0.92)', borderBottom: '1px solid rgba(255,51,102,0.2)', gap: 15, zIndex: 100, backdropFilter: 'blur(10px)'
      }}>
        <div onClick={() => navigate('/dashboard')} style={{ fontSize: 18, fontWeight: 300, color: '#fff', letterSpacing: 5, cursor: 'pointer' }}>
          SHADOW SPIKE
        </div>
        <span style={{ color: 'rgba(255,255,255,0.3)' }}>›</span>
        <span style={{
          background: 'rgba(255,51,102,0.1)', border: '1px solid rgba(255,51,102,0.4)',
          color: '#ff3366', fontSize: 10, padding: '3px 10px', borderRadius: 20, letterSpacing: 2
        }}>SQLI SCANNER</span>

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 12 }}>
          {displayVulns.length > 0 && !scanning && (
            <button onClick={exportResults} className="btn-eclipse" style={{ padding: '6px 15px', fontSize: 10, width: 'auto', background: 'rgba(255,51,102,0.1)', borderColor: '#ff3366', color: '#ff3366' }}>
              ⬇ EXPORT REPORT
            </button>
          )}
          <button onClick={() => setShowHistory(!showHistory)} className="btn-eclipse" style={{ padding: '6px 15px', fontSize: 10, width: 'auto', background: showHistory ? 'rgba(255,51,102,0.1)' : 'transparent', borderColor: showHistory ? '#ff3366' : 'var(--glass-border)', color: showHistory ? '#ff3366' : '#fff' }}>
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
            SQL <span style={{ color: '#ff3366' }}>INJECTION</span>
          </h1>
          <p style={{ color: 'rgba(255,255,255,0.5)', fontSize: 13, marginTop: 10, letterSpacing: 1 }}>
            Advanced detection of Error-based, Time-based, and Boolean-based SQL vulnerabilities.
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: showHistory ? '1fr 350px' : '1fr', gap: 25 }}>
          <div>

            {/* Config Card */}
            <div className="eclipse-card" style={{ marginBottom: 25, padding: 30, borderColor: 'rgba(255,51,102,0.15)' }}>
              <div style={{ fontSize: 11, letterSpacing: 3, color: '#ff3366', textTransform: 'uppercase', marginBottom: 20 }}>
                SCAN CONFIGURATION
              </div>

              {/* Target */}
              <div style={{ marginBottom: 20 }}>
                <label style={{ display: 'block', color: '#ffc1d1', fontSize: 11, letterSpacing: 2, marginBottom: 8 }}>
                  TARGET URL / DOMAIN
                </label>
                <input
                  type="text"
                  className="eclipse-input"
                  value={target}
                  onChange={e => setTarget(sanitizeUrl(e.target.value))}
                  placeholder="https://example.com/products.php?id=10"
                  disabled={scanning}
                  style={{ marginBottom: 0, fontSize: 15, letterSpacing: 1, borderColor: 'rgba(255,51,102,0.3)' }}
                  onKeyDown={e => e.key === 'Enter' && !scanning && handleScan()}
                />
              </div>

              {/* Scan Mode */}
              <div style={{ marginBottom: 22 }}>
                <label style={{ display: 'block', color: '#ffc1d1', fontSize: 11, letterSpacing: 2, marginBottom: 12 }}>
                  SCAN MODE
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  {SCAN_MODES.map(m => (
                    <div
                      key={m.id}
                      onClick={() => !scanning && setScanMode(m.id)}
                      style={{
                        padding: '18px', borderRadius: 10, cursor: scanning ? 'not-allowed' : 'pointer',
                        background: scanMode === m.id ? 'rgba(255,51,102,0.1)' : 'var(--glass-bg)',
                        border: `1px solid ${scanMode === m.id ? 'rgba(255,51,102,0.5)' : 'var(--glass-border)'}`,
                        transition: 'all 0.3s', textAlign: 'center',
                        boxShadow: scanMode === m.id ? '0 0 20px rgba(255,51,102,0.1)' : 'none',
                      }}
                    >
                      <div style={{ fontSize: 12, color: scanMode === m.id ? '#ff3366' : '#fff', letterSpacing: 2, marginBottom: 6 }}>{m.label}</div>
                      <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.45)' }}>{m.desc}</div>
                    </div>
                  ))}
                </div>
              </div>

              {scanning ? (
                <button
                  className="btn-eclipse"
                  onClick={handleCancel}
                  style={{
                    width: '100%', height: 50, fontSize: 11, letterSpacing: 4,
                    background: 'rgba(255,51,102,0.15)',
                    borderColor: '#ff3366',
                    color: '#ff3366',
                  }}
                >
                  🛑 CANCEL SCAN
                </button>
              ) : (
                <button
                  className="btn-eclipse"
                  onClick={handleScan}
                  style={{
                    width: '100%', height: 50, fontSize: 11, letterSpacing: 4,
                    background: 'rgba(255,51,102,0.1)',
                    borderColor: '#ff3366',
                    color: '#ff3366',
                  }}
                >
                  ⚡ INITIALIZE SQLI SCAN
                </button>
              )}
            </div>

            {/* Live Progress */}
            {scanning && (
              <div className="eclipse-card" style={{ marginBottom: 25, padding: '20px 30px', borderColor: 'rgba(255,51,102,0.2)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12, alignItems: 'center' }}>
                  <div style={{ fontSize: 10, letterSpacing: 2, color: '#ff3366', display: 'flex', alignItems: 'center', gap: 10 }}>
                    <div className="scanner-dot" style={{ width: 6, height: 6, borderRadius: '50%', background: '#ff3366', boxShadow: '0 0 10px #ff3366' }}></div>
                    {statusMsg.toUpperCase()}
                  </div>
                  <div style={{ fontSize: 12, color: '#fff', fontWeight: 300, letterSpacing: 1 }}>{scanProgress}%</div>
                </div>
                <div style={{ height: 2, background: 'rgba(255,255,255,0.05)', borderRadius: 4, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${scanProgress}%`, background: '#ff3366', boxShadow: '0 0 15px #ff3366', transition: 'width 0.4s' }}></div>
                </div>
              </div>
            )}

            {/* Vulnerability Table */}
            {displayVulns.length > 0 && (
              <div className="eclipse-card" style={{ padding: 0, borderColor: 'rgba(255,51,102,0.15)', animation: 'fade-up 0.4s ease-out' }}>
                <div style={{ padding: '18px 25px', borderBottom: '1px solid rgba(255,51,102,0.15)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ fontSize: 11, letterSpacing: 3, color: '#ff3366' }}>
                    SQL INJECTION VULNERABILITIES
                  </div>
                  <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.4)', letterSpacing: 1 }}>
                    {displayVulns.length} VULNERABILITIES DETECTED
                  </div>
                </div>

                <div style={{
                  display: 'grid', gridTemplateColumns: '100px 140px 1fr 100px',
                  gap: 12, padding: '12px 25px', borderBottom: '1px solid var(--glass-border)',
                  background: 'rgba(0,0,0,0.3)'
                }}>
                  {['SEVERITY', 'TYPE', 'VULNERABLE POINT / PAYLOAD', 'ACTION'].map(h => (
                    <div key={h} style={{ fontSize: 9, letterSpacing: 2, color: 'rgba(255,255,255,0.35)' }}>{h}</div>
                  ))}
                </div>

                {displayVulns.map((v, i) => (
                  <div key={i} ref={i === displayVulns.length - 1 ? resultsRef : null}>
                    <div style={{
                      display: 'grid', gridTemplateColumns: '100px 140px 1fr 100px',
                      gap: 12, padding: '20px 25px', alignItems: 'center',
                      borderBottom: i < displayVulns.length - 1 ? '1px solid rgba(255,255,255,0.03)' : 'none',
                      transition: 'background 0.2s',
                      animation: 'fade-up 0.3s ease-out',
                    }}
                      onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,51,102,0.04)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                      <div>
                        <span style={{
                          fontSize: 9, padding: '3px 9px', borderRadius: 20, letterSpacing: 1,
                          background: `${SEVERITY_COLORS[v.severity] || '#aaa'}15`,
                          border: `1px solid ${SEVERITY_COLORS[v.severity] || '#aaa'}40`,
                          color: SEVERITY_COLORS[v.severity] || '#aaa',
                        }}>{v.severity}</span>
                      </div>
                      <div style={{ fontSize: 10, color: '#ffc1d1', letterSpacing: 1 }}>{v.type.toUpperCase()}</div>
                      <div style={{ fontSize: 11, color: '#fff', letterSpacing: 1 }}>
                        <div style={{ color: 'rgba(255,255,255,0.4)', fontSize: 9, marginBottom: 4, letterSpacing: 2 }}>ENDPOINT / PARAMETER: {v.parameter}</div>
                        <div style={{ fontSize: 13, color: '#ffc1d1', fontFamily: 'monospace', marginBottom: 8, wordBreak: 'break-all' }}>{v.endpoint}</div>
                        <div style={{ fontSize: 10, padding: '8px', background: 'rgba(0,0,0,0.3)', borderRadius: 4, color: 'rgba(255,255,255,0.5)', border: '1px solid rgba(255,51,102,0.1)', fontFamily: 'monospace' }}>
                          PAYLOAD: {v.payload}
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button onClick={() => copyPayload(v.payload)} style={{
                          background: 'rgba(255,51,102,0.08)', border: '1px solid rgba(255,51,102,0.2)',
                          color: '#ff3366', fontSize: 9, cursor: 'pointer', padding: '6px 10px',
                          borderRadius: 4, letterSpacing: 1, transition: '0.2s'
                        }}>COPY</button>
                        <button onClick={() => executeLaunch(v)} style={{
                          background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.2)',
                          color: '#fff', fontSize: 9, cursor: 'pointer', padding: '6px 10px',
                          borderRadius: 4, letterSpacing: 1, transition: '0.2s'
                        }}>LAUNCH</button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* History Sidebar */}
          {showHistory && (
            <div className="eclipse-card" style={{ padding: '25px', borderColor: 'rgba(255,51,102,0.15)' }}>
              <div style={{ fontSize: 10, letterSpacing: 2, color: 'rgba(255,255,255,0.3)', marginBottom: 20 }}>SCAN HISTORY</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {history.length === 0 ? (
                  <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.2)', textAlign: 'center', padding: '20px 0' }}>NO PREVIOUS SCANS</div>
                ) : (
                  history.map((s, idx) => (
                    <div key={idx} className="history-item" style={{
                      padding: '15px', borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)', cursor: 'pointer'
                    }}>
                      <div style={{ fontSize: 12, color: '#fff', marginBottom: 4, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{s.target}</div>
                      <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.3)' }}>{new Date(s.created_at).toLocaleString()}</div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
