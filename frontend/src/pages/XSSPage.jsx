import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import api from '../utils/api'
import useAuthStore from '../store/authStore'
import { sanitizeUrl } from '../utils/sanitize'
import { getWsUrl } from '../utils/api'

const SEVERITY_COLORS = {
  CRITICAL: '#ff0040',
  HIGH: '#ff3366',
  MEDIUM: '#ffb347',
  LOW: '#00ff88',
}

const RISK_COLORS = {
  critical: '#ff0040',
  high: '#ff3366',
  medium: '#ffb347',
  low: '#00ff88',
}

const XSS_TYPE_CONFIG = {
  reflected: { label: '🔁 REFLECTED', color: '#a855f7' },
  stored: { label: '💾 STORED', color: '#ff3366' },
  dom: { label: '🌐 DOM', color: '#00f2fe' },
  header: { label: '📋 HEADER', color: '#ffb347' },
  blind: { label: '🕶️ BLIND', color: '#ff6b6b' },
}

const SCAN_MODES = [
  { id: 'quick', label: 'QUICK SCAN', desc: '48 bypass payloads, param brute-force, header injection', time: '~2min' },
  { id: 'deep', label: 'DEEP SCAN', desc: '450+ payloads, full spider, DOM + Stored + Blind XSS', time: '~12min' },
]

export default function XSSPage() {
  const navigate = useNavigate()
  const { user, fetchMe } = useAuthStore()
  const [loading, setLoading] = useState(true)

  const [target, setTarget] = useState('')
  const [scanMode, setScanMode] = useState('quick')
  const [scanning, setScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [statusMsg, setStatusMsg] = useState('')
  const [activeWs, setActiveWs] = useState(null)
  const [scanPhase, setScanPhase] = useState('')

  const [currentResult, setCurrentResult] = useState(null)
  const [liveVulns, setLiveVulns] = useState([])
  const [wafInfo, setWafInfo] = useState(null)
  const [expandedVuln, setExpandedVuln] = useState(null)

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
      const { data } = await api.get('/xss/scans')
      setHistory(data.scans)
    } catch {}
  }

  // Derive scan phase from status messages
  const getPhaseFromMsg = (msg) => {
    if (msg.includes('connectivity')) return 'connectivity'
    if (msg.includes('WAF') || msg.includes('firewall')) return 'waf'
    if (msg.includes('Spider') || msg.includes('spider')) return 'spider'
    if (msg.includes('JavaScript') || msg.includes('JS')) return 'js_parse'
    if (msg.includes('DOM')) return 'dom'
    if (msg.includes('Crawling') || msg.includes('forms')) return 'crawl'
    if (msg.includes('Brute-forc') || msg.includes('parameter')) return 'param_brute'
    if (msg.includes('path segment') || msg.includes('Path')) return 'path_fuzz'
    if (msg.includes('header') || msg.includes('Header')) return 'header'
    if (msg.includes('injection point') || msg.includes('payload')) return 'inject'
    if (msg.includes('blind') || msg.includes('Blind')) return 'blind'
    return 'scanning'
  }

  const handleScan = async () => {
    if (!target.trim()) {
      toast.error('Target URL daalo', { style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } })
      return
    }
    setScanning(true)
    setScanProgress(0)
    setStatusMsg('Connecting...')
    setCurrentResult(null)
    setLiveVulns([])
    setWafInfo(null)
    setScanPhase('connectivity')
    setExpandedVuln(null)

    const token = localStorage.getItem('access_token')
    if (!token) { toast.error('Unauthorized'); setScanning(false); return }

    const wsUrl = getWsUrl('/api/v1/xss/ws/scan')
    const ws = new WebSocket(wsUrl)
    setActiveWs(ws)

    ws.onopen = () => {
      ws.send(JSON.stringify({ token, target: target.trim(), scan_mode: scanMode }))
      setStatusMsg('Initializing scan engine...')
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
          setScanPhase(getPhaseFromMsg(msg.message))
        } else if (msg.type === 'progress') {
          setScanProgress(msg.progress)
        } else if (msg.type === 'waf_detected') {
          setWafInfo(msg.data)
        } else if (msg.type === 'vuln_found') {
          setLiveVulns(prev => [...prev, msg.data])
          resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' })
        } else if (msg.type === 'complete') {
          setCurrentResult(msg.data)
          setLiveVulns(msg.data.vulnerabilities || [])
          setWafInfo(msg.data.waf_detected ? { detected: true, waf_name: msg.data.waf_name } : null)
          setScanProgress(100)
          setScanning(false)
          loadHistory()
          const v = msg.data.total_vulnerable
          if (v > 0) {
            toast.error(`⚠ ${v} XSS vulnerability${v > 1 ? 'ies' : 'y'} found!`, { style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } })
          } else {
            toast.success('Scan complete — No XSS found', { style: { background: '#010204', color: '#00ff88', border: '1px solid #00ff88' } })
          }
          ws.close()
        }
      } catch {}
    }

    ws.onerror = () => {
      setStatusMsg('Network timeout or Target unreachable')
      toast.error('Connection failed! The target might be down, blocking requests, or unreachable.', { 
        style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366', maxWidth: 400 } 
      })
      setScanning(false)
    }

    ws.onclose = (event) => {
      setScanning(false)
      setActiveWs(null)
      if (event.code !== 1000 && event.code !== 1008 && scanProgress < 100) {
          toast.error('Scan stopped abruptly. Target may have blocked the connection or timed out.', { 
            style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } 
          })
      }
    }
  }

  const handleCancel = () => {
    if (activeWs && activeWs.readyState === WebSocket.OPEN) {
      activeWs.send(JSON.stringify({ action: 'stop' }))
      toast('Cancelling scan...', { icon: '🛑', style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } })
    }
  }

  const loadScan = async (scanId) => {
    try {
      const { data } = await api.get(`/xss/scans/${scanId}`)
      setCurrentResult(data)
      setLiveVulns(data.vulnerabilities || [])
      setWafInfo(data.waf_detected ? { detected: true, waf_name: data.waf_name } : null)
      setShowHistory(false)
    } catch { toast.error('Failed to load scan') }
  }

  const deleteScan = async (scanId) => {
    try {
      await api.delete(`/xss/scans/${scanId}`)
      toast.success('Scan deleted', { style: { background: '#010204', color: '#00f2fe', border: '1px solid #00f2fe' } })
      loadHistory()
      if (currentResult?.id === scanId) { setCurrentResult(null); setLiveVulns([]); setWafInfo(null) }
    } catch { toast.error('Delete failed') }
  }

  const copyPayload = (payload) => {
    navigator.clipboard.writeText(payload)
    toast.success('Payload copied!', { style: { background: '#010204', color: '#a855f7', border: '1px solid #a855f7' } })
  }

  const executeLaunch = (v) => {
    // 1. URL Parameter
    if (v.point_type === "url_param" || v.vulnerable_url) {
      window.open(v.vulnerable_url || v.endpoint, '_blank')
      return
    }

    // 2. Form Field injection
    if (v.point_type === "form_field") {
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
          <title>Shadow Spike - XSS Form Exploit</title>
          <style>
            body { background: #010204; color: #fff; font-family: monospace; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
            .container { border: 1px dashed #a855f7; padding: 30px; border-radius: 8px; text-align: center; }
            h2 { color: #a855f7; letter-spacing: 2px; }
          </style>
        </head>
        <body>
          <div class="container">
            <h2>Executing XSS POST Payload...</h2>
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

    // 3. Other injection types (DOM, Cookie, Header)
    toast.error(`For ${v.point_type?.replace('_', ' ')?.toUpperCase() || 'DOM/Header/Cookie'} injections, use a proxy tool or browser extensions to inject the payload.`, {
      style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366', maxWidth: 450 }
    })
  }


  const exportResults = () => {
    const vulns = liveVulns
    if (!vulns.length) return
    const lines = [
      '═══════════════════════════════════════════════════════════',
      'XSS SCAN REPORT — Shadow Spike v2.0',
      '═══════════════════════════════════════════════════════════',
      `Target: ${currentResult?.target || target}`,
      `Mode: ${currentResult?.scan_mode || scanMode}`,
      `Total Vulnerabilities: ${vulns.length}`,
      `WAF Detected: ${currentResult?.waf_detected ? currentResult.waf_name?.toUpperCase() : 'None'}`,
      `Parameters Discovered: ${currentResult?.params_discovered || 0}`,
      `Header Vulns: ${currentResult?.header_vulns || 0}`,
      `Blind XSS Injected: ${currentResult?.blind_vulns || 0}`,
      `DOM Vulns: ${currentResult?.dom_vulns || 0}`,
      '─'.repeat(60),
      ...vulns.map((v, i) => {
        let reproduceInstructions = ""
        if (v.method === "POST") {
          reproduceInstructions = `\n    How to Execute: This is a POST-based injection. Go to '${v.endpoint}', fill the '${v.field_label || v.parameter}' field with the payload below, and submit the form.`
        } else if (v.xss_type === "header") {
          reproduceInstructions = `\n    How to Execute: Send a request to '${v.endpoint}' with the '${v.parameter}' header set to the payload below.`
        } else if (v.xss_type === "blind") {
          reproduceInstructions = `\n    How to Execute: Blind XSS payload was injected. Monitor your callback server for delayed execution.`
        } else if (v.payload && (v.payload.includes("onmouseover") || v.payload.includes("autofocus"))) {
          reproduceInstructions = `\n    How to Execute: Open the Direct URL below. You must physically HOVER or CLICK on the vulnerable element for the payload to trigger (User Interaction required).`
        } else {
          reproduceInstructions = `\n    How to Execute: Open the Direct URL below in your browser. The payload should execute automatically.`
        }

        return `[${i + 1}] ${v.severity} | ${v.xss_type?.toUpperCase() || 'REFLECTED'} | ${v.endpoint}\n    Vulnerable Point: ${v.location_summary}${reproduceInstructions}\n    Direct URL: ${v.vulnerable_url || 'N/A (Use instructions above)'}\n    Payload: ${v.payload}\n    Evidence: ${v.evidence || 'N/A'}\n    Impact: ${v.impact || 'Session hijacking, phishing, and unauthorized actions.'}\n`
      })
    ]
    const blob = new Blob([lines.join('\n')], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'xss_report.txt'
    a.click()
  }

  if (loading) return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#a855f7', fontSize: 13, letterSpacing: 4 }}>
      INITIALIZING XSS SCANNER v2.0...
    </div>
  )

  const displayVulns = scanning ? liveVulns : (currentResult?.vulnerabilities || liveVulns)

  // Group vulnerabilities by type for stats
  const vulnTypeStats = displayVulns.reduce((acc, v) => {
    const t = v.xss_type || 'reflected'
    acc[t] = (acc[t] || 0) + 1
    return acc
  }, {})

  return (
    <div style={{ minHeight: '100vh', paddingTop: 60, paddingBottom: 60 }}>

      {/* Topbar */}
      <div style={{
        position: 'fixed', top: 0, left: 0, right: 0,
        display: 'flex', alignItems: 'center', padding: '0 30px',
        height: 60, background: 'rgba(1,2,4,0.92)', borderBottom: '1px solid rgba(168,85,247,0.2)', gap: 15, zIndex: 100, backdropFilter: 'blur(10px)'
      }}>
        <div onClick={() => navigate('/dashboard')} style={{ fontSize: 18, fontWeight: 300, color: '#fff', letterSpacing: 5, cursor: 'pointer' }}>
          SHADOW SPIKE
        </div>
        <span style={{ color: 'rgba(255,255,255,0.3)' }}>›</span>
        <span style={{
          background: 'rgba(168,85,247,0.1)', border: '1px solid rgba(168,85,247,0.4)',
          color: '#a855f7', fontSize: 10, padding: '3px 10px', borderRadius: 20, letterSpacing: 2
        }}>XSS SCANNER v2.0</span>

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 12 }}>
          {displayVulns.length > 0 && !scanning && (
            <button onClick={exportResults} className="btn-eclipse" style={{ padding: '6px 15px', fontSize: 10, width: 'auto', background: 'rgba(168,85,247,0.1)', borderColor: '#a855f7', color: '#a855f7' }}>
              ⬇ EXPORT REPORT
            </button>
          )}
          <button onClick={() => setShowHistory(!showHistory)} className="btn-eclipse" style={{ padding: '6px 15px', fontSize: 10, width: 'auto', background: showHistory ? 'rgba(168,85,247,0.1)' : 'transparent', borderColor: showHistory ? '#a855f7' : 'var(--glass-border)', color: showHistory ? '#a855f7' : '#fff' }}>
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
            XSS <span style={{ color: '#a855f7' }}>SCANNER</span> <span style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)', letterSpacing: 1 }}>v2.0 — Guaranteed Find</span>
          </h1>
          <p style={{ color: 'rgba(255,255,255,0.5)', fontSize: 13, marginTop: 10, letterSpacing: 1 }}>
            Multi-vector XSS detection: Parameter brute-force, Header injection, DOM analysis, WAF bypass, Blind XSS callbacks, and 450+ filter-evasion payloads.
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: showHistory ? '1fr 350px' : '1fr', gap: 25 }}>
          <div>

            {/* Config Card */}
            <div className="eclipse-card" style={{ marginBottom: 25, padding: 30, borderColor: 'rgba(168,85,247,0.15)' }}>
              <div style={{ fontSize: 11, letterSpacing: 3, color: '#a855f7', textTransform: 'uppercase', marginBottom: 20 }}>
                SCAN CONFIGURATION
              </div>

              {/* Target */}
              <div style={{ marginBottom: 20 }}>
                <label style={{ display: 'block', color: '#c4b5fd', fontSize: 11, letterSpacing: 2, marginBottom: 8 }}>
                  TARGET URL / DOMAIN
                </label>
                <input
                  type="text"
                  className="eclipse-input"
                  value={target}
                  onChange={e => setTarget(sanitizeUrl(e.target.value))}
                  placeholder="https://example.com/search?q=test"
                  disabled={scanning}
                  style={{ marginBottom: 0, fontSize: 15, letterSpacing: 1, borderColor: 'rgba(168,85,247,0.3)' }}
                  onKeyDown={e => e.key === 'Enter' && !scanning && handleScan()}
                />
              </div>

              {/* Scan Mode */}
              <div style={{ marginBottom: 22 }}>
                <label style={{ display: 'block', color: '#c4b5fd', fontSize: 11, letterSpacing: 2, marginBottom: 12 }}>
                  SCAN MODE
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  {SCAN_MODES.map(m => (
                    <div
                      key={m.id}
                      onClick={() => !scanning && setScanMode(m.id)}
                      style={{
                        padding: '18px', borderRadius: 10, cursor: scanning ? 'not-allowed' : 'pointer',
                        background: scanMode === m.id ? 'rgba(168,85,247,0.1)' : 'var(--glass-bg)',
                        border: `1px solid ${scanMode === m.id ? 'rgba(168,85,247,0.5)' : 'var(--glass-border)'}`,
                        transition: 'all 0.3s', textAlign: 'center',
                        boxShadow: scanMode === m.id ? '0 0 20px rgba(168,85,247,0.1)' : 'none',
                      }}
                    >
                      <div style={{ fontSize: 12, color: scanMode === m.id ? '#a855f7' : '#fff', letterSpacing: 2, marginBottom: 6 }}>{m.label}</div>
                      <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.45)' }}>{m.desc}</div>
                      <div style={{ fontSize: 9, color: scanMode === m.id ? '#a855f7' : 'rgba(255,255,255,0.25)', marginTop: 5 }}>{m.time}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Button */}
              {scanning ? (
                <button onClick={handleCancel} className="btn-eclipse" style={{ background: 'rgba(255,51,102,0.12)', borderColor: '#ff3366', color: '#ff3366' }}>
                  🛑 CANCEL SCAN
                </button>
              ) : (
                <button onClick={handleScan} className="btn-eclipse" style={{ background: 'rgba(168,85,247,0.12)', borderColor: '#a855f7', color: '#a855f7' }}>
                  ⚡ INITIATE XSS SCAN
                </button>
              )}

              {/* Progress with Phase Indicators */}
              {scanning && (
                <div style={{ marginTop: 22 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                    <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.5)', letterSpacing: 1, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{statusMsg}</span>
                    <span style={{ fontSize: 10, color: '#a855f7', letterSpacing: 1, flexShrink: 0, marginLeft: 10 }}>{Math.round(scanProgress)}%</span>
                  </div>
                  <div style={{ width: '100%', height: 4, background: 'rgba(255,255,255,0.05)', borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{
                      width: `${scanProgress}%`, height: '100%',
                      background: 'linear-gradient(90deg, #7c3aed, #a855f7, #c084fc)',
                      boxShadow: '0 0 12px #a855f7',
                      transition: 'width 0.4s ease', borderRadius: 2,
                    }} />
                  </div>
                  
                  {/* Phase Pills */}
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 12 }}>
                    {[
                      { id: 'connectivity', label: '🔌 CONNECT', min: 0 },
                      { id: 'waf', label: '🛡️ WAF', min: 2 },
                      { id: 'spider', label: '🕷️ SPIDER', min: 5 },
                      { id: 'js_parse', label: '📜 JS PARSE', min: 12 },
                      { id: 'crawl', label: '🔎 CRAWL', min: 22 },
                      { id: 'param_brute', label: '🔓 PARAMS', min: 28 },
                      { id: 'header', label: '📋 HEADERS', min: 38 },
                      { id: 'inject', label: '⚡ INJECT', min: 48 },
                    ].map(phase => {
                      const isActive = scanPhase === phase.id
                      const isDone = scanProgress > phase.min + 10
                      return (
                        <span key={phase.id} style={{
                          fontSize: 8, padding: '3px 8px', borderRadius: 10, letterSpacing: 1,
                          background: isActive ? 'rgba(168,85,247,0.25)' : isDone ? 'rgba(0,255,136,0.08)' : 'rgba(255,255,255,0.03)',
                          border: `1px solid ${isActive ? '#a855f7' : isDone ? 'rgba(0,255,136,0.2)' : 'rgba(255,255,255,0.08)'}`,
                          color: isActive ? '#c084fc' : isDone ? '#00ff88' : 'rgba(255,255,255,0.25)',
                          transition: 'all 0.3s',
                          animation: isActive ? 'pulse 1.5s infinite' : 'none',
                        }}>{isDone ? '✓ ' : ''}{phase.label}</span>
                      )
                    })}
                  </div>

                  {liveVulns.length > 0 && (
                    <div style={{ marginTop: 10, fontSize: 11, color: '#ff3366', letterSpacing: 1 }}>
                      ⚠ {liveVulns.length} vulnerability{liveVulns.length > 1 ? 'ies' : ''} found so far...
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* WAF Detection Banner */}
            {wafInfo && wafInfo.detected && (
              <div style={{
                marginBottom: 20, padding: '14px 20px', borderRadius: 10,
                background: 'rgba(255,179,71,0.06)', border: '1px solid rgba(255,179,71,0.25)',
                display: 'flex', alignItems: 'center', gap: 15, animation: 'fade-up 0.4s ease-out',
              }}>
                <div style={{ fontSize: 24 }}>🛡️</div>
                <div>
                  <div style={{ fontSize: 12, color: '#ffb347', letterSpacing: 2, fontWeight: 500 }}>
                    WAF DETECTED: {wafInfo.waf_name?.toUpperCase()}
                  </div>
                  <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.4)', marginTop: 4, letterSpacing: 1 }}>
                    Adaptive bypass mode engaged — encoding mutations & WAF-specific payloads active
                  </div>
                </div>
                <span style={{
                  fontSize: 9, padding: '4px 10px', borderRadius: 20, marginLeft: 'auto',
                  background: 'rgba(255,179,71,0.1)', border: '1px solid rgba(255,179,71,0.3)',
                  color: '#ffb347', letterSpacing: 1, flexShrink: 0
                }}>BYPASS MODE</span>
              </div>
            )}

            {/* Stats Row */}
            {(currentResult || (scanning && liveVulns.length > 0)) && (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 12, marginBottom: 25 }}>
                {[
                  { label: 'VULNERABLE', val: currentResult?.total_vulnerable ?? liveVulns.length, color: '#ff3366' },
                  { label: 'CRITICAL', val: currentResult?.critical_count ?? liveVulns.filter(v => v.severity === 'CRITICAL').length, color: '#ff0040' },
                  { label: 'MEDIUM', val: currentResult?.medium_count ?? liveVulns.filter(v => v.severity === 'MEDIUM').length, color: '#ffb347' },
                  { label: 'PAYLOADS', val: currentResult?.payloads_tested ?? '—', color: '#a855f7' },
                  ...(currentResult?.scan_duration ? [{ label: 'DURATION', val: `${currentResult.scan_duration}s`, color: 'var(--accent-cyan)' }] : []),
                  ...(currentResult?.risk_level ? [{ label: 'RISK', val: currentResult.risk_level.toUpperCase(), color: RISK_COLORS[currentResult.risk_level] || '#fff' }] : []),
                  ...(currentResult?.params_discovered ? [{ label: 'PARAMS FOUND', val: currentResult.params_discovered, color: '#4facfe' }] : []),
                  ...(currentResult?.header_vulns ? [{ label: 'HEADER XSS', val: currentResult.header_vulns, color: '#ffb347' }] : []),
                  ...(currentResult?.dom_vulns ? [{ label: 'DOM XSS', val: currentResult.dom_vulns, color: '#00f2fe' }] : []),
                  ...(currentResult?.blind_vulns ? [{ label: 'BLIND XSS', val: currentResult.blind_vulns, color: '#ff6b6b' }] : []),
                ].map((s, i) => (
                  <div key={i} className="eclipse-card" style={{ padding: 14, textAlign: 'center' }}>
                    <div style={{ fontSize: 8, color: 'rgba(255,255,255,0.4)', letterSpacing: 2, marginBottom: 6 }}>{s.label}</div>
                    <div style={{ fontSize: 22, fontWeight: 300, color: s.color, textShadow: `0 0 15px ${s.color}66` }}>{s.val}</div>
                  </div>
                ))}
              </div>
            )}

            {/* XSS Type Breakdown (when results available) */}
            {displayVulns.length > 0 && Object.keys(vulnTypeStats).length > 1 && (
              <div style={{ marginBottom: 20, display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                {Object.entries(vulnTypeStats).map(([type, count]) => {
                  const cfg = XSS_TYPE_CONFIG[type] || { label: type.toUpperCase(), color: '#a855f7' }
                  return (
                    <div key={type} style={{
                      padding: '8px 14px', borderRadius: 8,
                      background: `${cfg.color}10`, border: `1px solid ${cfg.color}30`,
                      display: 'flex', alignItems: 'center', gap: 8,
                    }}>
                      <span style={{ fontSize: 10, color: cfg.color, letterSpacing: 1 }}>{cfg.label}</span>
                      <span style={{ fontSize: 14, fontWeight: 300, color: cfg.color }}>{count}</span>
                    </div>
                  )
                })}
              </div>
            )}

            {/* Vulnerability Table */}
            {displayVulns.length > 0 && (
              <div className="eclipse-card" style={{ padding: 0, borderColor: 'rgba(168,85,247,0.15)', animation: 'fade-up 0.4s ease-out' }}>
                <div style={{ padding: '18px 25px', borderBottom: '1px solid rgba(168,85,247,0.15)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ fontSize: 11, letterSpacing: 3, color: '#a855f7' }}>
                    XSS INJECTION POINTS — {currentResult?.target || target}
                  </div>
                  <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.4)', letterSpacing: 1 }}>
                    {displayVulns.length} FOUND {scanning ? '(live)' : ''}
                  </div>
                </div>

                {/* Table Header */}
                <div style={{
                  display: 'grid', gridTemplateColumns: '80px 80px 1fr 1fr 100px',
                  gap: 12, padding: '12px 25px', borderBottom: '1px solid var(--glass-border)',
                  background: 'rgba(0,0,0,0.3)'
                }}>
                  {['SEVERITY', 'TYPE', 'VULNERABLE LOCATION', 'PAYLOAD', 'ACTION'].map(h => (
                    <div key={h} style={{ fontSize: 9, letterSpacing: 2, color: 'rgba(255,255,255,0.35)' }}>{h}</div>
                  ))}
                </div>

                {displayVulns.map((v, i) => (
                  <div key={i} ref={i === displayVulns.length - 1 ? resultsRef : null}>
                    <div style={{
                      display: 'grid', gridTemplateColumns: '80px 80px 1fr 1fr 100px',
                      gap: 12, padding: '14px 25px', alignItems: 'center',
                      borderBottom: i < displayVulns.length - 1 ? '1px solid rgba(255,255,255,0.03)' : 'none',
                      transition: 'background 0.2s',
                      animation: 'fade-up 0.3s ease-out',
                      cursor: 'pointer',
                      background: expandedVuln === i ? 'rgba(168,85,247,0.06)' : 'transparent',
                    }}
                      onClick={() => setExpandedVuln(expandedVuln === i ? null : i)}
                      onMouseEnter={e => { if (expandedVuln !== i) e.currentTarget.style.background = 'rgba(168,85,247,0.04)' }}
                      onMouseLeave={e => { if (expandedVuln !== i) e.currentTarget.style.background = 'transparent' }}
                    >
                      {/* Severity */}
                      <div>
                        <span style={{
                          fontSize: 9, padding: '3px 9px', borderRadius: 20, letterSpacing: 1,
                          background: `${SEVERITY_COLORS[v.severity] || '#aaa'}15`,
                          border: `1px solid ${SEVERITY_COLORS[v.severity] || '#aaa'}40`,
                          color: SEVERITY_COLORS[v.severity] || '#aaa',
                        }}>{v.severity}</span>
                      </div>
                      {/* XSS Type Badge */}
                      <div>
                        {(() => {
                          const t = v.xss_type || 'reflected'
                          const cfg = XSS_TYPE_CONFIG[t] || { label: t.toUpperCase(), color: '#a855f7' }
                          return (
                            <span style={{
                              fontSize: 8, padding: '3px 7px', borderRadius: 20, letterSpacing: 1,
                              background: `${cfg.color}15`,
                              border: `1px solid ${cfg.color}40`,
                              color: cfg.color, whiteSpace: 'nowrap',
                            }}>{cfg.label}</span>
                          )
                        })()}
                      </div>
                      <div style={{ fontSize: 11, color: '#fff', letterSpacing: 1, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        <div style={{ color: 'var(--accent-cyan)', fontSize: 9, marginBottom: 4, letterSpacing: 2 }}>VULNERABLE PATH / POINT</div>
                        <div style={{ 
                          fontSize: 13, color: '#c4b5fd', fontFamily: 'monospace', 
                          background: 'rgba(0,0,0,0.2)', padding: '4px 8px', borderRadius: 4,
                          borderLeft: '2px solid var(--accent-cyan)', marginBottom: 6
                        }}>
                          {v.location_summary}
                        </div>
                        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                          <span style={{ fontSize: 9, color: 'rgba(255,255,255,0.4)', letterSpacing: 1 }}>VULNERABLE INPUT:</span>
                          <span style={{ 
                            fontSize: 10, padding: '2px 8px', borderRadius: 4, 
                            background: 'rgba(0,242,254,0.1)', border: '1px solid rgba(0,242,254,0.3)',
                            color: 'var(--accent-cyan)', fontWeight: 'bold'
                          }}>
                            {v.field_label || v.parameter}
                          </span>
                        </div>
                      </div>
                      <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.7)', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={v.payload}>
                        {v.payload}
                      </div>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button onClick={(e) => { e.stopPropagation(); copyPayload(v.payload) }} style={{
                          background: 'rgba(168,85,247,0.08)', border: '1px solid rgba(168,85,247,0.2)',
                          color: '#a855f7', fontSize: 9, cursor: 'pointer', padding: '4px 8px',
                          borderRadius: 4, letterSpacing: 1, transition: '0.2s'
                        }}
                          onMouseEnter={e => e.target.style.background = 'rgba(168,85,247,0.2)'}
                          onMouseLeave={e => e.target.style.background = 'rgba(168,85,247,0.08)'}
                        >COPY</button>
                        {v.xss_type !== 'blind' && v.xss_type !== 'header' && (
                          <button onClick={(e) => { e.stopPropagation(); executeLaunch(v) }} style={{
                            background: 'rgba(0,242,254,0.08)', border: '1px solid rgba(0,242,254,0.2)',
                            color: 'var(--accent-cyan)', fontSize: 9, cursor: 'pointer', padding: '4px 8px',
                            borderRadius: 4, letterSpacing: 1, transition: '0.2s'
                          }}
                            onMouseEnter={e => e.target.style.background = 'rgba(0,242,254,0.2)'}
                            onMouseLeave={e => e.target.style.background = 'rgba(0,242,254,0.08)'}
                          >LAUNCH</button>
                        )}
                      </div>
                    </div>

                    {/* Expanded Detail Panel */}
                    {expandedVuln === i && (
                      <div style={{ 
                        padding: '15px 25px 20px', 
                        background: 'rgba(168,85,247,0.03)',
                        borderBottom: '1px solid rgba(168,85,247,0.1)',
                        animation: 'fade-up 0.2s ease-out',
                      }}>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 15 }}>
                          <div>
                            <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.4)', letterSpacing: 2, marginBottom: 6 }}>FULL PAYLOAD</div>
                            <div style={{
                              fontSize: 11, color: '#c084fc', fontFamily: 'monospace',
                              background: 'rgba(0,0,0,0.4)', padding: '10px 12px', borderRadius: 6,
                              border: '1px solid rgba(168,85,247,0.15)', wordBreak: 'break-all',
                              lineHeight: 1.6
                            }}>
                              {v.payload}
                            </div>
                          </div>
                          <div>
                            <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.4)', letterSpacing: 2, marginBottom: 6 }}>IMPACT ASSESSMENT</div>
                            <div style={{
                              fontSize: 11, color: 'rgba(255,255,255,0.6)',
                              background: 'rgba(0,0,0,0.3)', padding: '10px 12px', borderRadius: 6,
                              border: `1px solid ${SEVERITY_COLORS[v.severity]}20`,
                              lineHeight: 1.6
                            }}>
                              {v.impact}
                            </div>
                          </div>
                        </div>
                        {v.evidence && (
                          <div style={{ marginTop: 12 }}>
                            <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.4)', letterSpacing: 2, marginBottom: 6 }}>EVIDENCE</div>
                            <div style={{
                              fontSize: 10, color: 'rgba(255,255,255,0.35)', fontFamily: 'monospace',
                              background: 'rgba(0,0,0,0.3)', padding: '8px 12px', borderRadius: 6,
                              borderLeft: `2px solid ${SEVERITY_COLORS[v.severity]}50`,
                              overflow: 'auto', maxHeight: 100, whiteSpace: 'pre-wrap',
                              wordBreak: 'break-all'
                            }}>
                              {v.evidence}
                            </div>
                          </div>
                        )}
                        {v.vulnerable_url && (
                          <div style={{ marginTop: 12 }}>
                            <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.4)', letterSpacing: 2, marginBottom: 6 }}>DIRECT URL</div>
                            <div style={{
                              fontSize: 10, color: 'var(--accent-cyan)', fontFamily: 'monospace',
                              background: 'rgba(0,0,0,0.3)', padding: '8px 12px', borderRadius: 6,
                              overflow: 'auto', maxHeight: 60, wordBreak: 'break-all'
                            }}>
                              {v.vulnerable_url}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Evidence Row (collapsed view) */}
                    {expandedVuln !== i && v.evidence && (
                      <div style={{ padding: '0 25px 12px 25px', marginTop: -6 }}>
                        <div style={{
                          fontSize: 10, color: 'rgba(255,255,255,0.35)', fontFamily: 'monospace',
                          background: 'rgba(0,0,0,0.3)', padding: '6px 12px', borderRadius: 6,
                          borderLeft: `2px solid ${SEVERITY_COLORS[v.severity]}50`,
                          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                        }} title={v.evidence}>
                          ▸ {v.evidence}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* Empty State */}
            {!currentResult && !scanning && displayVulns.length === 0 && (
              <div className="eclipse-card" style={{ padding: 80, textAlign: 'center' }}>
                <div style={{ fontSize: 50, marginBottom: 20, opacity: 0.15 }}>🕷</div>
                <div style={{ fontSize: 16, color: 'rgba(255,255,255,0.35)', letterSpacing: 3, marginBottom: 10 }}>
                  AWAITING TARGET
                </div>
                <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.2)', letterSpacing: 1, maxWidth: 500, margin: '0 auto', lineHeight: 1.8 }}>
                  Enter a URL above. The v2.0 engine will: brute-force hidden parameters, test HTTP headers, detect WAF firewalls, crawl all pages, inject DOM/Reflected/Stored/Blind XSS payloads, and apply smart encoding mutations for WAF bypass.
                </div>
              </div>
            )}

            {/* Safe Result */}
            {currentResult && displayVulns.length === 0 && (
              <div className="eclipse-card" style={{ padding: 60, textAlign: 'center' }}>
                <div style={{ fontSize: 40, marginBottom: 15 }}>✅</div>
                <div style={{ fontSize: 15, color: '#00ff88', letterSpacing: 3, marginBottom: 8 }}>NO XSS VULNERABILITIES FOUND</div>
                <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.35)', letterSpacing: 1 }}>
                  Tested {currentResult.payloads_tested} payloads on {currentResult.target}
                  {currentResult.waf_detected && ` (WAF: ${currentResult.waf_name?.toUpperCase()})`}
                </div>
              </div>
            )}

          </div>

          {/* History Sidebar */}
          {showHistory && (
            <div style={{ animation: 'fade-up 0.3s ease-out' }}>
              <div style={{ fontSize: 11, letterSpacing: 3, color: '#a855f7', textTransform: 'uppercase', marginBottom: 15 }}>
                XSS SCAN HISTORY
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
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                        <div style={{ fontSize: 12, color: '#fff', letterSpacing: 1, flex: 1, marginRight: 8, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={h.target}>
                          {h.target}
                        </div>
                        <button onClick={e => { e.stopPropagation(); deleteScan(h.id) }} style={{
                          background: 'transparent', border: 'none', color: 'rgba(255,255,255,0.2)',
                          cursor: 'pointer', fontSize: 14, padding: '2px 5px', transition: '0.2s', flexShrink: 0
                        }}
                          onMouseEnter={e => e.target.style.color = '#ff3366'}
                          onMouseLeave={e => e.target.style.color = 'rgba(255,255,255,0.2)'}
                        >✕</button>
                      </div>
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                        <span style={{
                          fontSize: 9, padding: '2px 8px', borderRadius: 10,
                          background: 'rgba(168,85,247,0.1)', border: '1px solid rgba(168,85,247,0.2)',
                          color: '#a855f7', letterSpacing: 1
                        }}>{h.scan_mode?.toUpperCase()}</span>
                        {h.risk_level && (
                          <span style={{
                            fontSize: 9, padding: '2px 8px', borderRadius: 10,
                            background: `${RISK_COLORS[h.risk_level]}15`,
                            border: `1px solid ${RISK_COLORS[h.risk_level]}40`,
                            color: RISK_COLORS[h.risk_level], letterSpacing: 1
                          }}>{h.risk_level.toUpperCase()}</span>
                        )}
                        {h.waf_detected && (
                          <span style={{
                            fontSize: 9, padding: '2px 8px', borderRadius: 10,
                            background: 'rgba(255,179,71,0.1)', border: '1px solid rgba(255,179,71,0.2)',
                            color: '#ffb347', letterSpacing: 1
                          }}>🛡️ WAF</span>
                        )}
                        <span style={{ fontSize: 9, color: 'rgba(255,255,255,0.3)', letterSpacing: 1 }}>
                          {h.total_vulnerable} vuln{h.total_vulnerable !== 1 ? 's' : ''}
                        </span>
                      </div>
                      <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.25)', marginTop: 8 }}>
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

      {/* Pulse animation for active phase pills */}
      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.6; }
        }
      `}</style>
    </div>
  )
}
