import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import api from '../utils/api'
import useAuthStore from '../store/authStore'
import { sanitizeUrl, sanitizeMultiline } from '../utils/sanitize'

export default function RepeaterPage() {
  const navigate = useNavigate()
  const { fetchMe } = useAuthStore()
  const [loading, setLoading] = useState(true)
  
  const [method, setMethod] = useState('GET')
  const [url, setUrl] = useState('https://example.com')
  const [headers, setHeaders] = useState('{\n  "User-Agent": "ShadowSpike/1.0",\n  "Accept": "*/*"\n}')
  const [body, setBody] = useState('')
  
  const [response, setResponse] = useState(null)
  const [sending, setSending] = useState(false)

  useEffect(() => {
    const init = async () => {
      const u = await fetchMe()
      if (!u) { navigate('/login'); return }
      
      // Load from Proxy if available
      const savedReq = localStorage.getItem('repeater_req')
      if (savedReq) {
        const req = JSON.parse(savedReq)
        setMethod(req.method)
        setUrl(req.url)
        setHeaders(JSON.stringify(req.headers, null, 2))
        setBody(req.body || '')
        localStorage.removeItem('repeater_req') // Use once
      }
      
      setLoading(false)
    }
    init()
  }, [])

  const handleSend = async () => {
    setSending(true)
    setResponse(null)
    try {
      let parsedHeaders = {}
      try {
        parsedHeaders = JSON.parse(headers)
      } catch (e) {
        toast.error('Invalid JSON in Headers')
        setSending(false)
        return
      }

      const { data } = await api.post('/repeater/send', {
        method,
        url,
        headers: parsedHeaders,
        body
      })
      setResponse(data)
      toast.success('Response received')
    } catch (err) {
      toast.error('Failed to send request')
    } finally {
      setSending(false)
    }
  }

  if (loading) return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-cyan)', fontSize: 13, letterSpacing: 4 }}>
      INITIALIZING REPEATER...
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
        <span style={{ color: '#ffb347', fontSize: 10, letterSpacing: 2 }}>REPEATER</span>

        <button 
          onClick={handleSend}
          disabled={sending}
          className="btn-eclipse"
          style={{ 
            marginLeft: 'auto', padding: '8px 30px', fontSize: 11, 
            background: 'rgba(255,179,71,0.1)', borderColor: '#ffb347', color: '#ffb347' 
          }}
        >
          {sending ? 'SENDING...' : '⚡ GO'}
        </button>
      </div>

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        
        {/* Request Panel */}
        <div style={{ flex: 1, borderRight: '1px solid var(--glass-border)', display: 'flex', flexDirection: 'column' }}>
          <div style={{ padding: 15, background: 'rgba(255,179,71,0.03)', borderBottom: '1px solid var(--glass-border)', display: 'flex', gap: 10 }}>
            <select 
              value={method} 
              onChange={(e) => setMethod(e.target.value)}
              style={{ background: '#080c14', border: '1px solid #ffb34733', color: '#ffb347', padding: '5px 10px', fontSize: 11, outline: 'none' }}
            >
              {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map(m => <option key={m} value={m}>{m}</option>)}
            </select>
            <input 
              value={url}
              onChange={(e) => setUrl(sanitizeUrl(e.target.value))}
              placeholder="https://api.example.com/v1/..."
              style={{ flex: 1, background: '#080c14', border: '1px solid #ffb34733', color: '#fff', padding: '5px 10px', fontSize: 12, outline: 'none', fontFamily: 'monospace' }}
            />
          </div>

          <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <div style={{ padding: '10px 15px', fontSize: 10, color: '#ffb347', letterSpacing: 2 }}>HEADERS (JSON)</div>
            <textarea 
              value={headers}
              onChange={(e) => setHeaders(sanitizeMultiline(e.target.value))}
              style={{ height: '30%', background: 'transparent', border: 'none', borderBottom: '1px solid rgba(255,255,255,0.05)', color: '#00f2fe', padding: 15, fontSize: 11, fontFamily: 'monospace', outline: 'none', resize: 'none' }}
            />
            
            <div style={{ padding: '10px 15px', fontSize: 10, color: '#ffb347', letterSpacing: 2 }}>BODY</div>
            <textarea 
              value={body}
              onChange={(e) => setBody(sanitizeMultiline(e.target.value))}
              placeholder="No body"
              style={{ flex: 1, background: 'transparent', border: 'none', color: '#e2e8f0', padding: 15, fontSize: 12, fontFamily: 'monospace', outline: 'none', resize: 'none' }}
            />
          </div>
        </div>

        {/* Response Panel */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', background: '#020408' }}>
          {response ? (
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
              <div style={{ padding: '15px 25px', borderBottom: '1px solid var(--glass-border)', display: 'flex', gap: 20, alignItems: 'center' }}>
                <div style={{ fontSize: 11, color: response.status_code < 400 ? '#00ff88' : '#ff3366', fontWeight: 'bold', letterSpacing: 2 }}>
                  STATUS: {response.status_code}
                </div>
                <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', letterSpacing: 1 }}>
                  SIZE: {new Blob([response.body]).size} bytes
                </div>
              </div>

              <div style={{ flex: 1, overflowY: 'auto' }}>
                <div style={{ padding: '10px 20px', fontSize: 10, color: 'var(--accent-cyan)', letterSpacing: 2 }}>RESPONSE HEADERS</div>
                <div style={{ padding: '10px 20px', background: '#080c14', borderBottom: '1px solid rgba(255,179,71,0.05)' }}>
                  <pre style={{ margin: 0, fontSize: 11, color: '#a1c4fd', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                    {JSON.stringify(response.headers, null, 2)}
                  </pre>
                </div>

                <div style={{ padding: '10px 20px', fontSize: 10, color: 'var(--accent-cyan)', letterSpacing: 2 }}>RESPONSE BODY</div>
                <div style={{ padding: '20px' }}>
                  <pre style={{ margin: 0, fontSize: 11, color: '#e2e8f0', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                    {response.body}
                  </pre>
                </div>
              </div>
            </div>
          ) : (
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'rgba(255,255,255,0.1)', fontSize: 12, letterSpacing: 2 }}>
              {sending ? 'AWAITING RESPONSE...' : 'PRESS GO TO EXECUTE REQUEST'}
            </div>
          )}
        </div>

      </div>
    </div>
  )
}
