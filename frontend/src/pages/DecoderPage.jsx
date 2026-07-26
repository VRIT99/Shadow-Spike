import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import useAuthStore from '../store/authStore'
import api from '../utils/api'
// Note: Decoder intentionally handles arbitrary content for encode/decode.
// Only null bytes are stripped to prevent protocol-level issues.

export default function DecoderPage() {
  const navigate = useNavigate()
  const { fetchMe } = useAuthStore()
  const [loading, setLoading] = useState(true)
  
  const [inputVal, setInputVal] = useState('')
  const [outputVal, setOutputVal] = useState('')

  useEffect(() => {
    const init = async () => {
      const u = await fetchMe()
      if (!u) { navigate('/login'); return }
      setLoading(false)
    }
    init()
  }, [])

  // --- Utility functions ---

  const utf8ToBase64 = (str) => window.btoa(unescape(encodeURIComponent(str)))
  const base64ToUtf8 = (str) => decodeURIComponent(escape(window.atob(str)))

  const stringToHex = (str) => {
    let hex = ''
    for(let i=0; i<str.length; i++) {
        hex += '' + str.charCodeAt(i).toString(16).padStart(2, '0')
    }
    return hex
  }
  const hexToString = (hex) => {
    let str = ''
    hex = hex.replace(/\s+/g, '') // remove spaces just in case
    for (let i = 0; i < hex.length; i += 2) {
      str += String.fromCharCode(parseInt(hex.substr(i, 2), 16))
    }
    return str
  }

  const stringToBinary = (str) => {
    return str.split('').map(char => char.charCodeAt(0).toString(2).padStart(8, '0')).join(' ')
  }
  const binaryToString = (bin) => {
    return bin.split(' ').map(b => String.fromCharCode(parseInt(b, 2))).join('')
  }

  const encodeHtmlEntity = (str) => {
    return str.replace(/[\u00A0-\u9999<>\&]/g, function(i) {
        return '&#'+i.charCodeAt(0)+';'
    })
  }
  const decodeHtmlEntity = (str) => {
    const txt = document.createElement("textarea")
    txt.innerHTML = str
    return txt.value
  }

  const hashString = async (algorithm) => {
    try {
      const msgUint8 = new TextEncoder().encode(inputVal)
      const hashBuffer = await crypto.subtle.digest(algorithm, msgUint8)
      const hashArray = Array.from(new Uint8Array(hashBuffer))
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
      // Store in browser's local cache so any word user hashes can be "cracked" later
      localStorage.setItem('hash_cache_' + hashHex, inputVal)
      setOutputVal(hashHex)
      toast.success(`${algorithm} Hash Computed`, { style: { background: '#010204', color: '#00ff88', border: '1px solid #00ff88' }})
    } catch(err) {
      toast.error('Hashing failed')
    }
  }

  const crackHashOnline = async () => {
    if (!inputVal.trim()) { toast.error('Paste a hash to crack'); return; }
    
    toast('Searching databases and memory cache...', { icon: '🔍', style: { background: '#010204', color: '#ffb347', border: '1px solid #ffb347' }})
    
    let targetHash = inputVal.trim().toLowerCase()
    
    // Smart detection: If user left plain text in Input but Output has a hash, use Output instead
    const isHexHash = (s) => /^[a-f0-9]{32,128}$/.test(s)
    if (!isHexHash(targetHash) && isHexHash(outputVal.trim().toLowerCase())) {
        targetHash = outputVal.trim().toLowerCase()
        // Auto-swap for the user's convenience
        setInputVal(targetHash)
        setOutputVal('')
    }
    
    // Check if the user previously hashed this exact string in their browser
    const cachedWord = localStorage.getItem('hash_cache_' + targetHash)
    if (cachedWord) {
      setOutputVal(cachedWord)
      toast.success(`CRACKED!`, { style: { background: '#010204', color: '#00ff88', border: '1px solid #00ff88' }})
      return
    }
    
    try {
      const { data } = await api.get(`/decoder/crack?hash_value=${targetHash}`)
      if (data.success) {
        setOutputVal(data.result)
        toast.success(`CRACKED!`, { style: { background: '#010204', color: '#00ff88', border: '1px solid #00ff88' }})
      } else {
        setOutputVal('NOT FOUND')
        toast.error('Crack Failed.', { style: { background: '#010204', color: 'var(--error-color)', border: '1px solid var(--error-color)' }})
      }
    } catch (err) {
      toast.error('API Error during lookup')
      setOutputVal('Error: ' + err.message)
    }
  }

  const handleAction = async (actionType) => {
    if (!inputVal.trim()) {
      toast.error('Input is empty')
      return
    }

    try {
      let res = ''
      switch (actionType) {
        case 'url_encode': res = encodeURIComponent(inputVal); break;
        case 'url_decode': res = decodeURIComponent(inputVal); break;
        case 'b64_encode': res = utf8ToBase64(inputVal); break;
        case 'b64_decode': res = base64ToUtf8(inputVal); break;
        case 'hex_encode': res = stringToHex(inputVal); break;
        case 'hex_decode': res = hexToString(inputVal); break;
        case 'bin_encode': res = stringToBinary(inputVal); break;
        case 'bin_decode': res = binaryToString(inputVal); break;
        case 'html_decode': res = decodeHtmlEntity(inputVal); break;
        case 'md5': 
          const { data } = await api.post('/decoder/hash', { text: inputVal, algorithm: 'md5' });
          if(data.success) { 
            localStorage.setItem('hash_cache_' + data.result, inputVal)
            setOutputVal(data.result); 
            toast.success('MD5 Hash Computed', { style: { background: '#010204', color: '#00ff88', border: '1px solid #00ff88' }}); 
          }
          else { toast.error('Hashing failed') };
          return;
        case 'sha1': await hashString('SHA-1'); return;
        case 'sha256': await hashString('SHA-256'); return;
        case 'crack_online': await crackHashOnline(); return;
        default: break;
      }
      setOutputVal(res)
      toast.success('Operation Successful', { style: { background: '#010204', color: '#4facfe', border: '1px solid #4facfe' }})
    } catch(e) {
      toast.error('Invalid input for selected format', { style: { background: '#010204', color: 'var(--error-color)', border: '1px solid var(--error-color)' }})
      setOutputVal('Error: ' + e.message)
    }
  }

  const copyToClipboard = () => {
    if(!outputVal) return
    navigator.clipboard.writeText(outputVal)
    toast.success('Copied to clipboard', { style: { background: '#010204', color: '#00ff88', border: '1px solid #00ff88' }})
  }

  const swapInputOutput = () => {
    setInputVal(outputVal)
    setOutputVal('')
    toast('Swapped Input & Output', { icon: '🔄', style: { background: '#010204', color: '#b983ff', border: '1px solid #b983ff' } })
  }

  if (loading) return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#4facfe', fontSize: 13, letterSpacing: 4 }}>
      INITIALIZING DECODER...
    </div>
  )

  const ButtonGroup = ({ title, encodeAction, decodeAction }) => (
    <div style={{ marginBottom: 15 }}>
      <div style={{ fontSize: 10, letterSpacing: 2, color: 'rgba(255,255,255,0.4)', marginBottom: 8 }}>{title}</div>
      <div style={{ display: 'flex', gap: 10 }}>
        {encodeAction && (
          <button 
            onClick={() => handleAction(encodeAction)}
            style={{ 
              flex: 1, padding: '8px', 
              background: 'rgba(79,172,254,0.1)', border: '1px solid rgba(79,172,254,0.3)', 
              color: '#4facfe', fontSize: 11, cursor: 'pointer', borderRadius: 4, transition: '0.2s', letterSpacing: 1
            }}
            onMouseEnter={e => e.currentTarget.style.background = 'rgba(79,172,254,0.2)'}
            onMouseLeave={e => e.currentTarget.style.background = 'rgba(79,172,254,0.1)'}
          >
            ENCODE
          </button>
        )}
        {decodeAction && (
          <button 
            onClick={() => handleAction(decodeAction)}
            style={{ 
              flex: 1, padding: '8px', 
              background: 'rgba(185,131,255,0.1)', border: '1px solid rgba(185,131,255,0.3)', 
              color: '#b983ff', fontSize: 11, cursor: 'pointer', borderRadius: 4, transition: '0.2s', letterSpacing: 1
            }}
            onMouseEnter={e => e.currentTarget.style.background = 'rgba(185,131,255,0.2)'}
            onMouseLeave={e => e.currentTarget.style.background = 'rgba(185,131,255,0.1)'}
          >
            DECODE
          </button>
        )}
      </div>
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
        <span style={{ color: '#4facfe', fontSize: 10, letterSpacing: 2 }}>DECODER</span>
      </div>

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        
        {/* Main Interface Area */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: 20, gap: 20, maxWidth: 1200, margin: '0 auto', width: '100%' }}>
          
          {/* Top Panel - Input */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', background: 'var(--glass-bg)', border: '1px solid var(--glass-border)', borderRadius: 12, overflow: 'hidden' }}>
            <div style={{ padding: '15px 20px', borderBottom: '1px solid rgba(255,255,255,0.05)', fontSize: 12, color: '#4facfe', letterSpacing: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>INPUT STRING / HASH</span>
              <button 
                onClick={() => setInputVal('')}
                style={{ background: 'transparent', border: '1px solid var(--error-color)', color: 'var(--error-color)', padding: '4px 10px', fontSize: 10, borderRadius: 15, cursor: 'pointer', letterSpacing: 1}}
              >CLEAR</button>
            </div>
            <textarea 
              value={inputVal}
              onChange={e => setInputVal(e.target.value.replace(/\0/g, ''))}
              placeholder="Paste text to encode/hash, OR paste a Hash to crack..."
              style={{ flex: 1, background: 'transparent', border: 'none', color: '#e2e8f0', padding: 20, fontSize: 14, fontFamily: 'monospace', outline: 'none', resize: 'none' }}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'center', margin: '-10px 0', zIndex: 10 }}>
             <button 
                onClick={swapInputOutput}
                style={{
                  background: '#010204', border: '1px solid var(--glass-border)', color: '#b983ff', padding: '10px 20px', fontSize: 11, borderRadius: 20, cursor: 'pointer', letterSpacing: 2, display: 'flex', alignItems: 'center', gap: 10, boxShadow: '0 0 15px rgba(185,131,255,0.2)'
                }}
              >
                <span>↑↓</span> SWAP INPUT / OUTPUT
              </button>
          </div>

          {/* Middle Panel - Operations */}
          <div style={{ padding: 20, display: 'flex', gap: 30, background: 'var(--glass-bg)', border: '1px solid var(--glass-border)', borderRadius: 12 }}>
            <div style={{ flex: 1 }}>
              <ButtonGroup title="URL" encodeAction="url_encode" decodeAction="url_decode" />
              <ButtonGroup title="BASE64" encodeAction="b64_encode" decodeAction="b64_decode" />
            </div>
            <div style={{ flex: 1 }}>
              <ButtonGroup title="HEXADECIMAL" encodeAction="hex_encode" decodeAction="hex_decode" />
              <ButtonGroup title="BINARY" encodeAction="bin_encode" decodeAction="bin_decode" />
            </div>
            <div style={{ flex: 1 }}>
              <ButtonGroup title="HTML ENTITY" encodeAction="html_encode" decodeAction="html_decode" />
              
              <div style={{ fontSize: 10, letterSpacing: 2, color: 'rgba(255,255,255,0.4)', marginBottom: 8 }}>HASHING & CRACKING</div>
              <div style={{ display: 'flex', gap: 10, marginBottom: 10 }}>
                <button 
                  onClick={() => handleAction('md5')}
                  style={{ flex: 1, padding: '8px', background: 'rgba(0,242,254,0.1)', border: '1px solid rgba(0,242,254,0.3)', color: '#00f2fe', fontSize: 11, cursor: 'pointer', borderRadius: 4, letterSpacing: 1}}
                >HASH MD5</button>
                <button 
                  onClick={() => handleAction('sha1')}
                  style={{ flex: 1, padding: '8px', background: 'rgba(0,242,254,0.1)', border: '1px solid rgba(0,242,254,0.3)', color: '#00f2fe', fontSize: 11, cursor: 'pointer', borderRadius: 4, letterSpacing: 1}}
                >HASH SHA-1</button>
                <button 
                  onClick={() => handleAction('sha256')}
                  style={{ flex: 1, padding: '8px', background: 'rgba(0,242,254,0.1)', border: '1px solid rgba(0,242,254,0.3)', color: '#00f2fe', fontSize: 11, cursor: 'pointer', borderRadius: 4, letterSpacing: 1}}
                >HASH SHA-256</button>
              </div>
              <div style={{ display: 'flex', gap: 10 }}>
                <button 
                  onClick={() => handleAction('crack_online')}
                  style={{ flex: 1, padding: '8px', background: 'rgba(255,51,102,0.1)', border: '1px solid rgba(255,51,102,0.3)', color: '#ff3366', fontSize: 11, cursor: 'pointer', borderRadius: 4, letterSpacing: 1}}
                >HASH CRACK</button>
              </div>
            </div>
          </div>

          {/* Bottom Panel - Output */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', background: 'var(--glass-bg)', border: '1px solid var(--glass-border)', borderRadius: 12, overflow: 'hidden' }}>
            <div style={{ padding: '15px 20px', borderBottom: '1px solid rgba(255,255,255,0.05)', fontSize: 12, color: '#b983ff', letterSpacing: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>RESULT OUTPUT</span>
              <button 
                onClick={copyToClipboard}
                style={{ background: 'rgba(0,255,136,0.1)', border: '1px solid #00ff88', color: '#00ff88', padding: '4px 10px', fontSize: 10, borderRadius: 15, cursor: 'pointer', letterSpacing: 1}}
              >COPY</button>
            </div>
            <textarea 
              value={outputVal}
              readOnly
              placeholder="Output will appear here..."
              style={{ flex: 1, background: 'rgba(0,0,0,0.3)', border: 'none', color: '#a1c4fd', padding: 20, fontSize: 14, fontFamily: 'monospace', outline: 'none', resize: 'none' }}
            />
          </div>

        </div>
      </div>
    </div>
  )
}
