import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import toast from 'react-hot-toast'
import api from '../utils/api'
import useAuthStore from '../store/authStore'
import { sanitizeEmail, sanitizePassword, sanitizeTotp } from '../utils/sanitize'

export default function LoginPage() {
  const navigate = useNavigate()
  const { setTempToken, fetchMe } = useAuthStore()
  const [step, setStep] = useState('credentials')
  const [loading, setLoading] = useState(false)
  const [tempToken, setTemp] = useState('')
  const [qrData, setQrData] = useState(null)
  const [creds, setCreds] = useState({ email: '', password: '' })
  const [totp, setTotp] = useState('')
  const [showPw, setShowPw] = useState(false)

  const getError = (err) => {
    const detail = err.response?.data?.detail
    if (!detail) return 'Something went wrong'
    if (Array.isArray(detail)) return detail[0]?.msg || 'Validation error'
    return String(detail)
  }

  const showError = (err) => {
    const msg = getError(err);
    if (msg.includes('SUSPENDED') || msg.includes('REVOKED')) {
      toast.error(msg, {
        duration: 8000,
        icon: '🚫',
        style: {
          background: 'rgba(255, 51, 102, 0.1)',
          color: '#ff3366',
          border: '2px solid #ff3366',
          boxShadow: '0 0 20px rgba(255, 51, 102, 0.3)',
          padding: '16px',
          fontSize: '12px',
          letterSpacing: '1px',
          fontWeight: 'bold',
          textAlign: 'center'
        }
      });
    } else {
      toast.error(msg, { style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } })
    }
  }

  const handleLogin = async (e) => {
    e.preventDefault()
    setLoading(true)
    try {
      const { data } = await api.post('/auth/login', creds)
      setTemp(data.temp_token)
      setTempToken(data.temp_token)

      if (!data.requires_2fa) {
        const qrRes = await api.post('/auth/2fa/setup', null, {
          headers: { Authorization: `Bearer ${data.temp_token}` }
        })
        setQrData(qrRes.data)
        setStep('setup_2fa')
        toast('Setup Google Authenticator first!', { icon: '🔐', style: { background: '#010204', color: '#fff', border: '1px solid #00f2fe' } })
      } else {
        setStep('verify_2fa')
        toast.success('Password verified! Enter your 2FA code.', { style: { background: '#010204', color: '#00f2fe', border: '1px solid #00f2fe' } })
      }
    } catch (err) {
      showError(err)
    } finally {
      setLoading(false)
    }
  }

  const handleSetup2FA = async (e) => {
    e.preventDefault()
    setLoading(true)
    try {
      await api.post('/auth/2fa/verify-setup',
        { totp_code: totp },
        { headers: { Authorization: `Bearer ${tempToken}` } }
      )
      toast.success('2FA activated! Now login again.', { style: { background: '#010204', color: '#00f2fe', border: '1px solid #00f2fe' } })
      setStep('verify_2fa')
      setTotp('')
    } catch (err) {
      toast.error(getError(err))
    } finally {
      setLoading(false)
    }
  }

  const handleVerify2FA = async (e) => {
    e.preventDefault()
    setLoading(true)
    try {
      const { data } = await api.post('/auth/2fa/login', {
        temp_token: tempToken,
        totp_code: totp
      })
      localStorage.setItem('access_token', data.access_token)
      localStorage.setItem('refresh_token', data.refresh_token)
      await fetchMe()
      toast.success('Welcome back!', { style: { background: '#010204', color: '#00f2fe', border: '1px solid #00f2fe' } })
      navigate('/dashboard')
    } catch (err) {
      showError(err)
    } finally {
      setLoading(false)
    }
  }

  const labelStyle = {
    display: 'block', color: '#a1c4fd', fontSize: 11, letterSpacing: 2, marginBottom: 8, textTransform: 'uppercase'
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', padding: 16 }}>
      <div style={{ width: '100%', maxWidth: 450 }}>

        {/* Logo */}
        <h1 className="eclipse-title-small">SHADOW SPIKE</h1>
        <p style={{ textAlign: 'center', color: '#4facfe', letterSpacing: 5, fontSize: 12, marginBottom: 40, marginTop: -25, opacity: 0.8 }}>
          SECURE ACCESS GATEWAY
        </p>

        {/* Card */}
        <div className="eclipse-card">

          {/* Step 1 - Credentials */}
          {step === 'credentials' && (
            <>
              <h2 style={{ color: '#fff', fontSize: 16, marginBottom: 30, fontWeight: 300, letterSpacing: 4, textAlign: 'center' }}>
                IDENTIFICATION
              </h2>
              <form onSubmit={handleLogin}>
                <div>
                  <label style={labelStyle}>Operative Protocol (Email)</label>
                  <input type="email" required className="eclipse-input" value={creds.email} onChange={e => setCreds(p => ({ ...p, email: sanitizeEmail(e.target.value) }))} placeholder="operative@network.com" />
                </div>
                <div>
                  <label style={labelStyle}>Encryption Key (Password)</label>
                  <div style={{ position: 'relative' }}>
                    <input type={showPw ? 'text' : 'password'} required className="eclipse-input" value={creds.password} onChange={e => setCreds(p => ({ ...p, password: sanitizePassword(e.target.value) }))} placeholder="••••••••" />
                    <button type="button" onClick={() => setShowPw(!showPw)} style={{ position: 'absolute', right: 15, top: '40%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#4facfe', fontSize: 11 }}>
                      {showPw ? 'HIDE' : 'SHOW'}
                    </button>
                  </div>
                </div>
                <button type="submit" disabled={loading} className="btn-eclipse" style={{ marginTop: 15 }}>
                  {loading ? 'VERIFYING...' : '▶ AUTHENTICATE'}
                </button>
              </form>
              <div style={{ marginTop: 25, textAlign: 'center', fontSize: 12, borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: 20 }}>
                <Link to="/forgot-password" style={{ color: 'rgba(255,255,255,0.5)', letterSpacing: 1, textDecoration: 'none', display: 'block', marginBottom: 15, transition: '0.3s' }} onMouseOver={e => e.target.style.color = '#fff'} onMouseOut={e => e.target.style.color = 'rgba(255,255,255,0.5)'}>
                  FORGOT ENCRYPTION KEY?
                </Link>
                <span style={{ color: 'rgba(255,255,255,0.5)', letterSpacing: 1 }}>No access profile? </span>
                <Link to="/register" style={{ color: 'var(--accent-cyan)', fontWeight: 500, letterSpacing: 2 }}>REQUEST ACCESS</Link>
              </div>
            </>
          )}

          {/* Step 2 - Setup 2FA */}
          {step === 'setup_2fa' && qrData && (
            <>
              <h2 style={{ color: '#fff', fontSize: 16, marginBottom: 16, fontWeight: 300, letterSpacing: 3, textAlign: 'center' }}>
                BIOMETRIC / 2FA SETUP
              </h2>
              <p style={{ color: 'rgba(255,255,255,0.7)', fontSize: 12, marginBottom: 25, lineHeight: 1.6, textAlign: 'center' }}>
                High-security clearance <span style={{ color: 'var(--accent-cyan)' }}>required</span>. Scan the QR code to pair your authenticator device.
              </p>
              <div style={{ textAlign: 'center', marginBottom: 25 }}>
                <div style={{ display: 'inline-block', padding: 8, background: '#fff', borderRadius: 8, boxShadow: '0 0 30px rgba(0,242,254,0.3)' }}>
                  <img src={qrData.qr_code_url} alt="QR Code" style={{ width: 170, height: 170, display: 'block' }} />
                </div>
              </div>
              <div style={{ background: 'rgba(0,0,0,0.5)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, padding: '15px', marginBottom: 25 }}>
                <div style={labelStyle}>MANUAL OVERRIDE KEY</div>
                <div style={{ color: 'var(--accent-cyan)', fontSize: 13, wordBreak: 'break-all', letterSpacing: 4, fontFamily: 'monospace' }}>
                  {qrData.secret}
                </div>
              </div>
              <form onSubmit={handleSetup2FA}>
                <div>
                  <label style={labelStyle}>Encryption Token</label>
                  <input type="text" maxLength={6} required className="eclipse-input" value={totp} onChange={e => setTotp(sanitizeTotp(e.target.value))} style={{ fontSize: 26, letterSpacing: 14, textAlign: 'center', color: '#fff', padding: '16px' }} placeholder="000000" />
                </div>
                <button type="submit" disabled={loading || totp.length !== 6} className="btn-eclipse" style={{ background: totp.length === 6 ? 'var(--accent-cyan)' : 'var(--glass-bg)', color: totp.length === 6 ? '#000' : '#fff' }}>
                  {loading ? 'VERIFYING...' : '✓ ACTIVATE CLEARANCE'}
                </button>
              </form>
            </>
          )}

          {/* Step 3 - Verify 2FA */}
          {step === 'verify_2fa' && (
            <>
              <h2 style={{ color: '#fff', fontSize: 16, marginBottom: 16, fontWeight: 300, letterSpacing: 3, textAlign: 'center' }}>
                TWO-FACTOR REQUIRED
              </h2>
              <p style={{ color: 'rgba(255,255,255,0.7)', fontSize: 13, marginBottom: 35, lineHeight: 1.6, textAlign: 'center' }}>
                Provide the <span style={{ color: 'var(--accent-cyan)' }}>Shadow Spike</span> rolling 6-digit access token from your authenticator to proceed.
              </p>
              <form onSubmit={handleVerify2FA}>
                <div style={{ marginBottom: 35 }}>
                  <input type="text" maxLength={6} required autoFocus className="eclipse-input" value={totp} onChange={e => setTotp(sanitizeTotp(e.target.value))} style={{ fontSize: 34, letterSpacing: 18, textAlign: 'center', padding: '24px', color: '#fff' }} placeholder="000000" />
                  <div style={{ textAlign: 'center', color: '#4facfe', fontSize: 10, marginTop: 12, letterSpacing: 3, opacity: 0.6 }}>
                    TOKEN REFRESHES EVERY 30 SECONDS
                  </div>
                </div>
                <button type="submit" disabled={loading || totp.length !== 6} className="btn-eclipse" style={{ background: totp.length === 6 ? 'var(--accent-cyan)' : 'var(--glass-bg)', color: totp.length === 6 ? '#000' : '#fff' }}>
                  {loading ? 'VERIFYING...' : '▶ ENTER NETWORK'}
                </button>
                <button type="button" onClick={() => { setStep('credentials'); setTotp('') }} style={{ width: '100%', padding: '12px 0', marginTop: 20, background: 'transparent', border: 'none', color: 'rgba(255,255,255,0.4)', fontSize: 11, cursor: 'pointer', letterSpacing: 3, textTransform: 'uppercase', transition: '0.3s' }}>
                  ← ABORT AND RETURN
                </button>
              </form>
            </>
          )}
        </div>

        <p style={{ textAlign: 'center', color: 'rgba(255,255,255,0.2)', fontSize: 10, marginTop: 40, letterSpacing: 3 }}>
          SHADOW SPIKE v1.0.0 — CLASSIFIED ACCESS ONLY
        </p>
      </div>
    </div>
  )
}