import { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import toast from 'react-hot-toast'
import api from '../utils/api'
import { sanitizePassword } from '../utils/sanitize'

export default function ResetPasswordPage() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token')

  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [showPw, setShowPw] = useState(false)

  const handleReset = async (e) => {
    e.preventDefault()
    if (!token) {
      toast.error('Invalid or missing recovery token', { style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } })
      return
    }
    if (password !== confirmPassword) {
      toast.error('Encryption keys do not match', { style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } })
      return
    }

    setLoading(true)
    try {
      const { data } = await api.post('/auth/reset-password', {
        token,
        new_password: password
      })
      toast.success(data.message, { style: { background: '#010204', color: '#00f2fe', border: '1px solid #00f2fe' } })
      navigate('/login')
    } catch (err) {
      const detail = err.response?.data?.detail
      let errorMsg = 'Failed to process request'
      if (Array.isArray(detail)) {
        errorMsg = detail[0]?.msg || 'Validation error'
      } else if (typeof detail === 'string') {
        errorMsg = detail
      }
      toast.error(errorMsg, { style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } })
    } finally {
      setLoading(false)
    }
  }

  const labelStyle = {
    display: 'block', color: '#a1c4fd', fontSize: 11, letterSpacing: 2, marginBottom: 8, textTransform: 'uppercase'
  }

  if (!token) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', padding: 16 }}>
        <div style={{ width: '100%', maxWidth: 450, textAlign: 'center' }}>
          <h1 className="eclipse-title-small">ERROR</h1>
          <p style={{ color: '#ff3366', marginTop: 20 }}>NO RECOVERY TOKEN DETECTED</p>
          <button onClick={() => navigate('/login')} className="btn-eclipse" style={{ marginTop: 30 }}>RETURN TO GATEWAY</button>
        </div>
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', padding: 16 }}>
      <div style={{ width: '100%', maxWidth: 450 }}>
        {/* Logo */}
        <h1 className="eclipse-title-small">SHADOW SPIKE</h1>
        <p style={{ textAlign: 'center', color: '#4facfe', letterSpacing: 5, fontSize: 12, marginBottom: 40, marginTop: -25, opacity: 0.8 }}>
          FINALIZE OVERRIDE
        </p>

        {/* Card */}
        <div className="eclipse-card">
          <h2 style={{ color: '#fff', fontSize: 16, marginBottom: 30, fontWeight: 300, letterSpacing: 4, textAlign: 'center' }}>
            NEW ENCRYPTION KEY
          </h2>

          <form onSubmit={handleReset}>
            <div>
              <label style={labelStyle}>New Encryption Key (Password)</label>
              <div style={{ position: 'relative', marginBottom: 15 }}>
                <input 
                  type={showPw ? 'text' : 'password'} 
                  required 
                  className="eclipse-input" 
                  value={password} 
                  onChange={e => setPassword(sanitizePassword(e.target.value))} 
                  placeholder="••••••••" 
                />
                <button type="button" onClick={() => setShowPw(!showPw)} style={{ position: 'absolute', right: 15, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#4facfe', fontSize: 11 }}>
                  {showPw ? 'HIDE' : 'SHOW'}
                </button>
              </div>
            </div>

            <div>
              <label style={labelStyle}>Confirm New Key</label>
              <div style={{ position: 'relative' }}>
                <input 
                  type={showPw ? 'text' : 'password'} 
                  required 
                  className="eclipse-input" 
                  value={confirmPassword} 
                  onChange={e => setConfirmPassword(sanitizePassword(e.target.value))} 
                  placeholder="••••••••" 
                />
              </div>
            </div>

            <button type="submit" disabled={loading} className="btn-eclipse" style={{ marginTop: 25 }}>
              {loading ? 'STORING KEY...' : '▶ CONFIRM OVERRIDE'}
            </button>
          </form>
        </div>

        <p style={{ textAlign: 'center', color: 'rgba(255,255,255,0.2)', fontSize: 10, marginTop: 40, letterSpacing: 3 }}>
          SHADOW SPIKE v1.0.0 — CLASSIFIED ACCESS ONLY
        </p>
      </div>
    </div>
  )
}
