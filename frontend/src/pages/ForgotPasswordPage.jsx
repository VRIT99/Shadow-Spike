import { useState } from 'react'
import { Link } from 'react-router-dom'
import toast from 'react-hot-toast'
import api from '../utils/api'
import { sanitizeEmail } from '../utils/sanitize'

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [success, setSuccess] = useState(false)

  const handleForgot = async (e) => {
    e.preventDefault()
    setLoading(true)
    try {
      const { data } = await api.post('/auth/forgot-password', { email })
      toast.success(data.message, { style: { background: '#010204', color: '#00f2fe', border: '1px solid #00f2fe' } })
      
      setSuccess(true)
    } catch (err) {
      const errorMsg = err.response?.data?.detail || 'An error occurred'
      toast.error(typeof errorMsg === 'string' ? errorMsg : 'Failed to process request', { style: { background: '#010204', color: '#ff3366', border: '1px solid #ff3366' } })
    } finally {
      setLoading(false)
    }
  }

  const labelStyle = {
    display: 'block', color: '#a1c4fd', fontSize: 11, letterSpacing: 2, marginBottom: 8, textTransform: 'uppercase'
  }

  return (
    <>
      <style>
        {`
          @keyframes slideUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
          }
          @keyframes glowPulse {
            0% { filter: drop-shadow(0 0 10px rgba(0,242,254,0.3)); }
            50% { filter: drop-shadow(0 0 25px rgba(0,242,254,0.8)); }
            100% { filter: drop-shadow(0 0 10px rgba(0,242,254,0.3)); }
          }
          .animate-card {
            animation: slideUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards;
          }
          .animate-success {
            animation: slideUp 0.4s ease-out forwards;
          }
          .recovery-icon {
            animation: glowPulse 2s infinite ease-in-out;
            margin-bottom: 20px;
          }
        `}
      </style>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', padding: 16 }}>
        <div style={{ width: '100%', maxWidth: 450 }}>
          {/* Logo */}
          <h1 className="eclipse-title-small">SHADOW SPIKE</h1>
          <p style={{ textAlign: 'center', color: '#4facfe', letterSpacing: 5, fontSize: 12, marginBottom: 40, marginTop: -25, opacity: 0.8 }}>
            SECURE RECOVERY PROTOCOL
          </p>

          {/* Card */}
          <div className="eclipse-card animate-card">
            
            <div style={{ textAlign: 'center' }}>
              <svg className="recovery-icon" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                <circle cx="12" cy="16" r="1"></circle>
              </svg>
            </div>

            <h2 style={{ color: '#fff', fontSize: 16, marginBottom: 30, fontWeight: 300, letterSpacing: 4, textAlign: 'center' }}>
              INITIATE OVERRIDE
            </h2>

            {success ? (
              <div className="animate-success" style={{ textAlign: 'center', padding: '20px 0' }}>
                <div style={{ width: '60px', height: '60px', borderRadius: '50%', background: 'rgba(0, 242, 254, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 20px', border: '1px solid rgba(0, 242, 254, 0.3)' }}>
                  <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="20 6 9 17 4 12"></polyline>
                  </svg>
                </div>
                <p style={{ color: '#e2e8f0', letterSpacing: 1, marginBottom: 30, lineHeight: '1.6' }}>
                  Encryption override protocol transmitted.<br/>
                  <span style={{color: 'var(--accent-cyan)', fontSize: 13}}>Check secure channels for the manual link.</span>
                </p>
                <Link to="/login" className="btn-eclipse" style={{ display: 'inline-block', textDecoration: 'none', textAlign: 'center' }}>
                  RETURN TO GATEWAY
                </Link>
              </div>
            ) : (
              <form onSubmit={handleForgot} style={{ animation: 'slideUp 0.6s ease-out' }}>
                <div>
                  <label style={labelStyle}>Operative Protocol (Email)</label>
                  <input 
                    type="email" 
                    required 
                    className="eclipse-input" 
                    value={email} 
                    onChange={e => setEmail(sanitizeEmail(e.target.value))} 
                    placeholder="operative@network.com" 
                    style={{ background: 'rgba(0,0,0,0.6)', padding: '16px' }}
                  />
                </div>
                <button type="submit" disabled={loading} className="btn-eclipse" style={{ marginTop: 15, position: 'relative', overflow: 'hidden' }}>
                  {loading ? (
                     <span style={{ animation: 'glowPulse 1s infinite' }}>TRANSMITTING...</span>
                  ) : '▶ SEND RECOVERY LINK'}
                </button>
              </form>
            )}

            <div style={{ marginTop: 25, textAlign: 'center', fontSize: 12, borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: 20 }}>
              <Link to="/login" style={{ color: 'rgba(255,255,255,0.4)', letterSpacing: 2, textDecoration: 'none', transition: '0.3s' }} onMouseOver={e => e.target.style.color = 'var(--accent-cyan)'} onMouseOut={e => e.target.style.color = 'rgba(255,255,255,0.4)'}>
                ← CANCEL AND RETURN
              </Link>
            </div>
          </div>

          <p style={{ textAlign: 'center', color: 'rgba(255,255,255,0.2)', fontSize: 10, marginTop: 40, letterSpacing: 3 }}>
            SHADOW SPIKE v1.0.0 — CLASSIFIED ACCESS ONLY
          </p>
        </div>
      </div>
    </>
  )
}
