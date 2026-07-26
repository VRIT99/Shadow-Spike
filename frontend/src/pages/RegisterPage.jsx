import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import toast from 'react-hot-toast'
import api from '../utils/api'
import { sanitizeEmail, sanitizeText, sanitizePassword } from '../utils/sanitize'

export default function RegisterPage() {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [showPw, setShowPw] = useState(false)
  const [form, setForm] = useState({
    email: '', username: '', full_name: '', password: '', confirm: ''
  })
  const [errors, setErrors] = useState({})

  const validate = () => {
    const e = {}
    if (!form.email) e.email = 'Required'
    if (!form.username) e.username = 'Required'
    if (form.username && !/^[a-zA-Z0-9_]{3,30}$/.test(form.username))
      e.username = '3-30 chars, letters/numbers/underscore only'
    if (!form.password) e.password = 'Required'
    if (form.password.length < 8) e.password = 'Min 8 characters'
    if (!/[A-Z]/.test(form.password)) e.password = 'Need one uppercase letter'
    if (!/\d/.test(form.password)) e.password = 'Need one number'
    if (!/[!@#$%^&*]/.test(form.password)) e.password = 'Need one special character (!@#$%^&*)'
    if (form.password !== form.confirm) e.confirm = 'Passwords do not match'
    setErrors(e)
    return Object.keys(e).length === 0
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!validate()) return
    setLoading(true)
    try {
      await api.post('/auth/register', {
        email: form.email,
        username: form.username,
        full_name: form.full_name,
        password: form.password
      })
      toast.success('Account created! Login and setup 2FA.')
      navigate('/login')
    } catch (err) {
      const detail = err.response?.data?.detail
      const msg = Array.isArray(detail) ? detail[0]?.msg : (detail || 'Registration failed')
      toast.error(String(msg))
    } finally {
      setLoading(false)
    }
  }

  const labelStyle = {
    display: 'block',
    color: '#a1c4fd',
    fontSize: 11,
    letterSpacing: 2,
    marginBottom: 8,
    textTransform: 'uppercase'
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', padding: 16 }}>
      <div style={{ width: '100%', maxWidth: 480 }}>

        {/* Logo */}
        <h1 className="eclipse-title-small">SHADOW SPIKE</h1>
        <p style={{ textAlign: 'center', color: '#4facfe', letterSpacing: 5, fontSize: 12, marginBottom: 40, marginTop: -25, opacity: 0.8 }}>
          CREATE NETWORK PROFILE
        </p>

        {/* Card */}
        <div className="eclipse-card">
          {/* Warning */}
          <div style={{ background: 'rgba(255,179,71,0.05)', border: '1px solid rgba(255,179,71,0.2)', borderRadius: 6, padding: '15px', marginBottom: 25 }}>
            <p style={{ color: '#ffb347', fontSize: 12, lineHeight: 1.5, margin: 0 }}>
              ⚠ After registration, you must set up Google Authenticator 2FA before accessing the platform.
            </p>
          </div>

          <form onSubmit={handleSubmit}>
            {/* Email */}
            <div>
              <label style={labelStyle}>Email</label>
              <input type="email" className="eclipse-input" style={errors.email ? {borderColor: 'var(--error-color)'} : {}} value={form.email} onChange={e => setForm(p => ({ ...p, email: sanitizeEmail(e.target.value) }))} placeholder="operative@network.com" />
              {errors.email && <p style={{ color: 'var(--error-color)', fontSize: 11, marginTop: -15, marginBottom: 15 }}>{errors.email}</p>}
            </div>

            {/* Username */}
            <div>
              <label style={labelStyle}>Username</label>
              <input type="text" className="eclipse-input" style={errors.username ? {borderColor: 'var(--error-color)'} : {}} value={form.username} onChange={e => setForm(p => ({ ...p, username: sanitizeText(e.target.value) }))} placeholder="ghost42" />
              {errors.username && <p style={{ color: 'var(--error-color)', fontSize: 11, marginTop: -15, marginBottom: 15 }}>{errors.username}</p>}
            </div>

            {/* Full Name */}
            <div>
              <label style={labelStyle}>Full Name (optional)</label>
              <input type="text" className="eclipse-input" value={form.full_name} onChange={e => setForm(p => ({ ...p, full_name: sanitizeText(e.target.value) }))} placeholder="John Doe" />
            </div>

            {/* Password */}
            <div>
              <label style={labelStyle}>Password</label>
              <div style={{ position: 'relative' }}>
                <input type={showPw ? 'text' : 'password'} className="eclipse-input" style={errors.password ? {borderColor: 'var(--error-color)'} : {}} value={form.password} onChange={e => setForm(p => ({ ...p, password: sanitizePassword(e.target.value) }))} placeholder="Min 8 chars, A-Z, 0-9, !@#" />
                <button type="button" onClick={() => setShowPw(!showPw)} style={{ position: 'absolute', right: 15, top: '35%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#4facfe', fontSize: 11 }}>
                  {showPw ? 'HIDE' : 'SHOW'}
                </button>
              </div>
              {errors.password && <p style={{ color: 'var(--error-color)', fontSize: 11, marginTop: -15, marginBottom: 15 }}>{errors.password}</p>}
            </div>

            {/* Confirm Password */}
            <div>
              <label style={labelStyle}>Confirm Password</label>
              <input type={showPw ? 'text' : 'password'} className="eclipse-input" style={errors.confirm ? {borderColor: 'var(--error-color)'} : {}} value={form.confirm} onChange={e => setForm(p => ({ ...p, confirm: sanitizePassword(e.target.value) }))} placeholder="Enter Password Again" />
              {errors.confirm && <p style={{ color: 'var(--error-color)', fontSize: 11, marginTop: -15, marginBottom: 15 }}>{errors.confirm}</p>}
            </div>

            <button type="submit" disabled={loading} className="btn-eclipse" style={{ marginTop: 15 }}>
              {loading ? 'CREATING...' : '▶ INITIALIZE PROFILE'}
            </button>
          </form>

          <div style={{ marginTop: 25, textAlign: 'center', fontSize: 12, borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: 20 }}>
            <span style={{ color: 'rgba(255,255,255,0.5)', letterSpacing: 1 }}>Already have access? </span>
            <Link to="/login" style={{ color: 'var(--accent-cyan)', fontWeight: 500, letterSpacing: 2 }}>AUTHENTICATE</Link>
          </div>
        </div>
        
        <p style={{ textAlign: 'center', color: 'rgba(255,255,255,0.2)', fontSize: 10, marginTop: 30, letterSpacing: 2 }}>
          SHADOW SPIKE SECURE COMMS
        </p>
      </div>
    </div>
  )
}