import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import LoginPage from './pages/LoginPage'
import RegisterPage from './pages/RegisterPage'
import DashboardPage from './pages/DashboardPage'
import AdminPage from './pages/AdminPage'
import LandingPage from './pages/LandingPage'
import PortScannerPage from './pages/PortScannerPage'
import SubdomainPage from './pages/SubdomainPage'
import ForgotPasswordPage from './pages/ForgotPasswordPage'
import ResetPasswordPage from './pages/ResetPasswordPage'
import ProxyPage from './pages/ProxyPage'
import RepeaterPage from './pages/RepeaterPage'
import DecoderPage from './pages/DecoderPage'
import XSSPage from './pages/XSSPage'
import SQLiPage from './pages/SQLiPage'

function ProtectedRoute({ children }) {
  const token = localStorage.getItem('access_token')
  if (!token) return <Navigate to="/login" replace />
  return children
}

function App() {
  return (
    <BrowserRouter>
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: '#0f1117',
            color: '#e2e8f0',
            border: '1px solid #1e2a3a',
            fontFamily: 'monospace',
            fontSize: 13
          }
        }}
      />
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route path="/reset-password" element={<ResetPasswordPage />} />
        <Route path="/dashboard" element={
          <ProtectedRoute>
            <DashboardPage />
          </ProtectedRoute>
        } />
        <Route path="/admin" element={
          <ProtectedRoute>
            <AdminPage />
          </ProtectedRoute>
        } />
        <Route path="/tools/port-scanner" element={
          <ProtectedRoute>
            <PortScannerPage />
          </ProtectedRoute>
        } />
        <Route path="/tools/subdomain" element={
          <ProtectedRoute>
            <SubdomainPage />
          </ProtectedRoute>
        } />
        <Route path="/tools/proxy" element={
          <ProtectedRoute>
            <ProxyPage />
          </ProtectedRoute>
        } />
        <Route path="/tools/repeater" element={
          <ProtectedRoute>
            <RepeaterPage />
          </ProtectedRoute>
        } />
        <Route path="/tools/decoder" element={
          <ProtectedRoute>
            <DecoderPage />
          </ProtectedRoute>
        } />
        <Route path="/tools/xss-scanner" element={
          <ProtectedRoute>
            <XSSPage />
          </ProtectedRoute>
        } />
        <Route path="/tools/sqli-scanner" element={
          <ProtectedRoute>
            <SQLiPage />
          </ProtectedRoute>
        } />
        <Route path="/" element={<LandingPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App