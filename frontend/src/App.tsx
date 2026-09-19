import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import EmailAnalyzer from './pages/EmailAnalyzer'
import EmailDetail from './pages/EmailDetail'
import Investigations from './pages/Investigations'
import ThreatIntelligence from './pages/ThreatIntelligence'
import Evidence from './pages/Evidence'
import RealTimeStream from './pages/RealTimeStream'

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="stream" element={<RealTimeStream />} />
          <Route path="analyze" element={<EmailAnalyzer />} />
          <Route path="emails/:emailId" element={<EmailDetail />} />
          <Route path="investigations" element={<Investigations />} />
          <Route path="intelligence" element={<ThreatIntelligence />} />
          <Route path="evidence" element={<Evidence />} />
        </Route>
      </Routes>
    </Router>
  )
}

export default App
