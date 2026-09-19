import { Link, Outlet, useLocation } from 'react-router-dom'
import { LayoutDashboard, Search, FileText, Activity, Database, AlertTriangle, Radio } from 'lucide-react'

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Live Threat Stream', href: '/stream', icon: Radio, live: true },
  { name: 'Analyze Email', href: '/analyze', icon: Search },
  { name: 'Investigations', href: '/investigations', icon: FileText },
  { name: 'Threat Intel', href: '/intelligence', icon: Activity },
  { name: 'Evidence', href: '/evidence', icon: Database },
]

export default function Layout() {
  const location = useLocation()

  return (
    <div className="min-h-screen flex flex-col bg-background text-slate-900">
      {/* Header */}
      <header className="bg-surface border-b border-surface-border sticky top-0 z-30 shadow-xs">
        <div className="max-w-[1920px] mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <Link to="/dashboard" className="flex items-center space-x-3 group">
              <div className="relative flex items-center justify-center p-1 rounded-lg bg-white shadow-xs border border-slate-200 group-hover:border-red-300 transition-colors">
                <img src="/logo.png" alt="TRACE-X Logo" className="h-9 w-auto object-contain transition-transform group-hover:scale-105" />
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <h1 className="text-xl font-black tracking-tight text-slate-900">
                    TRACE<span className="text-red-600">-X</span>
                  </h1>
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-red-50 text-red-700 font-bold border border-red-200 uppercase tracking-wide">
                    PRO
                  </span>
                </div>
                <p className="text-xs text-slate-500 font-medium">Email Threat Detection & Forensic Intelligence</p>
              </div>
            </Link>

            <div className="flex items-center space-x-3">
              <Link
                to="/stream"
                className="inline-flex items-center px-3 py-1.5 rounded-lg bg-red-50 text-red-700 border border-red-200 text-xs font-semibold hover:bg-red-100 transition-colors shadow-xs"
              >
                <span className="w-2 h-2 bg-red-600 rounded-full mr-2 animate-ping"></span>
                Real-Time Stream Active
              </Link>
              <span className="inline-flex items-center px-3 py-1.5 rounded-lg bg-emerald-50 text-emerald-700 border border-emerald-200 text-xs font-semibold">
                <span className="w-2 h-2 bg-emerald-500 rounded-full mr-2 animate-pulse"></span>
                System Operational
              </span>
            </div>
          </div>
        </div>
      </header>

      <div className="flex-1 flex">
        {/* Sidebar */}
        <aside className="w-64 bg-surface border-r border-surface-border flex flex-col justify-between">
          <nav className="p-4 space-y-1.5">
            {navigation.map((item) => {
              const isActive = location.pathname === item.href
              const Icon = item.icon

              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-semibold transition-all ${
                    isActive
                      ? 'bg-red-600 text-white shadow-sm shadow-red-600/25'
                      : 'text-slate-600 hover:bg-red-50/60 hover:text-red-600'
                  }`}
                >
                  <div className="flex items-center space-x-3">
                    <Icon className={`w-5 h-5 ${isActive ? 'text-white' : 'text-slate-400 group-hover:text-red-600'}`} />
                    <span>{item.name}</span>
                  </div>
                  {item.live && (
                    <span className={`w-2 h-2 rounded-full ${isActive ? 'bg-white' : 'bg-red-600'} animate-ping`} title="Real-Time Feed" />
                  )}
                </Link>
              )
            })}
          </nav>

          {/* Demo Mode Warning */}
          <div className="p-4 m-4 bg-amber-50/70 border border-amber-200/80 rounded-xl">
            <div className="flex items-start space-x-2.5">
              <AlertTriangle className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-xs font-bold text-amber-900 mb-0.5">Demo Mode Active</p>
                <p className="text-[11px] text-amber-700 leading-relaxed">
                  Intelligence data may be simulated. Configure API keys for live enterprise ingestion.
                </p>
              </div>
            </div>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 overflow-auto bg-background">
          <div className="max-w-[1920px] mx-auto p-6 md:p-8">
            <Outlet />
          </div>
        </main>
      </div>

      {/* Footer */}
      <footer className="bg-surface border-t border-surface-border py-4">
        <div className="max-w-[1920px] mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center space-x-2">
            <img src="/logo.png" alt="TRACE-X" className="h-4 w-auto object-contain opacity-70" />
            <p className="text-xs text-slate-500 font-medium">
              TRACE-X Forensic Intelligence Platform © 2026 | Enterprise Email Security
            </p>
          </div>
          <span className="text-[11px] text-slate-400">
            Powered by Deep Forensic Engine & AI Reasoning
          </span>
        </div>
      </footer>
    </div>
  )
}
