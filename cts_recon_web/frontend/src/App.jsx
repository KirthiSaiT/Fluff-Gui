import React, { useState, useEffect } from 'react'
import { Activity, Shield, Search, Database, FileText } from 'lucide-react'
import { TerminalView } from './components/TerminalView'
import { startScan, getResults, getResultDetail } from './services/api'
import { cn } from './lib/utils'

function App() {
    const [activeTab, setActiveTab] = useState('dashboard')
    const [domain, setDomain] = useState('')
    const [scanType, setScanType] = useState('deep')
    const [recentScans, setRecentScans] = useState([])
    const [selectedScan, setSelectedScan] = useState(null)
    const [loading, setLoading] = useState(false)
    const [scanStatus, setScanStatus] = useState(null)
    const [currentScanId, setCurrentScanId] = useState(null)

    useEffect(() => {
        loadRecentScans()
    }, [])

    const loadRecentScans = async () => {
        try {
            const files = await getResults()
            setRecentScans(files)
        } catch (error) {
            console.error("Failed to load scans", error)
        }
    }

    const handleScan = async (e) => {
        e.preventDefault()
        setLoading(true)
        setScanStatus('Starting scan...')
        try {
            const res = await startScan(domain, scanType)
            setCurrentScanId(res.scan_id)
            setActiveTab('terminal')
            setScanStatus(`Scan started! ID: ${res.scan_id}`)
        } catch (error) {
            console.error(error)
            setScanStatus('Error starting scan')
        } finally {
            setLoading(false)
        }
    }

    const viewResult = async (scanId) => {
        try {
            const data = await getResultDetail(scanId)
            setSelectedScan(data)
            setActiveTab('results')
        } catch (error) {
            console.error("Failed to load detail", error)
        }
    }

    return (
        <div className="min-h-screen bg-background text-foreground font-sans flex">
            {/* Sidebar */}
            <aside className="w-64 border-r border-border bg-card p-6 flex flex-col">
                <div className="flex items-center gap-2 mb-8">
                    <Shield className="w-8 h-8 text-primary" />
                    <h1 className="text-xl font-bold tracking-tight">CTS Recon</h1>
                </div>

                <nav className="space-y-2 flex-1">
                    <NavItem
                        icon={<Activity />}
                        label="Dashboard"
                        active={activeTab === 'dashboard'}
                        onClick={() => setActiveTab('dashboard')}
                    />
                    <NavItem
                        icon={<Search />}
                        label="New Scan"
                        active={activeTab === 'new-scan'}
                        onClick={() => setActiveTab('new-scan')}
                    />
                    <NavItem
                        icon={<FileText />}
                        label="Results"
                        active={activeTab === 'results'}
                        onClick={() => setActiveTab('results')}
                    />
                </nav>

                <div className="mt-auto pt-6 border-t border-border">
                    <p className="text-xs text-muted-foreground">v2.0.0 Refactor</p>
                </div>
            </aside>

            {/* Main Content */}
            <main className="flex-1 p-8 overflow-y-auto">

                {/* Dashboard View */}
                {activeTab === 'dashboard' && (
                    <div className="space-y-6">
                        <header>
                            <h2 className="text-3xl font-bold">Dashboard</h2>
                            <p className="text-muted-foreground">Overview of your reconnaissance activities.</p>
                        </header>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                            <StatCard title="Total Scans" value={recentScans.length} icon={<Database className="text-blue-500" />} />
                            <StatCard title="Active Scans" value={recentScans.filter(s => s.status === 'running').length} icon={<Activity className="text-green-500" />} />
                            <StatCard title="Completed" value={recentScans.filter(s => s.status === 'completed').length} icon={<Shield className="text-purple-500" />} />
                        </div>

                        <section>
                            <h3 className="text-xl font-semibold mb-4">Recent Scans</h3>
                            <div className="bg-card border border-border rounded-lg overflow-hidden">
                                <table className="w-full text-left text-sm">
                                    <thead className="bg-muted text-muted-foreground">
                                        <tr>
                                            <th className="p-4 font-medium">Target</th>
                                            <th className="p-4 font-medium">Type</th>
                                            <th className="p-4 font-medium">Status</th>
                                            <th className="p-4 font-medium">Date</th>
                                            <th className="p-4 font-medium">Action</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-border">
                                        {recentScans.map((scan) => (
                                            <tr key={scan.scan_id} className="hover:bg-muted/50 transition-colors">
                                                <td className="p-4 font-medium">{scan.domain}</td>
                                                <td className="p-4">
                                                    <span className={cn(
                                                        "px-2 py-1 rounded-full text-xs font-bold uppercase",
                                                        scan.type === 'deep' ? "bg-purple-900/50 text-purple-400" : "bg-blue-900/50 text-blue-400"
                                                    )}>
                                                        {scan.type}
                                                    </span>
                                                </td>
                                                <td className="p-4">
                                                    <span className={cn(
                                                        "px-2 py-1 rounded-full text-xs font-bold uppercase",
                                                        scan.status === 'completed' ? "bg-green-900/50 text-green-400" :
                                                            scan.status === 'running' ? "bg-yellow-900/50 text-yellow-400 animate-pulse" :
                                                                "bg-gray-800 text-gray-400"
                                                    )}>
                                                        {scan.status}
                                                    </span>
                                                </td>
                                                <td className="p-4 text-muted-foreground">
                                                    {new Date(scan.created_at).toLocaleString()}
                                                </td>
                                                <td className="p-4">
                                                    <button
                                                        onClick={() => viewResult(scan.scan_id)}
                                                        className="text-primary hover:underline font-medium"
                                                    >
                                                        View Report
                                                    </button>
                                                </td>
                                            </tr>
                                        ))}
                                        {recentScans.length === 0 && (
                                            <tr>
                                                <td colSpan="5" className="p-8 text-center text-muted-foreground">No scans found.</td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </section>
                    </div>
                )}

                {/* New Scan View */}
                {activeTab === 'new-scan' && (
                    <div className="max-w-2xl mx-auto space-y-8">
                        <header>
                            <h2 className="text-3xl font-bold">New Scan</h2>
                            <p className="text-muted-foreground">Launch a new reconnaissance mission.</p>
                        </header>

                        <form onSubmit={handleScan} className="bg-card border border-border p-8 rounded-lg space-y-6">
                            <div className="space-y-2">
                                <label htmlFor="domain" className="block text-sm font-medium">Target Domain / IP</label>
                                <input
                                    type="text"
                                    id="domain"
                                    value={domain}
                                    onChange={(e) => setDomain(e.target.value)}
                                    placeholder="example.com"
                                    className="w-full bg-background border border-border rounded-md px-4 py-2 focus:outline-none focus:ring-2 focus:ring-primary"
                                    required
                                />
                            </div>

                            <div className="space-y-2">
                                <label className="block text-sm font-medium">Scan Type</label>
                                <div className="grid grid-cols-2 gap-4">
                                    <EventTypeOption
                                        type="deep"
                                        label="Deep Scan"
                                        desc="Comprehensive analysis (Slower)"
                                        selected={scanType === 'deep'}
                                        onClick={() => setScanType('deep')}
                                    />
                                    <EventTypeOption
                                        type="lite"
                                        label="Lite Scan"
                                        desc="Quick overview (Faster)"
                                        selected={scanType === 'lite'}
                                        onClick={() => setScanType('lite')}
                                    />
                                </div>
                            </div>

                            <button
                                type="submit"
                                disabled={loading}
                                className="w-full bg-primary text-primary-foreground font-bold py-3 rounded-md hover:opacity-90 transition-opacity disabled:opacity-50"
                            >
                                {loading ? 'Initiating...' : 'Launch Scan'}
                            </button>
                        </form>

                        {scanStatus && (
                            <div className="p-4 rounded-md bg-muted text-muted-foreground border border-border text-center">
                                {scanStatus}
                            </div>
                        )}
                    </div>
                )}

                {/* Terminal View */}
                {activeTab === 'terminal' && currentScanId && (
                    <TerminalView
                        scanId={currentScanId}
                        onComplete={(scanId) => {
                            loadRecentScans()
                            viewResult(scanId || currentScanId)
                        }}
                    />
                )}

                {/* Results View */}
                {activeTab === 'results' && (
                    <div className="space-y-6">
                        <header className="flex justify-between items-center">
                            <div>
                                <h2 className="text-3xl font-bold">Scan Results</h2>
                                <p className="text-muted-foreground">{selectedScan ? selectedScan.target : 'Select a scan to view details'}</p>
                            </div>
                            {selectedScan && <span className="text-sm bg-muted px-3 py-1 rounded-full">{selectedScan.scan_type}</span>}
                        </header>

                        {selectedScan ? (
                            <div className="bg-card border border-border rounded-lg p-6">
                                <pre className="text-xs font-mono whitespace-pre-wrap overflow-auto max-h-[600px] text-muted-foreground">
                                    {JSON.stringify(selectedScan, null, 2)}
                                </pre>
                            </div>
                        ) : (
                            <div className="text-center py-20 text-muted-foreground bg-card border border-border rounded-lg">
                                <Search className="w-12 h-12 mx-auto mb-4 opacity-20" />
                                <p>Select a scan from the Dashboard to view results here.</p>
                            </div>
                        )}
                    </div>
                )}

            </main>
        </div>
    )
}

// UI Components
function NavItem({ icon, label, active, onClick }) {
    return (
        <button
            onClick={onClick}
            className={cn(
                "w-full flex items-center gap-3 px-4 py-3 rounded-md transition-colors text-sm font-medium",
                active ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-muted hover:text-foreground"
            )}
        >
            {icon}
            {label}
        </button>
    )
}

function StatCard({ title, value, icon }) {
    return (
        <div className="bg-card border border-border p-6 rounded-lg flex items-center gap-4">
            <div className="p-3 bg-muted rounded-full">
                {icon}
            </div>
            <div>
                <p className="text-sm text-muted-foreground">{title}</p>
                <p className="text-2xl font-bold">{value}</p>
            </div>
        </div>
    )
}

function EventTypeOption({ type, label, desc, selected, onClick }) {
    return (
        <div
            onClick={onClick}
            className={cn(
                "cursor-pointer border rounded-lg p-4 transition-all",
                selected ? "border-primary bg-primary/5" : "border-border hover:border-primary/50"
            )}
        >
            <p className="font-bold">{label}</p>
            <p className="text-xs text-muted-foreground">{desc}</p>
        </div>
    )
}

export default App
