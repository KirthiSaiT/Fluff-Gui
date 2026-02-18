import React, { useEffect, useState, useRef } from 'react'
import { Terminal, Shield, AlertTriangle, CheckCircle, Clock } from 'lucide-react'
import { getScanStatus } from '../services/api'
import { cn } from '../lib/utils'

export function TerminalView({ scanId, onComplete }) {
    const [logs, setLogs] = useState([])
    const [status, setStatus] = useState('initializing')
    const [metadata, setMetadata] = useState(null)
    const bottomRef = useRef(null)
    const pollingRef = useRef(null)

    useEffect(() => {
        // Start polling
        pollingRef.current = setInterval(fetchLogs, 1000)
        return () => clearInterval(pollingRef.current)
    }, [scanId])

    useEffect(() => {
        if (bottomRef.current) {
            bottomRef.current.scrollIntoView({ behavior: 'smooth' })
        }
    }, [logs])

    const fetchLogs = async () => {
        try {
            const data = await getScanStatus(scanId)
            if (data) {
                setLogs(data.logs || [])
                setStatus(data.status)
                setMetadata({
                    domain: data.domain,
                    type: data.type,
                    startTime: data.start_time
                })

                if (data.status === 'completed' || data.status === 'error') {
                    clearInterval(pollingRef.current)
                }
            }
        } catch (error) {
            console.error("Polling error", error)
        }
    }

    const handleComplete = () => {
        onComplete(scanId)
    }

    return (
        <div className="flex flex-col h-full bg-black text-green-400 font-mono rounded-lg overflow-hidden border border-green-900 shadow-[0_0_20px_rgba(0,255,0,0.1)]">
            {/* Terminal Header */}
            <div className="flex items-center justify-between p-3 bg-gray-900 border-b border-green-900">
                <div className="flex items-center gap-2">
                    <Terminal className="w-5 h-5 text-green-500" />
                    <span className="text-sm font-bold tracking-wider">CTS_RECON_TERMINAL_v2.0</span>
                </div>
                <div className="flex items-center gap-4 text-xs">
                    <div className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        <span>{metadata?.startTime ? new Date(metadata.startTime).toLocaleTimeString() : '--:--:--'}</span>
                    </div>
                    <div className={cn(
                        "px-2 py-0.5 rounded-full uppercase font-bold",
                        status === 'running' ? "bg-green-900/50 text-green-400 animate-pulse" :
                            status === 'completed' ? "bg-blue-900/50 text-blue-400" :
                                "bg-red-900/50 text-red-400"
                    )}>
                        {status}
                    </div>
                </div>
            </div>

            {/* Logs Area */}
            <div className="flex-1 overflow-y-auto p-4 space-y-1 scrollbar-thin scrollbar-thumb-green-900 scrollbar-track-transparent">
                {logs.length === 0 && (
                    <div className="text-gray-500 italic">Initializing scan sequence... awaiting output...</div>
                )}

                {logs.map((log, i) => (
                    <div key={i} className="break-all whitespace-pre-wrap font-mono text-sm leading-tight hover:bg-green-900/10">
                        <span className="text-gray-600 mr-2">[{new Date().toLocaleTimeString()}]</span>
                        {log}
                    </div>
                ))}

                {status === 'completed' && (
                    <div className="mt-8 p-4 border border-green-800 bg-green-900/20 rounded flex items-center justify-center flex-col gap-2">
                        <CheckCircle className="w-8 h-8 text-green-500" />
                        <span className="text-lg font-bold">SCAN SEQUENCE COMPLETE</span>
                        <p className="text-sm text-green-300">Results generated and stored successfully.</p>
                        <button
                            onClick={handleComplete}
                            className="mt-4 px-6 py-2 bg-green-600 hover:bg-green-500 text-black font-bold rounded shadow-[0_0_10px_rgba(0,255,0,0.5)] transition-all"
                        >
                            ACCESS REPORT DATA
                        </button>
                    </div>
                )}

                {status === 'error' && (
                    <div className="mt-8 p-4 border border-red-800 bg-red-900/20 rounded flex items-center justify-center flex-col gap-2 animate-bounce">
                        <AlertTriangle className="w-8 h-8 text-red-500" />
                        <span className="text-lg font-bold text-red-500">SYSTEM FAILURE</span>
                        <p className="text-sm text-red-300">Critical process termination. Check system logs.</p>
                    </div>
                )}

                <div ref={bottomRef} />
            </div>
        </div>
    )
}
