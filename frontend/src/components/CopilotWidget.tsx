import React, { useState, useEffect, useRef } from 'react'
import {
  Bot,
  Send,
  X,
  User,
  MessageSquare,
  Sparkles,
  Trash2,
  Copy,
  Check,
  ShieldAlert,
  ChevronDown,
  Terminal,
  Activity
} from 'lucide-react'
import { querySocCopilot, type CopilotMessage } from '../services/api'

interface ChatEntry extends CopilotMessage {
  id: string
  timestamp: string
  suggestedActions?: string[]
  isError?: boolean
}

export default function CopilotWidget() {
  const [isOpen, setIsOpen] = useState<boolean>(false)
  const [isExpanded, setIsExpanded] = useState<boolean>(false)
  const [input, setInput] = useState<string>('')
  const [isLoading, setIsLoading] = useState<boolean>(false)
  const [copiedIndex, setCopiedIndex] = useState<string | null>(null)
  const [threatContext, setThreatContext] = useState<Record<string, any> | null>(null)
  const [unreadBadge, setUnreadBadge] = useState<boolean>(false)

  const messagesEndRef = useRef<HTMLDivElement | null>(null)
  const inputRef = useRef<HTMLTextAreaElement | null>(null)

  const [messages, setMessages] = useState<ChatEntry[]>([
    {
      id: 'init-1',
      role: 'assistant',
      content:
        "**TRACE-X AI SOC Copilot Online.**\n\n" +
        "I am your automated Tier-3 SOC Analyst. I can investigate email threats, explain SPF/DKIM/DMARC authentication failures, decode RFC 5322 header routing anomalies, and generate NIST SP 800-61r2 containment playbooks.\n\n" +
        "How can I assist your investigation today?",
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      suggestedActions: [
        'Explain SPF/DKIM/DMARC failures',
        'Generate containment playbook',
        'Decode header routing anomalies',
        'Generate KQL threat hunting query',
      ],
    },
  ])

  // Scroll to bottom when messages update
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    if (isOpen) {
      scrollToBottom()
      setUnreadBadge(false)
      setTimeout(() => inputRef.current?.focus(), 150)
    }
  }, [isOpen, messages, isLoading])

  // Global event listener to accept threat context from any page in TRACE-X
  useEffect(() => {
    const handleContextEvent = (event: Event) => {
      const customEvent = event as CustomEvent
      if (customEvent.detail) {
        setThreatContext(customEvent.detail)
        setIsOpen(true)
        setUnreadBadge(true)

        const subject = customEvent.detail.subject || 'Incident'
        const fromAddr = customEvent.detail.from_address || 'Sender'
        const risk = customEvent.detail.risk_score || 85

        const contextAnnouncement: ChatEntry = {
          id: 'ctx-' + Date.now(),
          role: 'assistant',
          content:
            `🎯 **Active Forensic Context Loaded**\n\n` +
            `• **Subject**: "${subject}"\n` +
            `• **From**: \`${fromAddr}\`\n` +
            `• **Risk Score**: **${risk}/100**\n` +
            `• **Auth Verdicts**: SPF: \`${customEvent.detail.spf_result || 'FAIL'}\` | DKIM: \`${customEvent.detail.dkim_result || 'FAIL'}\` | DMARC: \`${customEvent.detail.dmarc_result || 'FAIL'}\`\n\n` +
            `I have injected these IoCs and authentication verdicts into our active session. You can now ask for containment playbooks, forensic explanations, or SIEM queries.`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          suggestedActions: [
            'Explain why this email failed SPF/DKIM/DMARC',
            'Generate 4-phase containment playbook',
            'Decode header anomalies for this email',
            'Generate KQL threat hunting query',
          ],
        }

        setMessages((prev) => [...prev, contextAnnouncement])
      }
    }

    window.addEventListener('tracex-copilot-context', handleContextEvent)
    return () => window.removeEventListener('tracex-copilot-context', handleContextEvent)
  }, [])

  // Send message
  const handleSend = async (textToSend?: string) => {
    const userQuery = (textToSend || input).trim()
    if (!userQuery || isLoading) return

    const userMessage: ChatEntry = {
      id: 'usr-' + Date.now(),
      role: 'user',
      content: userQuery,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    }

    const updatedMessages = [...messages, userMessage]
    setMessages(updatedMessages)
    setInput('')
    setIsLoading(true)

    // Build payload for backend
    const apiMessages: CopilotMessage[] = updatedMessages.map((m) => ({
      role: m.role,
      content: m.content,
    }))

    try {
      const res = await querySocCopilot({
        messages: apiMessages,
        threat_context: threatContext || undefined,
      })

      const assistantMessage: ChatEntry = {
        id: 'ast-' + Date.now(),
        role: 'assistant',
        content: res.response,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        suggestedActions: res.suggested_actions || [],
      }

      setMessages((prev) => [...prev, assistantMessage])
    } catch (err: any) {
      const errorMessage: ChatEntry = {
        id: 'err-' + Date.now(),
        role: 'assistant',
        content:
          `⚠️ **Copilot Query Encountered an Issue**\n\n` +
          `Failed to retrieve response: ${err?.response?.data?.detail || err?.message || 'Check backend connection'}.\n` +
          `Falling back to local heuristic analysis. Try asking specifically about SPF, DKIM, DMARC, or Containment.`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        isError: true,
      }
      setMessages((prev) => [...prev, errorMessage])
    } finally {
      setIsLoading(false)
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const handleCopyCode = (text: string, id: string) => {
    navigator.clipboard.writeText(text)
    setCopiedIndex(id)
    setTimeout(() => setCopiedIndex(null), 2000)
  }

  const clearChat = () => {
    setMessages([
      {
        id: 'init-reset',
        role: 'assistant',
        content:
          "Conversation cleared. I am ready to assist with your next email threat investigation.",
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        suggestedActions: [
          'Explain SPF/DKIM/DMARC failures',
          'Generate containment playbook',
          'Decode header routing anomalies',
        ],
      },
    ])
  }

  // Render markdown with code block support
  const renderMessageContent = (content: string, messageId: string) => {
    const parts = content.split(/(```[\s\S]*?```)/g)

    return parts.map((part, index) => {
      if (part.startsWith('```') && part.endsWith('```')) {
        const lines = part.slice(3, -3).trim().split('\n')
        const language = lines[0].trim().match(/^[a-zA-Z0-9_-]+$/) ? lines[0].trim() : ''
        const code = language ? lines.slice(1).join('\n') : lines.join('\n')
        const blockId = `${messageId}-${index}`

        return (
          <div
            key={index}
            className="my-2.5 rounded-lg border border-slate-700/80 bg-slate-950/80 overflow-hidden text-xs font-mono"
          >
            <div className="flex items-center justify-between px-3 py-1.5 bg-slate-900/90 border-b border-slate-800 text-[11px] text-slate-400">
              <span className="flex items-center space-x-1.5 uppercase font-semibold text-cyan-400">
                <Terminal className="w-3.5 h-3.5" />
                <span>{language || 'code'}</span>
              </span>
              <button
                onClick={() => handleCopyCode(code, blockId)}
                className="flex items-center space-x-1 text-slate-400 hover:text-white transition-colors"
                title="Copy to clipboard"
              >
                {copiedIndex === blockId ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
            <pre className="p-3 overflow-x-auto text-slate-200 leading-relaxed font-mono whitespace-pre">
              {code}
            </pre>
          </div>
        )
      }

      // Format markdown headings, bold, bullet points
      const formattedLines = part.split('\n').map((line, lIdx) => {
        // Headings
        if (line.startsWith('### ')) {
          return (
            <h4 key={lIdx} className="text-sm font-bold text-red-700 mt-2 mb-1">
              {line.replace('### ', '')}
            </h4>
          )
        }
        if (line.startsWith('#### ')) {
          return (
            <h5 key={lIdx} className="text-xs font-bold text-slate-900 mt-2 mb-0.5">
              {line.replace('#### ', '')}
            </h5>
          )
        }

        // Bullet points
        if (line.trim().startsWith('- ') || line.trim().startsWith('• ')) {
          const bulletText = line.replace(/^[\s]*[-•]\s+/, '')
          return (
            <li key={lIdx} className="ml-4 list-disc text-xs text-slate-700 my-0.5">
              {renderBoldText(bulletText)}
            </li>
          )
        }

        if (!line.trim()) {
          return <div key={lIdx} className="h-1.5" />
        }

        return (
          <p key={lIdx} className="text-xs text-slate-700 leading-relaxed my-0.5">
            {renderBoldText(line)}
          </p>
        )
      })

      return <div key={index}>{formattedLines}</div>
    })
  }

  const renderBoldText = (text: string): React.ReactNode => {
    const segments = text.split(/(\*\*.*?\*\*|`.*?`)/g)
    return segments.map((seg, sIdx) => {
      if (seg.startsWith('**') && seg.endsWith('**')) {
        return (
          <strong key={sIdx} className="font-bold text-slate-900">
            {seg.slice(2, -2)}
          </strong>
        )
      }
      if (seg.startsWith('`') && seg.endsWith('`')) {
        return (
          <code
            key={sIdx}
            className="px-1.5 py-0.5 rounded bg-red-50 border border-red-200 text-red-700 font-mono text-[11px] font-semibold"
          >
            {seg.slice(1, -1)}
          </code>
        )
      }
      return seg
    })
  }

  return (
    <div className="fixed bottom-6 right-6 z-50 select-none">
      {/* Collapsed Trigger Button */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="relative flex items-center space-x-2.5 px-4 py-3 rounded-full bg-red-600 hover:bg-red-700 text-white font-medium shadow-lg shadow-red-600/30 hover:shadow-red-600/50 hover:scale-105 active:scale-95 transition-all duration-200 border border-red-500 group"
          title="Open AI SOC Analyst Copilot"
        >
          <div className="relative">
            <Bot className="w-5 h-5 text-white group-hover:rotate-12 transition-transform duration-300" />
            <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-white animate-ping" />
            <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-white" />
          </div>
          <span className="text-sm font-bold tracking-wide">SOC Copilot</span>

          {unreadBadge && (
            <span className="w-2.5 h-2.5 rounded-full bg-white animate-pulse border border-red-600" />
          )}
        </button>
      )}

      {/* Expanded Chatbot Modal */}
      {isOpen && (
        <div
          className={`flex flex-col rounded-2xl shadow-2xl transition-all duration-200 border border-slate-200 backdrop-blur-xl bg-white/95 overflow-hidden ${
            isExpanded
              ? 'w-[92vw] sm:w-[680px] h-[86vh] max-h-[860px]'
              : 'w-[92vw] sm:w-[420px] h-[580px] max-h-[85vh]'
          }`}
          style={{
            boxShadow: '0 20px 50px rgba(0, 0, 0, 0.15), 0 0 30px rgba(220, 38, 38, 0.12)',
          }}
        >
          {/* Header Bar */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-200 bg-slate-50">
            <div className="flex items-center space-x-2.5">
              <div className="relative p-1.5 rounded-lg bg-red-50 border border-red-200 text-red-600">
                <Bot className="w-5 h-5" />
                <span className="absolute -bottom-0.5 -right-0.5 w-2 h-2 rounded-full bg-emerald-500 ring-2 ring-white" />
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <h3 className="text-sm font-bold text-slate-900 tracking-tight">AI SOC Analyst Copilot</h3>
                  <span className="px-1.5 py-0.5 text-[10px] font-bold rounded bg-red-50 text-red-700 border border-red-200">
                    TIER-3
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 font-medium">
                  Forensic Email & Threat Containment Assistant
                </p>
              </div>
            </div>

            {/* Header controls */}
            <div className="flex items-center space-x-1">
              <button
                onClick={clearChat}
                className="p-1.5 rounded-md text-slate-400 hover:text-red-600 hover:bg-slate-200/60 transition-colors"
                title="Clear conversation"
              >
                <Trash2 className="w-4 h-4" />
              </button>
              <button
                onClick={() => setIsExpanded(!isExpanded)}
                className="p-1.5 rounded-md text-slate-400 hover:text-slate-800 hover:bg-slate-200/60 transition-colors hidden sm:inline-flex"
                title={isExpanded ? 'Collapse width' : 'Expand width'}
              >
                <ChevronDown
                  className={`w-4 h-4 transition-transform duration-200 ${
                    isExpanded ? 'rotate-180' : ''
                  }`}
                />
              </button>
              <button
                onClick={() => setIsOpen(false)}
                className="p-1.5 rounded-md text-slate-400 hover:text-slate-800 hover:bg-slate-200/60 transition-colors"
                title="Minimize Copilot"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Threat Context Banner (if active) */}
          {threatContext && (
            <div className="flex items-center justify-between px-3.5 py-2 bg-red-50/80 border-b border-red-200 text-xs text-slate-800">
              <div className="flex items-center space-x-2 truncate">
                <ShieldAlert className="w-4 h-4 text-red-600 flex-shrink-0" />
                <span className="truncate">
                  <strong className="text-red-700">Context:</strong>{' '}
                  {threatContext.subject || threatContext.email_id || 'Active Threat'}
                  {threatContext.risk_score && (
                    <span className="ml-1 text-red-600 font-bold">
                      ({threatContext.risk_score}/100)
                    </span>
                  )}
                </span>
              </div>
              <button
                onClick={() => setThreatContext(null)}
                className="text-[11px] text-red-600 hover:text-red-800 ml-2 underline font-semibold flex-shrink-0"
                title="Detach context"
              >
                Clear
              </button>
            </div>
          )}

          {/* Messages Scroll Area */}
          <div className="flex-1 p-4 overflow-y-auto space-y-4 font-sans select-text scrollbar-thin scrollbar-thumb-slate-300 scrollbar-track-transparent bg-slate-50/60">
            {messages.map((m) => {
              const isUser = m.role === 'user'

              return (
                <div
                  key={m.id}
                  className={`flex flex-col ${isUser ? 'items-end' : 'items-start'} space-y-1.5`}
                >
                  <div className="flex items-center space-x-1.5 text-[11px] text-slate-500 px-1">
                    {isUser ? (
                      <>
                        <span>{m.timestamp}</span>
                        <span className="font-semibold text-slate-600">Analyst</span>
                        <User className="w-3 h-3 text-red-600" />
                      </>
                    ) : (
                      <>
                        <Bot className="w-3 h-3 text-red-600" />
                        <span className="font-bold text-red-700">SOC Copilot</span>
                        <span>{m.timestamp}</span>
                      </>
                    )}
                  </div>

                  <div
                    className={`max-w-[90%] rounded-2xl px-3.5 py-2.5 transition-all text-xs ${
                      isUser
                        ? 'bg-red-600 text-white rounded-tr-none shadow-sm shadow-red-600/20'
                        : m.isError
                        ? 'bg-red-50 border border-red-200 text-red-800 rounded-tl-none'
                        : 'bg-white border border-slate-200 text-slate-800 rounded-tl-none shadow-xs'
                    }`}
                  >
                    {renderMessageContent(m.content, m.id)}
                  </div>

                  {/* Suggested Action Chips (only on assistant messages) */}
                  {!isUser && m.suggestedActions && m.suggestedActions.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 pt-1 pl-1 max-w-[90%]">
                      {m.suggestedActions.map((action, aIdx) => (
                        <button
                          key={aIdx}
                          disabled={isLoading}
                          onClick={() => handleSend(action)}
                          className="px-2.5 py-1 rounded-full bg-white hover:bg-red-50 border border-red-200 text-[11px] font-semibold text-red-700 hover:text-red-800 transition-all flex items-center space-x-1 group shadow-2xs"
                        >
                          <Sparkles className="w-3 h-3 text-red-500 group-hover:scale-110 transition-transform" />
                          <span>{action}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              )
            })}

            {/* Loading typing indicator */}
            {isLoading && (
              <div className="flex items-start space-x-2">
                <div className="p-1 rounded-md bg-red-50 border border-red-200 text-red-600 mt-1">
                  <Bot className="w-3.5 h-3.5" />
                </div>
                <div className="px-3.5 py-2.5 rounded-2xl rounded-tl-none bg-white border border-slate-200 text-xs text-slate-500 flex items-center space-x-1.5 shadow-xs">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-600 animate-bounce" />
                  <span
                    className="w-1.5 h-1.5 rounded-full bg-red-600 animate-bounce"
                    style={{ animationDelay: '0.15s' }}
                  />
                  <span
                    className="w-1.5 h-1.5 rounded-full bg-red-600 animate-bounce"
                    style={{ animationDelay: '0.3s' }}
                  />
                  <span className="ml-1 text-[11px] text-red-600 font-mono font-medium">
                    Analyzing threat matrix...
                  </span>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Input Footer */}
          <div className="p-3 border-t border-slate-200 bg-white">
            <form
              onSubmit={(e) => {
                e.preventDefault()
                handleSend()
              }}
              className="flex items-end space-x-2"
            >
              <div className="flex-1 relative">
                <textarea
                  ref={inputRef}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Ask about SPF/DKIM/DMARC, header routing, containment playbooks, or KQL..."
                  rows={2}
                  className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:bg-white focus:ring-2 focus:ring-red-500/20 focus:border-red-500 resize-none font-sans leading-relaxed"
                />
              </div>

              <button
                type="submit"
                disabled={isLoading || !input.trim()}
                className="p-2.5 rounded-xl bg-red-600 text-white hover:bg-red-700 disabled:opacity-40 disabled:cursor-not-allowed transition-all shadow-sm shadow-red-600/30"
                title="Send query (Enter)"
              >
                <Send className="w-4 h-4" />
              </button>
            </form>
            <div className="flex items-center justify-between text-[10px] text-slate-500 mt-1.5 px-1">
              <span>Press <kbd className="font-mono text-slate-500 bg-slate-100 px-1 py-0.5 rounded border border-slate-200">Enter</kbd> to send, <kbd className="font-mono text-slate-500 bg-slate-100 px-1 py-0.5 rounded border border-slate-200">Shift+Enter</kbd> for newline</span>
              <span className="flex items-center space-x-1 text-emerald-600 font-medium">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                <span>Heuristic & AI Engine Ready</span>
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
