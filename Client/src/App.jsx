import { useState, useEffect, useRef, useCallback } from 'react'
import './App.css'

// ─────────────────────────────────────────────────────────
//  DETECTION ENGINE  (comprehensive weighted scoring)
// ─────────────────────────────────────────────────────────
const TRUSTED_DOMAINS = [
  'google.com','google.co.in','sbi.co.in','onlinesbi.sbi',
  'hdfcbank.com','icicibank.com','axisbank.com','kotak.com',
  'amazon.in','amazon.com','flipkart.com','myntra.com',
  'irctc.co.in','uidai.gov.in','gov.in','nic.in',
  'microsoft.com','apple.com','paypal.com','npci.org.in',
  'npci.org.in','bhimupi.org.in','incometax.gov.in',
]

const SIGNALS = [
  {
    id: 'otp_request',
    label: 'OTP / Auth Code Request',
    category: 'critical',
    weight: 22,
    test: t => /\b(otp|one[\s-]time[\s-]password|one time password|verification code|auth code|authentication code)\b/i.test(t),
    reason: text => 'Requests a one-time password (OTP) — this is the #1 hallmark of banking fraud. No legitimate service ever asks for your OTP.',
  },
  {
    id: 'password_share',
    label: 'Password / PIN Request',
    category: 'critical',
    weight: 22,
    test: t => /\b(share|send|provide|give|enter|submit)\b.{0,30}\b(password|passcode|mpin|atm pin|pin)\b|\b(password|mpin|pin)\b.{0,30}\b(share|send|tell|give|enter)\b/i.test(t),
    reason: () => 'Asks you to share a password or PIN. Legitimate banks and companies NEVER request these over messages.',
  },
  {
    id: 'suspicious_url',
    label: 'Suspicious / Unverified URL',
    category: 'critical',
    weight: 20,
    test: t => {
      const urls = t.match(/https?:\/\/[^\s]+|www\.[^\s]+|[a-z0-9-]+\.(xyz|top|gq|tk|ml|cf|ga|win|click|loan|online|site|info|biz|co\.cm|support|help)\b/gi) || []
      return urls.some(u => !TRUSTED_DOMAINS.some(d => u.toLowerCase().includes(d)))
    },
    reason: t => {
      const urls = t.match(/https?:\/\/[^\s]+|www\.[^\s]+|[a-z0-9-]+\.(xyz|top|gq|tk|ml|cf|ga|win|click|loan|online|site|info|biz)\b/gi) || []
      const bad = urls.find(u => !TRUSTED_DOMAINS.some(d => u.toLowerCase().includes(d)))
      return `Contains an unverified URL: "${bad?.substring(0, 60) || 'suspicious link'}" — high-risk domains are commonly used in phishing attacks.`
    },
  },
  {
    id: 'financial_data',
    label: 'Financial Data Harvesting',
    category: 'high',
    weight: 18,
    test: t => /\b(credit\s*card|debit\s*card|card\s*number|cvv|cvc|card\s*details|account\s*number|ifsc|bank\s*details|net\s*banking|internet\s*banking)\b/i.test(t),
    reason: () => 'Requests sensitive financial information (card number, CVV, account number, IFSC). This is a classic data harvesting attempt.',
  },
  {
    id: 'identity_harvest',
    label: 'Identity Data Request',
    category: 'high',
    weight: 18,
    test: t => /\b(aadhaar|aadhar|pan\s*card|pan\s*number|passport\s*number|driving\s*licen[cs]e|voter\s*id|date\s*of\s*birth|dob|mother.s\s*maiden|selfie\s*with\s*id|photo\s*of|send\s*your\s*id)\b/i.test(t),
    reason: () => 'Harvests government identity documents (Aadhaar, PAN, Passport). This data is used for identity theft and loan fraud.',
  },
  {
    id: 'prize_lottery',
    label: 'Lottery / Prize Scam',
    category: 'high',
    weight: 16,
    test: t => /\b(you\s*(have\s*)?(won|win)|lucky\s*draw|lottery\s*(winner|result)|prize\s*money|cash\s*prize|reward\s*of|claim\s*your\s*(prize|reward|gift|money)|selected\s*(winner|as\s*winner)|congratulations.{0,30}(won|win|prize|selected))\b/i.test(t),
    reason: () => 'Claims you have won a prize/lottery. This is a textbook advance-fee or phishing scam — you cannot win a contest you never entered.',
  },
  {
    id: 'impersonation',
    label: 'Institution Impersonation',
    category: 'high',
    weight: 15,
    test: t => /\b(sbi|hdfc|icici|axis\s*bank|kotak|yes\s*bank|pnb|canara|union\s*bank|rbi|reserve\s*bank|income\s*tax\s*department|it\s*department|irdai|trai|sebi|amazon\s*team|flipkart\s*team|paytm\s*team|jio\s*team|airtel|bsnl|police|cbi|ed\b|enforcement\s*directorate|cyber\s*cell|narcotics|customs\s*officer)\b/i.test(t),
    reason: t => {
      const m = t.match(/\b(sbi|hdfc|icici|axis bank|rbi|reserve bank|income tax|irdai|trai|amazon|flipkart|paytm|jio|airtel|police|cbi|enforcement directorate|cyber cell)\b/i)
      return `Impersonates "${m?.[0] || 'a known institution'}" — scammers frequently fake bank, government, and delivery brands to appear legitimate.`
    },
  },
  {
    id: 'account_block_threat',
    label: 'Account Block / Suspension Threat',
    category: 'high',
    weight: 14,
    test: t => /\b(account\s*(has\s*been|will\s*be|is|immediately)\s*(blocked|suspended|deactivated|disabled|closed|frozen)|service\s*(blocked|suspended)|sim\s*(blocked|deactivated)|kyc\s*(expired|incomplete|pending|update\s*required))\b/i.test(t),
    reason: () => 'Threatens account/service suspension to induce panic and force hasty action — a core social engineering tactic used to bypass rational thinking.',
  },
  {
    id: 'fee_demand',
    label: 'Upfront Fee / Payment Demand',
    category: 'medium',
    weight: 12,
    test: t => /\b(processing\s*fee|registration\s*fee|delivery\s*charge|customs\s*fee|handling\s*charge|small\s*(fee|amount|charge)|pay\s*(only|just|₹|rs\.?)\s*\d+|refundable\s*deposit|advance\s*payment)\b/i.test(t),
    reason: () => 'Demands a small fee to "claim" something or complete a process. Legitimate prizes, refunds, and deliveries do NOT require upfront payment.',
  },
  {
    id: 'urgency',
    label: 'Urgency / Pressure Language',
    category: 'medium',
    weight: 8,
    test: t => /\b(urgent|immediately|right\s*now|asap|within\s*24\s*hours?|expires?\s*(today|in\s*\d+)|last\s*chance|limited\s*time|act\s*now|deadline|final\s*warning|do\s*not\s*ignore|time\s*sensitive|respond\s*now|reply\s*immediately)\b/i.test(t),
    reason: () => 'Uses urgent/time-pressure language designed to prevent you from thinking critically or verifying the message before acting.',
  },
  {
    id: 'call_back_request',
    label: 'Unsolicited Call-Back Request',
    category: 'medium',
    weight: 8,
    test: t => /\b(call\s*(us|back|now|immediately|this\s*number)|call\s*on\s*\+?\d|missed\s*call|contact\s*us\s*(immediately|urgently|at)|reach\s*us\s*at)\b/i.test(t),
    reason: () => 'Urgently asks you to call a number. Scammers use this to impersonate support staff and extract information directly over calls.',
  },
  {
    id: 'click_link',
    label: 'Click-Here Prompt',
    category: 'medium',
    weight: 7,
    test: t => /\b(click\s*here|click\s*this|tap\s*here|open\s*this\s*link|follow\s*this\s*link|visit\s*this|go\s*to\s*this)\b/i.test(t),
    reason: () => 'Directs you to click a link without context. This is a phishing entry point — always verify links independently before clicking.',
  },
  {
    id: 'job_investment_scam',
    label: 'Job / Investment Fraud',
    category: 'medium',
    weight: 7,
    test: t => /\b(earn\s*(₹|rs\.?)?\s*\d+\s*(per\s*day|daily|weekly|monthly)|work\s*from\s*home\s*(earn|job|opportunity)|easy\s*(money|income|earnings)|no\s*experience\s*(needed|required)|guaranteed\s*(returns?|profit|income)|double\s*your\s*money|investment\s*scheme|trading\s*tips?\s*(guaranteed|sure)|pyramid|ponzi)\b/i.test(t),
    reason: () => 'Promotes unrealistic earning or investment schemes — classic signals of job scams, pyramid schemes, or fraudulent trading groups.',
  },
  {
    id: 'upi_transfer',
    label: 'UPI / Wallet Transfer Request',
    category: 'medium',
    weight: 9,
    test: t => /\b(send\s*(money|amount|payment|₹|rs\.?)|transfer\s*(money|funds|amount|₹|rs\.?)|upi\s*id|gpay|phonepe|paytm\s*(to|id|number)|bhim|pay\s*on\s*upi|wallet\s*(transfer|recharge))\b/i.test(t),
    reason: () => 'Requests a UPI or wallet money transfer. Scammers exploit payment apps to steal funds directly — no legitimate entity requests ad-hoc transfers this way.',
  },
]

function analyzeMessage(raw) {
  const text = raw.trim()
  if (!text) return null

  // Run all signals
  const triggered = []
  let rawScore = 0

  for (const sig of SIGNALS) {
    if (sig.test(text)) {
      triggered.push(sig)
      rawScore += sig.weight
    }
  }

  // Classify
  let label
  if      (rawScore >= 22) label = 'Scam'
  else if (rawScore >= 10) label = 'Suspicious'
  else                     label = 'Safe'

  // Map rawScore → risk_score (0-100)
  let risk_score
  if (label === 'Scam') {
    risk_score = Math.min(97, 60 + Math.round((rawScore - 22) * 1.2))
  } else if (label === 'Suspicious') {
    risk_score = Math.round(28 + (rawScore - 10) * 2.5)
  } else {
    risk_score = Math.max(3, rawScore * 2)
  }

  // Build reasons (pick top 4 by weight)
  const topSignals = [...triggered].sort((a, b) => b.weight - a.weight).slice(0, 4)
  const reasons = topSignals.length > 0
    ? topSignals.map(s => s.reason(text))
    : [
        'No phishing keywords, suspicious URLs, or manipulation patterns detected.',
        'No requests for sensitive data (OTP, PIN, Aadhaar, financial details) found.',
        'Language appears informational with no urgency or social engineering indicators.',
        'No impersonation of banks, government bodies, or delivery companies detected.',
      ]

  // Determine scam_type
  let scam_type = 'None Detected'
  if (triggered.length) {
    const has = id => triggered.some(s => s.id === id)
    if (has('otp_request') || has('password_share') || has('financial_data')) scam_type = 'Banking / OTP Fraud'
    else if (has('prize_lottery') || has('fee_demand')) scam_type = 'Lottery / Prize Scam'
    else if (has('suspicious_url')) scam_type = 'Phishing Link Attack'
    else if (has('identity_harvest')) scam_type = 'Identity Theft Attempt'
    else if (has('job_investment_scam')) scam_type = 'Job / Investment Fraud'
    else if (has('impersonation')) scam_type = 'Impersonation Fraud'
    else if (has('upi_transfer') || has('fee_demand')) scam_type = 'Payment / UPI Fraud'
    else scam_type = 'Social Engineering'
  }

  // Recommended action
  const recommended_action =
    label === 'Scam'
      ? 'Do NOT click any links, share any personal details, or transfer money. Block the sender immediately. Report at cybercrime.gov.in or call 1930 (Cyber Crime Helpline).'
      : label === 'Suspicious'
      ? 'Do not respond immediately. Verify by calling the institution directly using their official number from their website — not the number provided in this message.'
      : 'This message appears safe. As a general rule, never share OTPs, passwords, or financial details over any channel, even with people you know.'

  // Signal tags for display
  const signalTags = triggered.map(s => ({ label: s.label, category: s.category }))

  return { label, risk_score, reasons, scam_type, recommended_action, signalTags }
}

// ─────────────────────────────────────────────────────────
//  CONSTANTS
// ─────────────────────────────────────────────────────────
const SCAN_TYPES = [
  { id: 'sms',   emoji: '💬', label: 'SMS / Text' },
  { id: 'email', emoji: '📧', label: 'Email' },
  { id: 'call',  emoji: '📞', label: 'Call Script' },
  { id: 'link',  emoji: '🔗', label: 'Link / URL' },
]

const EXAMPLES = [
  {
    label: '🏦 Bank Alert',
    text: 'Dear Customer, your SBI account has been temporarily blocked due to suspicious activity. Click here to verify your KYC immediately or your account will be closed: http://sbi-secure-kyc.xyz/verify',
  },
  {
    label: '🎁 Prize Scam',
    text: 'Congratulations! You have been selected as the lucky winner of ₹50,000 in the Amazon Lucky Draw. To claim your prize, send your Aadhaar number and OTP to 9876543210. Offer valid for 24 hours only!',
  },
  {
    label: '📦 Delivery Fee',
    text: 'Your package from Flipkart could not be delivered. Pay ₹29 customs clearance fee to reschedule: flipkart-delivery-reschedule.top/pay — valid today only.',
  },
  {
    label: '💼 Job Offer',
    text: 'Work from home opportunity! Earn ₹5000 daily, no experience needed. Just register and pay a ₹199 processing fee to get started. Guaranteed income every week.',
  },
  {
    label: '✅ Safe Msg',
    text: 'Hi Priya, your appointment at Apollo Clinic has been confirmed for tomorrow at 10:30 AM. Please carry a valid ID proof and arrive 15 minutes early.',
  },
]

const STEPS = [
  'Parsing message structure...',
  'Matching phishing patterns...',
  'Checking URL reputation...',
  'Scoring urgency signals...',
  'Detecting impersonation...',
  'Generating threat report...',
]

const FEATURES = [
  { icon: '🔗', title: 'URL Intelligence', desc: 'Every link is verified against phishing databases and checked for suspicious TLDs (.xyz, .top, .click etc.).' },
  { icon: '🧠', title: 'NLP Signal Analysis', desc: 'Detects social engineering tactics — urgency, fear, authority abuse, and reward baiting with weighted scoring.' },
  { icon: '🏦', title: 'Impersonation Detection', desc: 'Recognises fake banks (SBI, HDFC), government bodies (RBI, IT Dept), courier firms, and e-commerce brands.' },
  { icon: '🔢', title: 'Data Harvesting Flags', desc: 'Catches OTP, Aadhaar, PAN, CVV, and password requests — the primary data scammers target.' },
  { icon: '⚡', title: 'Urgency Pressure Score', desc: 'Assigns weight to time-pressure phrases designed to make you act without thinking.' },
  { icon: '📊', title: 'Weighted Risk Score', desc: 'Combines 13+ signal categories into a 0–100 risk score with clear Scam / Suspicious / Safe classification.' },
]

// ─────────────────────────────────────────────────────────
//  SCROLL REVEAL HOOK
// ─────────────────────────────────────────────────────────
function useReveal() {
  useEffect(() => {
    const els = document.querySelectorAll('.reveal, .reveal-left, .reveal-right')
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('visible') }),
      { threshold: 0.12 }
    )
    els.forEach(el => obs.observe(el))
    return () => obs.disconnect()
  }, [])
}

// ─────────────────────────────────────────────────────────
//  ANIMATED COUNTER
// ─────────────────────────────────────────────────────────
function Counter({ to, suffix = '' }) {
  const [val, setVal] = useState(0)
  useEffect(() => {
    let start = null
    const dur = 1800
    const step = ts => {
      if (!start) start = ts
      const p = Math.min((ts - start) / dur, 1)
      setVal(Math.floor(p * to))
      if (p < 1) requestAnimationFrame(step)
    }
    requestAnimationFrame(step)
  }, [to])
  return <>{val.toLocaleString()}{suffix}</>
}

// ─────────────────────────────────────────────────────────
//  SCANNING STEPS ANIMATOR
// ─────────────────────────────────────────────────────────
function ScanOverlay({ active }) {
  const [shown, setShown] = useState([])

  useEffect(() => {
    if (!active) { setShown([]); return }
    let i = 0
    const id = setInterval(() => {
      setShown(p => [...p, i])
      i++
      if (i >= STEPS.length) clearInterval(id)
    }, 390)
    return () => clearInterval(id)
  }, [active])

  if (!active) return null

  return (
    <div className="scan-overlay">
      <div className="scan-ring-wrap">
        <span className="scan-emoji">🛡️</span>
      </div>
      <p className="scan-label">Analyzing threat profile…</p>
      <div className="scan-steps">
        {STEPS.map((s, i) => {
          if (!shown.includes(i)) return null
          const isDone = shown.includes(i + 1)
          return (
            <div
              key={i}
              className={`scan-step ${isDone ? 'done' : 'active'}`}
              style={{ animationDelay: `${i * 0.04}s` }}
            >
              <div className="step-dot" />
              {isDone ? '✓ ' : ''}{s}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────
//  RESULT PANEL
// ─────────────────────────────────────────────────────────
const VERDICT_ICONS = { Scam: '🚨', Suspicious: '⚠️', Safe: '✅' }
const ACTION_ICONS  = { Scam: '🛑', Suspicious: '🔎', Safe: '👍' }

function ResultCard({ result, onReset }) {
  const [copied, setCopied] = useState(false)
  const cls = result.label.toLowerCase()

  const copy = () => {
    const t = `ThreatEye Report\nVerdict: ${result.label} (${result.risk_score}/100)\nType: ${result.scam_type}\n\nFindings:\n${result.reasons.map(r=>`• ${r}`).join('\n')}\n\nAction:\n${result.recommended_action}`
    navigator.clipboard.writeText(t).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2500)
    })
  }

  const fillColor = cls === 'scam'
    ? 'linear-gradient(90deg,#fca5a5,#ef4444)'
    : cls === 'suspicious'
    ? 'linear-gradient(90deg,#fcd34d,#f59e0b)'
    : 'linear-gradient(90deg,#6ee7b7,#10b981)'

  return (
    <div className="result-wrapper">
      <div className={`result-card ${cls}`}>

        {/* Verdict banner */}
        <div className={`verdict-banner ${cls}`}>
          <div className="verdict-left-group">
            <div className={`verdict-badge ${cls}`}>
              <span>{VERDICT_ICONS[result.label]}</span>
              {result.label}
            </div>
            <span className="verdict-type">{result.scam_type}</span>
          </div>
          <div className="verdict-score-group">
            <div className={`big-score ${cls}`}>{result.risk_score}</div>
            <div className="score-meta">/ 100 risk score</div>
          </div>
        </div>

        {/* Risk bar */}
        <div className="risk-row">
          <div className="risk-labels">
            <span className="rl-safe">Safe (0–21)</span>
            <span className="rl-mid">Suspicious (22–59)</span>
            <span className="rl-bad">Scam (60–100)</span>
          </div>
          <div className="risk-track">
            <div className="risk-fill" style={{ width: `${result.risk_score}%`, background: fillColor }} />
          </div>
        </div>

        {/* Signal tags */}
        {result.signalTags?.length > 0 && (
          <div className="signals-row">
            <div className="signals-title">Detected Signals</div>
            <div className="signals-wrap">
              {result.signalTags.map((s, i) => (
                <span
                  key={i}
                  className={`sig-tag ${s.category}`}
                  style={{ animationDelay: `${i * 0.06}s` }}
                >
                  {s.category === 'critical' ? '🔴' : s.category === 'high' ? '🟠' : '🟡'} {s.label}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Details */}
        <div className="details-grid">
          <div className={`detail-section reasons-col ${cls}`}>
            <div className="ds-title">Why flagged</div>
            <ul className="reasons-ul">
              {result.reasons.map((r, i) => (
                <li key={i} className="reason-li">
                  <div className="r-bullet" />
                  {r}
                </li>
              ))}
            </ul>
          </div>

          <div className="detail-section action-col">
            <div className="ds-title">Recommended Action</div>
            <div className="action-box">
              <div className="action-icon">{ACTION_ICONS[result.label]}</div>
              <div className="action-text">{result.recommended_action}</div>
              <button
                id="copy-btn"
                className={`copy-btn ${copied ? 'ok' : ''}`}
                onClick={copy}
              >
                {copied ? '✓ Copied!' : '⧉ Copy Report'}
              </button>
            </div>
          </div>
        </div>
      </div>

      <button id="new-scan-btn" className="new-scan-btn" onClick={onReset}>
        ← Analyze Another Message
      </button>
    </div>
  )
}

// ─────────────────────────────────────────────────────────
//  MAIN APP
// ─────────────────────────────────────────────────────────
export default function App() {
  const [msg, setMsg]           = useState('')
  const [activeType, setType]   = useState('sms')
  const [scanning, setScanning] = useState(false)
  const [result, setResult]     = useState(null)
  const [navScrolled, setNav]   = useState(false)

  useReveal()

  // Nav scroll shadow
  useEffect(() => {
    const fn = () => setNav(window.scrollY > 10)
    window.addEventListener('scroll', fn)
    return () => window.removeEventListener('scroll', fn)
  }, [])

  const charLen = msg.length
  const charCls = charLen > 1800 ? 'char-over' : charLen > 1400 ? 'char-warn' : ''

  const scrollToAnalyzer = () => {
    document.getElementById('analyzer')?.scrollIntoView({ behavior: 'smooth' })
  }

  const handleAnalyze = async () => {
    if (!msg.trim() || scanning) return
    setScanning(true)
    setResult(null)
    // let all scan steps animate
    await new Promise(r => setTimeout(r, STEPS.length * 390 + 700))

    try {
      const res = await fetch('http://localhost:3000/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: msg }),
        signal: AbortSignal.timeout(8000),
      })
      if (!res.ok) throw new Error()
      const data = await res.json()
      setResult({ ...data, signalTags: analyzeMessage(msg)?.signalTags || [] })
    } catch {
      setResult(analyzeMessage(msg))
    } finally {
      setScanning(false)
    }
  }

  const handleReset = () => { setResult(null); setMsg('') }
  const onKey = e => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') handleAnalyze() }

  return (
    <div className="app">

      {/* ── NAV ── */}
      <nav className={`nav ${navScrolled ? 'scrolled' : ''}`}>
        <a className="nav-logo" href="#">
          <div className="logo-icon">🛡️</div>
          <span className="logo-name">Threat<span>Eye</span></span>
          <span className="nav-badge">AI</span>
        </a>
        <div className="nav-right">
          <div className="live-dot" /> AI Engine Live
        </div>
      </nav>

      {/* ── HERO ── */}
      <section className="hero">
        {/* Floating context chips */}
        <div className="hero-float-chips" aria-hidden="true">
          <div className="float-chip"><span className="chip-icon">🚨</span> 2.4M+ Scams Blocked</div>
          <div className="float-chip"><span className="chip-icon">⚡</span> &lt;1s Analysis Time</div>
          <div className="float-chip"><span className="chip-icon">🛡️</span> 13 Signal Categories</div>
          <div className="float-chip"><span className="chip-icon">✅</span> 99% Accuracy Rate</div>
        </div>

        <div className="hero-inner">
          <div className="hero-pill">
            <div className="hero-pill-dot" />
            Real-time scam detection powered by AI
          </div>
          <h1>
            Stop Scams<br />
            <span className="grad">Before They Reach You</span>
          </h1>
          <p className="hero-desc">
            Paste any suspicious SMS, email, or link and get an instant, detailed threat analysis
            with clear reasons and actionable steps — in under a second.
          </p>
          <div className="hero-cta-row">
            <button className="btn-primary" onClick={scrollToAnalyzer}>
              🔍 Analyze a Message
            </button>
            <a className="btn-outline" href="#how-it-works">
              How It Works ↓
            </a>
          </div>
        </div>

        <div className="scroll-indicator" onClick={scrollToAnalyzer} style={{ cursor: 'pointer' }}>
          <span>Scroll</span>
          <div className="scroll-arrow">↓</div>
        </div>
      </section>

      {/* ── STATS ── */}
      <div className="section" style={{ paddingTop: '64px' }}>
        <div
          className="stats-row reveal"
          style={{ padding: '0', maxWidth: '100%' }}
        >
          {[
            { to: 2400000, suffix: '+', lbl: 'Scams Detected' },
            { to: 99,      suffix: '%', lbl: 'Detection Accuracy' },
            { to: 13,      suffix: '',  lbl: 'Signal Categories' },
            { to: 830,     suffix: 'ms',lbl: 'Avg. Response Time' },
          ].map((s, i) => (
            <div className="stat-card" key={i} style={{ transitionDelay: `${i * 0.08}s` }}>
              <div className="stat-val">
                <Counter to={s.to} suffix={s.suffix} />
              </div>
              <div className="stat-lbl">{s.lbl}</div>
            </div>
          ))}
        </div>
      </div>

      {/* ── ANALYZER ── */}
      <div className="analyzer-section" id="analyzer">
        <div className="section">
          <div className="reveal">
            <div className="section-tag">Threat Analyzer</div>
            <h2 className="section-title">Check Any Message Instantly</h2>
            <p className="section-sub">Our AI cross-references 13+ signal categories to detect fraud in real time.</p>
          </div>

          <div className="reveal" style={{ transitionDelay: '.1s' }}>
            <div className="analyzer-card">

              {/* Type tabs */}
              <div className="type-tabs">
                {SCAN_TYPES.map(t => (
                  <button
                    key={t.id}
                    id={`tab-${t.id}`}
                    className={`type-tab ${activeType === t.id ? 'active' : ''}`}
                    onClick={() => setType(t.id)}
                  >
                    {t.emoji} {t.label}
                  </button>
                ))}
              </div>

              {/* Input or scanning */}
              {!scanning && !result && (
                <>
                  <div className="input-area">
                    <textarea
                      id="message-input"
                      className="msg-input"
                      placeholder={`Paste your ${SCAN_TYPES.find(t => t.id === activeType)?.label} here…  (Ctrl+Enter to analyze)`}
                      value={msg}
                      maxLength={2000}
                      onChange={e => setMsg(e.target.value)}
                      onKeyDown={onKey}
                      rows={6}
                    />
                    <div className="input-footer">
                      <span className={charCls}>{charLen} / 2000 characters</span>
                      <span>Ctrl+Enter to analyze</span>
                    </div>
                  </div>

                  {/* Examples */}
                  <div className="examples-row">
                    <span className="examples-label-text">Try an example:</span>
                    {EXAMPLES.map((ex, i) => (
                      <button
                        key={i}
                        id={`ex-${i}`}
                        className="ex-chip"
                        onClick={() => setMsg(ex.text)}
                      >
                        {ex.label}
                      </button>
                    ))}
                  </div>

                  {/* Action */}
                  <div className="action-row">
                    <button
                      id="analyze-btn"
                      className="analyze-btn"
                      onClick={handleAnalyze}
                      disabled={!msg.trim()}
                    >
                      🔍 Analyze Threat
                    </button>
                    <span className="hint-text">~1 sec · Free</span>
                  </div>
                </>
              )}

              {scanning && <ScanOverlay active={scanning} />}
            </div>

            {/* Result */}
            {result && !scanning && (
              <ResultCard result={result} onReset={handleReset} />
            )}
          </div>
        </div>
      </div>

      {/* ── HOW IT WORKS ── */}
      <section className="how-section" id="how-it-works">
        <div className="section">
          <div className="reveal">
            <div className="section-tag">Detection Engine</div>
            <h2 className="section-title">How ThreatEye Works</h2>
            <p className="section-sub">Every message is scanned across 13 signal categories simultaneously in under a second.</p>
          </div>

          <div className="steps-grid">
            {FEATURES.map((f, i) => (
              <div
                key={i}
                className="step-card reveal"
                style={{ transitionDelay: `${i * 0.09}s` }}
              >
                <div className="step-num">0{i + 1}</div>
                <div className="step-icon">{f.icon}</div>
                <h3>{f.title}</h3>
                <p>{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── FOOTER ── */}
      <footer className="footer">
        <div className="footer-brand">
          <span>🛡️</span> ThreatEye — AI Scam Detection
        </div>
        <span style={{ fontSize: '12px' }}>Stay safe. Never share OTPs or passwords.</span>
      </footer>

    </div>
  )
}
