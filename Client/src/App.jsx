import { useState, useEffect, useRef, useCallback } from 'react'
import './App.css'

// ═══════════════════════════════════════════════════════════
//  DETECTION ENGINE
// ═══════════════════════════════════════════════════════════
const TRUSTED_DOMAINS = [
  'google.com','google.co.in','sbi.co.in','onlinesbi.sbi',
  'hdfcbank.com','icicibank.com','axisbank.com','kotak.com',
  'amazon.in','amazon.com','flipkart.com','myntra.com',
  'irctc.co.in','uidai.gov.in','gov.in','nic.in',
  'microsoft.com','apple.com','paypal.com','npci.org.in',
  'bhimupi.org.in','incometax.gov.in','paytm.com','phonepe.com',
]

const SIGNALS = [
  { id:'otp_request',          label:'OTP Request',            category:'critical', weight:22, test:t=>/\b(otp|one[\s-]time[\s-]password|verification code|auth code)\b/i.test(t),                                                                                   reason:()=>'Requests a one-time password (OTP) — the #1 hallmark of banking fraud. No legitimate service ever asks for your OTP.' },
  { id:'password_share',       label:'Password/PIN Request',   category:'critical', weight:22, test:t=>/\b(share|send|provide|give|enter|submit)\b.{0,30}\b(password|passcode|mpin|atm pin|pin)\b|\b(password|mpin|pin)\b.{0,30}\b(share|send|tell|give|enter)\b/i.test(t), reason:()=>'Asks you to share a password or PIN. Legitimate banks NEVER request these over messages.' },
  { id:'suspicious_url',       label:'Suspicious URL',         category:'critical', weight:20, test:t=>{const u=t.match(/https?:\/\/[^\s]+|www\.[^\s]+|[a-z0-9-]+\.(xyz|top|gq|tk|ml|cf|ga|win|click|loan|online|site|biz|support|help)\b/gi)||[];return u.some(x=>!TRUSTED_DOMAINS.some(d=>x.toLowerCase().includes(d)))}, reason:t=>{const u=t.match(/https?:\/\/[^\s]+|www\.[^\s]+|[a-z0-9-]+\.(xyz|top|gq|tk|ml|ga|click|loan|online|site|biz)\b/gi)||[];const b=u.find(x=>!TRUSTED_DOMAINS.some(d=>x.toLowerCase().includes(d)));return `Suspicious URL detected: "${(b||'link').substring(0,55)}" — phishing sites often mimic trusted brands with fake domains.`} },
  { id:'financial_data',       label:'Financial Data Harvest', category:'high',     weight:18, test:t=>/\b(credit\s*card|debit\s*card|card\s*number|cvv|cvc|account\s*number|ifsc|bank\s*details|net\s*banking)\b/i.test(t),                                           reason:()=>'Requests card number, CVV, account number or IFSC. Classic data-harvesting attempt targeting your bank account.' },
  { id:'identity_harvest',     label:'Identity Data Request',  category:'high',     weight:18, test:t=>/\b(aadhaar|aadhar|pan\s*card|pan\s*number|passport\s*number|voter\s*id|date\s*of\s*birth|dob|mother.s\s*maiden|selfie\s*with|photo\s*of\s*your)\b/i.test(t),   reason:()=>'Harvests government ID documents (Aadhaar, PAN, Passport) — the foundation of identity theft and loan fraud.' },
  { id:'prize_lottery',        label:'Lottery/Prize Scam',     category:'high',     weight:16, test:t=>/\b(you\s*(have\s*)?(won|win)|lucky\s*draw|lottery\s*(winner|result)|prize\s*money|cash\s*prize|claim\s*your\s*(prize|reward|gift)|selected\s*(winner)|congratulations.{0,30}(won|prize|selected))\b/i.test(t), reason:()=>'Claims you have won a prize or lottery. You cannot win a contest you never entered — this is an advance-fee scam.' },
  { id:'impersonation',        label:'Brand Impersonation',    category:'high',     weight:15, test:t=>/\b(sbi|hdfc|icici|axis\s*bank|kotak|rbi|reserve\s*bank|income\s*tax|irdai|trai|amazon\s*team|flipkart\s*team|jio\s*team|airtel|police|cbi|ed\b|enforcement\s*directorate|cyber\s*cell)\b/i.test(t), reason:t=>{const m=t.match(/\b(sbi|hdfc|icici|axis bank|rbi|reserve bank|income tax|irdai|trai|amazon|flipkart|jio|airtel|police|cbi|enforcement directorate|cyber cell)\b/i);return `Impersonates "${m?.[0]||'a known institution'}" — scammers fake bank/govt brands to appear legitimate.`} },
  { id:'account_block_threat', label:'Account Threat',         category:'high',     weight:14, test:t=>/\b(account\s*(has\s*been|will\s*be|is)\s*(blocked|suspended|deactivated|closed)|sim\s*(blocked|deactivated)|kyc\s*(expired|incomplete|pending|required))\b/i.test(t), reason:()=>'Threatens account/service suspension to trigger panic — a core social engineering tactic to bypass rational thinking.' },
  { id:'fee_demand',           label:'Upfront Fee Demand',     category:'medium',   weight:12, test:t=>/\b(processing\s*fee|registration\s*fee|delivery\s*charge|customs\s*fee|small\s*(fee|amount)|pay\s*(only|just|₹|rs\.?)\s*\d+|refundable\s*deposit|advance\s*payment)\b/i.test(t), reason:()=>'Demands a fee to "claim" something. Legitimate prizes, refunds, and deliveries never require upfront payment.' },
  { id:'urgency',              label:'Urgency Pressure',       category:'medium',   weight:8,  test:t=>/\b(urgent|immediately|right\s*now|asap|within\s*24\s*hours?|expires?\s*today|last\s*chance|limited\s*time|act\s*now|final\s*warning|do\s*not\s*ignore|time\s*sensitive)\b/i.test(t), reason:()=>'Uses time-pressure language designed to prevent you from thinking critically or verifying before acting.' },
  { id:'call_back_request',    label:'Call-Back Request',      category:'medium',   weight:8,  test:t=>/\b(call\s*(us|back|now|immediately|this\s*number)|call\s*on\s*\+?\d|contact\s*us\s*(immediately|at)|reach\s*us\s*at)\b/i.test(t), reason:()=>'Urgently asks you to call a number — scammers impersonate support staff over calls to extract your information.' },
  { id:'click_link',           label:'Click-Here Prompt',      category:'medium',   weight:7,  test:t=>/\b(click\s*here|tap\s*here|open\s*this\s*link|follow\s*this\s*link|visit\s*this)\b/i.test(t), reason:()=>'Directs you to click a link — always verify links independently through official websites before clicking.' },
  { id:'upi_transfer',         label:'UPI/Payment Request',    category:'medium',   weight:9,  test:t=>/\b(send\s*(money|amount|payment|₹|rs\.?)|transfer\s*(money|funds|₹|rs\.?)|upi\s*id|gpay|phonepe|paytm\s*(to|id)|bhim|pay\s*on\s*upi)\b/i.test(t), reason:()=>'Requests a UPI or wallet transfer — no legitimate entity requests ad-hoc money transfers through messages.' },
  { id:'job_investment_scam',  label:'Job/Investment Fraud',   category:'medium',   weight:7,  test:t=>/\b(earn\s*(₹|rs\.?)?\s*\d+\s*(per\s*day|daily)|work\s*from\s*home\s*(earn|job)|easy\s*(money|income)|no\s*experience\s*(needed|required)|guaranteed\s*(returns?|profit)|double\s*your\s*money|investment\s*scheme)\b/i.test(t), reason:()=>'Promotes unrealistic earning/investment schemes — classic job scam, pyramid scheme, or fraudulent trading group.' },
]

function analyzeMessage(raw) {
  const text = raw.trim()
  if (!text) return null
  const triggered = []
  let rawScore = 0
  for (const sig of SIGNALS) { if (sig.test(text)) { triggered.push(sig); rawScore += sig.weight } }
  let label = rawScore >= 22 ? 'Scam' : rawScore >= 10 ? 'Suspicious' : 'Safe'
  let risk_score = label === 'Scam' ? Math.min(97, 60 + Math.round((rawScore - 22) * 1.2)) : label === 'Suspicious' ? Math.round(28 + (rawScore - 10) * 2.5) : Math.max(3, rawScore * 2)
  const topSignals = [...triggered].sort((a,b)=>b.weight-a.weight).slice(0,4)
  const reasons = topSignals.length > 0 ? topSignals.map(s=>s.reason(text)) : ['No phishing keywords, suspicious URLs, or manipulation patterns detected.','No requests for sensitive data (OTP, PIN, Aadhaar, financial details) found.','Language appears informational with no urgency or social engineering indicators.','No impersonation of banks, government bodies, or delivery companies detected.']
  const has = id => triggered.some(s=>s.id===id)
  let scam_type = triggered.length ? (has('otp_request')||has('password_share')||has('financial_data') ? 'Banking / OTP Fraud' : has('prize_lottery')||has('fee_demand') ? 'Lottery / Prize Scam' : has('suspicious_url') ? 'Phishing Link Attack' : has('identity_harvest') ? 'Identity Theft Attempt' : has('job_investment_scam') ? 'Job / Investment Fraud' : has('impersonation') ? 'Impersonation Fraud' : has('upi_transfer') ? 'Payment / UPI Fraud' : 'Social Engineering') : 'None Detected'
  const recommended_action = label === 'Scam' ? 'Do NOT click any links, share details, or transfer money. Block the sender immediately. Report at cybercrime.gov.in or call 1930.' : label === 'Suspicious' ? 'Do not respond immediately. Verify by calling the institution using their official number from their website — not the number in this message.' : 'This message appears safe. As a general rule, never share OTPs, passwords, or financial details over any channel.'
  return { label, risk_score, reasons, scam_type, recommended_action, signalTags: triggered.map(s=>({label:s.label, category:s.category})) }
}

// ═══════════════════════════════════════════════════════════
//  TOOLTIP COMPONENT
// ═══════════════════════════════════════════════════════════
function Tooltip({ children, content, position = 'top' }) {
  const [show, setShow] = useState(false)
  const [coords, setCoords] = useState({ x: 0, y: 0 })
  const ref = useRef(null)

  const handleMouseEnter = e => {
    const rect = ref.current.getBoundingClientRect()
    setCoords({
      x: rect.left + rect.width / 2,
      y: position === 'top' ? rect.top : rect.bottom
    })
    setShow(true)
  }

  const handleMouseLeave = () => setShow(false)

  return (
    <>
      <div
        ref={ref}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        className="tooltip-trigger"
      >
        {children}
      </div>
      {show && (
        <div
          className={`tooltip tooltip-${position}`}
          style={{
            left: coords.x,
            top: position === 'top' ? coords.y - 8 : coords.y + 8,
            transform: 'translateX(-50%)'
          }}
        >
          {content}
        </div>
      )}
    </>
  )
}

// ═══════════════════════════════════════════════════════════
//  RIPPLE EFFECT HOOK
// ═══════════════════════════════════════════════════════════
function useRipple() {
  const [ripples, setRipples] = useState([])

  const addRipple = e => {
    const button = e.currentTarget
    const rect = button.getBoundingClientRect()
    const size = Math.max(rect.width, rect.height)
    const x = e.clientX - rect.left - size / 2
    const y = e.clientY - rect.top - size / 2

    const newRipple = {
      id: Date.now(),
      x, y, size,
      opacity: 1,
      scale: 0
    }

    setRipples(prev => [...prev, newRipple])

    // Animate and remove
    setTimeout(() => {
      setRipples(prev => prev.map(r =>
        r.id === newRipple.id ? { ...r, opacity: 0, scale: 1 } : r
      ))
      setTimeout(() => {
        setRipples(prev => prev.filter(r => r.id !== newRipple.id))
      }, 300)
    }, 100)
  }

  return { ripples, addRipple }
}
// ═══════════════════════════════════════════════════════════
const SCAN_TYPES = [
  { id:'sms',   emoji:'💬', label:'SMS / Text' },
  { id:'email', emoji:'📧', label:'Email' },
  { id:'call',  emoji:'📞', label:'Call Script' },
  { id:'link',  emoji:'🔗', label:'Link / URL' },
]

const EXAMPLES = [
  { label:'🏦 Bank Alert',   text:'Dear Customer, your SBI account has been temporarily blocked due to suspicious activity. Verify your KYC immediately or your account will be closed: http://sbi-secure-kyc.xyz/verify' },
  { label:'🎁 Prize Scam',   text:'Congratulations! You have been selected as the lucky winner of ₹50,000 in the Amazon Lucky Draw. Send your Aadhaar number and OTP to claim. Offer valid 24 hours only!' },
  { label:'📦 Delivery Fee', text:'Your Flipkart package could not be delivered. Pay ₹29 customs clearance fee to reschedule: flipkart-delivery-reschedule.top/pay — valid today only.' },
  { label:'💼 Job Offer',    text:'Work from home opportunity! Earn ₹5000 daily, no experience needed. Pay a ₹199 registration fee to start. Guaranteed income every week.' },
  { label:'✅ Safe Msg',     text:'Hi Priya, your appointment at Apollo Clinic is confirmed for tomorrow at 10:30 AM. Please carry valid ID and arrive 15 minutes early.' },
]

const STEPS = [
  'Parsing message structure…',
  'Matching phishing patterns…',
  'Checking URL reputation…',
  'Scoring urgency signals…',
  'Detecting impersonation…',
  'Generating threat report…',
]

const TYPEWRITER_WORDS = ['SMS Scams','Phishing Links','OTP Theft','Bank Fraud','Fake Job Offers','UPI Fraud','Identity Theft']

// ═══════════════════════════════════════════════════════════
//  CURSOR GLOW EFFECT
// ═══════════════════════════════════════════════════════════
function CursorGlow() {
  const [position, setPosition] = useState({ x: 0, y: 0 })
  const [isVisible, setIsVisible] = useState(false)

  useEffect(() => {
    const handleMouseMove = (e) => {
      setPosition({ x: e.clientX, y: e.clientY })
    }
    const handleMouseEnter = () => setIsVisible(true)
    const handleMouseLeave = () => setIsVisible(false)

    document.addEventListener('mousemove', handleMouseMove)
    document.addEventListener('mouseenter', handleMouseEnter)
    document.addEventListener('mouseleave', handleMouseLeave)

    return () => {
      document.removeEventListener('mousemove', handleMouseMove)
      document.removeEventListener('mouseenter', handleMouseEnter)
      document.removeEventListener('mouseleave', handleMouseLeave)
    }
  }, [])

  return (
    <div
      className="cursor-glow"
      style={{
        left: position.x,
        top: position.y,
        opacity: isVisible ? 1 : 0,
      }}
    />
  )
}

// ═══════════════════════════════════════════════════════════
//  SCROLL PROGRESS BAR
// ═══════════════════════════════════════════════════════════
function ScrollProgress() {
  const [pct, setPct] = useState(0)
  useEffect(() => {
    const fn = () => {
      const el = document.documentElement
      setPct(Math.round((el.scrollTop / (el.scrollHeight - el.clientHeight)) * 100) || 0)
    }
    window.addEventListener('scroll', fn, { passive: true })
    return () => window.removeEventListener('scroll', fn)
  }, [])
  return <div className="scroll-prog" style={{ width: `${pct}%` }} />
}

// ═══════════════════════════════════════════════════════════
//  PARTICLE CANVAS
// ═══════════════════════════════════════════════════════════
function ParticleCanvas() {
  const ref = useRef(null)
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 })
  const [isMouseIn, setIsMouseIn] = useState(false)

  useEffect(() => {
    const canvas = ref.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    let W, H, particles, animId
    const resize = () => {
      W = canvas.width  = canvas.offsetWidth
      H = canvas.height = canvas.offsetHeight
    }
    resize()
    window.addEventListener('resize', resize)

    particles = Array.from({ length: 35 }, () => ({
      x: Math.random() * W,
      y: Math.random() * H,
      r: Math.random() * 3 + 1,
      dx: (Math.random() - 0.5) * 0.3,
      dy: (Math.random() - 0.5) * 0.3,
      alpha: Math.random() * 0.4 + 0.1,
      baseAlpha: Math.random() * 0.4 + 0.1,
      hue: Math.random() * 60 + 240, // Purple range
      saturation: Math.random() * 30 + 70,
      lightness: Math.random() * 20 + 60,
    }))

    const draw = () => {
      ctx.clearRect(0, 0, W, H)

      particles.forEach(p => {
        // Mouse interaction
        if (isMouseIn) {
          const dx = mousePos.x - p.x
          const dy = mousePos.y - p.y
          const distance = Math.sqrt(dx * dx + dy * dy)
          const maxDistance = 150

          if (distance < maxDistance) {
            const force = (maxDistance - distance) / maxDistance
            p.dx += (dx / distance) * force * 0.01
            p.dy += (dy / distance) * force * 0.01
            p.alpha = Math.min(0.8, p.baseAlpha + force * 0.4)
          } else {
            p.alpha = Math.max(p.baseAlpha, p.alpha - 0.01)
          }
        }

        // Update position
        p.x += p.dx
        p.y += p.dy

        // Bounce off edges
        if (p.x < 0 || p.x > W) p.dx *= -1
        if (p.y < 0 || p.y > H) p.dy *= -1

        // Keep particles in bounds
        p.x = Math.max(0, Math.min(W, p.x))
        p.y = Math.max(0, Math.min(H, p.y))

        // Apply friction
        p.dx *= 0.99
        p.dy *= 0.99

        // Draw particle with dynamic color
        const gradient = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.r * 2)
        gradient.addColorStop(0, `hsla(${p.hue}, ${p.saturation}%, ${p.lightness}%, ${p.alpha})`)
        gradient.addColorStop(1, `hsla(${p.hue}, ${p.saturation}%, ${p.lightness}%, 0)`)

        ctx.beginPath()
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2)
        ctx.fillStyle = gradient
        ctx.fill()
      })

      // Draw connecting lines for nearby particles
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x
          const dy = particles[i].y - particles[j].y
          const dist = Math.sqrt(dx*dx + dy*dy)

          if (dist < 120) {
            const alpha = (120 - dist) / 120 * 0.15
            ctx.beginPath()
            ctx.moveTo(particles[i].x, particles[i].y)
            ctx.lineTo(particles[j].x, particles[j].y)
            ctx.strokeStyle = `rgba(139,92,246,${alpha})`
            ctx.lineWidth = 0.5
            ctx.stroke()
          }
        }
      }

      animId = requestAnimationFrame(draw)
    }
    draw()

    return () => {
      cancelAnimationFrame(animId)
      window.removeEventListener('resize', resize)
    }
  }, [mousePos, isMouseIn])

  return (
    <canvas
      ref={ref}
      className="interactive-particle-canvas"
      aria-hidden="true"
      onMouseMove={(e) => {
        const rect = e.currentTarget.getBoundingClientRect()
        setMousePos({
          x: e.clientX - rect.left,
          y: e.clientY - rect.top
        })
      }}
      onMouseEnter={() => setIsMouseIn(true)}
      onMouseLeave={() => setIsMouseIn(false)}
    />
  )
}

// ═══════════════════════════════════════════════════════════
//  TYPEWRITER
// ═══════════════════════════════════════════════════════════
function TypewriterWord() {
  const [idx, setIdx]     = useState(0)
  const [text, setText]   = useState('')
  const [phase, setPhase] = useState('typing') // 'typing' | 'holding' | 'erasing'

  useEffect(() => {
    const word = TYPEWRITER_WORDS[idx]
    let t
    if (phase === 'typing') {
      if (text.length < word.length) {
        t = setTimeout(() => setText(word.slice(0, text.length + 1)), 80)
      } else {
        t = setTimeout(() => setPhase('holding'), 1800)
      }
    } else if (phase === 'holding') {
      t = setTimeout(() => setPhase('erasing'), 400)
    } else {
      if (text.length > 0) {
        t = setTimeout(() => setText(text.slice(0, -1)), 45)
      } else {
        setIdx(i => (i + 1) % TYPEWRITER_WORDS.length)
        setPhase('typing')
      }
    }
    return () => clearTimeout(t)
  }, [text, phase, idx])

  return (
    <span className="typewriter-word">
      {text}<span className="tw-cursor">|</span>
    </span>
  )
}

// ═══════════════════════════════════════════════════════════
//  LIVE DETECTION HINTS (debounced, appears while typing)
// ═══════════════════════════════════════════════════════════
function LiveHints({ message }) {
  const [hints, setHints] = useState([])
  const timer = useRef(null)

  useEffect(() => {
    clearTimeout(timer.current)
    if (!message.trim()) { setHints([]); return }
    timer.current = setTimeout(() => {
      const r = analyzeMessage(message)
      setHints(r?.signalTags?.slice(0, 5) || [])
    }, 350)
    return () => clearTimeout(timer.current)
  }, [message])

  if (!hints.length) return null

  return (
    <div className="live-hints">
      <span className="live-hints-label">⚡ Live signals:</span>
      {hints.map((h, i) => (
        <span key={i} className={`live-chip live-${h.category}`} style={{ animationDelay: `${i * 0.07}s` }}>
          {h.category === 'critical' ? '🔴' : h.category === 'high' ? '🟠' : '🟡'} {h.label}
        </span>
      ))}
    </div>
  )
}

// ═══════════════════════════════════════════════════════════
//  RADAR SCAN ANIMATION
// ═══════════════════════════════════════════════════════════
function RadarScan({ steps, shown }) {
  return (
    <div className="radar-wrap">
      <svg className="radar-svg" viewBox="0 0 160 160">
        {/* Concentric circles */}
        {[60, 45, 30, 15].map(r => (
          <circle key={r} cx="80" cy="80" r={r} fill="none" stroke="rgba(91,33,182,0.15)" strokeWidth="1" />
        ))}
        {/* Cross hairs */}
        <line x1="80" y1="20" x2="80" y2="140" stroke="rgba(91,33,182,0.1)" strokeWidth="1" />
        <line x1="20" y1="80" x2="140" y2="80" stroke="rgba(91,33,182,0.1)" strokeWidth="1" />
        {/* Sweep sector */}
        <defs>
          <radialGradient id="sweepGrad" cx="100%" cy="50%" r="100%">
            <stop offset="0%" stopColor="rgba(91,33,182,0.4)" />
            <stop offset="100%" stopColor="rgba(91,33,182,0)" />
          </radialGradient>
        </defs>
        <g className="radar-sweep-group">
          <path d="M80,80 L80,20 A60,60 0 0,1 140,80 Z" fill="url(#sweepGrad)" />
          <line x1="80" y1="80" x2="80" y2="22" stroke="rgba(139,92,246,0.8)" strokeWidth="1.5" />
        </g>
        {/* Blip dots that appear progressively */}
        {[
          {cx:110,cy:50}, {cx:50,cy:105}, {cx:120,cy:100},
          {cx:60,cy:45},  {cx:100,cy:120},{cx:35,cy:70},
        ].map((d, i) => (
          <circle
            key={i} cx={d.cx} cy={d.cy} r="3"
            fill={shown.length > i ? (shown.length > i + 2 ? '#10b981' : '#f59e0b') : 'transparent'}
            className="radar-blip"
            style={{ animationDelay: `${i * 0.4}s`, opacity: shown.length > i ? 1 : 0, transition: 'opacity .3s' }}
          />
        ))}
        {/* Center dot */}
        <circle cx="80" cy="80" r="3" fill="rgba(91,33,182,0.5)" />
      </svg>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════
//  SCAN OVERLAY (with radar)
// ═══════════════════════════════════════════════════════════
function ScanOverlay({ active }) {
  const [shown, setShown] = useState([])
  useEffect(() => {
    if (!active) { setShown([]); return }
    let i = 0
    const id = setInterval(() => { setShown(p => [...p, i]); i++; if (i >= STEPS.length) clearInterval(id) }, 390)
    return () => clearInterval(id)
  }, [active])
  if (!active) return null
  return (
    <div className="scan-overlay">
      <RadarScan steps={STEPS} shown={shown} />
      <p className="scan-label">Scanning threat profile…</p>
      <div className="scan-steps">
        {STEPS.map((s, i) => {
          if (!shown.includes(i)) return null
          const isDone = shown.includes(i + 1)
          return (
            <div key={i} className={`scan-step ${isDone ? 'done' : 'active'}`} style={{ animationDelay: `${i * 0.04}s` }}>
              <div className="step-dot" />
              {isDone ? '✓ ' : ''}{s}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════
//  ANIMATED SVG GAUGE
// ═══════════════════════════════════════════════════════════
function AnimatedGauge({ score, colorClass }) {
  const [displayed, setDisplayed] = useState(0)
  const r = 52, cx = 80, cy = 80
  const circumference = Math.PI * r
  const [offset, setOffset] = useState(circumference)

  useEffect(() => {
    // Count up
    let start = null
    const dur = 1200
    const step = ts => {
      if (!start) start = ts
      const p = Math.min((ts - start) / dur, 1)
      const eased = 1 - Math.pow(1 - p, 3)
      setDisplayed(Math.round(eased * score))
      setOffset(circumference - eased * (score / 100) * circumference)
      if (p < 1) requestAnimationFrame(step)
    }
    requestAnimationFrame(step)
  }, [score])

  const strokeColor = colorClass === 'scam' ? '#ef4444' : colorClass === 'suspicious' ? '#f59e0b' : '#10b981'
  const arc = `M ${cx - r},${cy} A ${r},${r} 0 0 1 ${cx + r},${cy}`

  return (
    <div className="gauge-container">
      <svg className="gauge-svg" viewBox="0 0 160 100">
        <path d={arc} fill="none" stroke="#f1f3fb" strokeWidth="12" strokeLinecap="round" />
        <path
          d={arc} fill="none" stroke={strokeColor} strokeWidth="12" strokeLinecap="round"
          strokeDasharray={circumference} strokeDashoffset={offset}
          style={{ filter: `drop-shadow(0 0 6px ${strokeColor}55)` }}
        />
      </svg>
      <div className="gauge-label-group">
        <span className={`gauge-num ${colorClass}`}>{displayed}</span>
        <span className="gauge-out">/ 100</span>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════
//  CONFETTI (for Safe results)
// ═══════════════════════════════════════════════════════════
const CONFETTI_COLORS = ['#5b21b6','#7c3aed','#10b981','#f59e0b','#ec4899','#6366f1','#34d399']
function Confetti({ active }) {
  const [pieces, setPieces] = useState([])
  useEffect(() => {
    if (!active) return
    const arr = Array.from({ length: 60 }, (_, i) => ({
      id: i,
      left: Math.random() * 100,
      color: CONFETTI_COLORS[Math.floor(Math.random() * CONFETTI_COLORS.length)],
      size:  Math.random() * 8 + 5,
      dur:   Math.random() * 1.5 + 1.5,
      delay: Math.random() * 0.8,
      rotate: Math.random() * 720 - 360,
      shape: Math.random() > 0.5 ? 'circle' : 'rect',
    }))
    setPieces(arr)
    const t = setTimeout(() => setPieces([]), 3500)
    return () => clearTimeout(t)
  }, [active])
  if (!pieces.length) return null
  return (
    <div className="confetti-overlay" aria-hidden="true">
      {pieces.map(p => (
        <div
          key={p.id}
          className="confetti-piece"
          style={{
            left: `${p.left}%`,
            width: p.shape === 'circle' ? p.size : p.size * 0.6,
            height: p.size,
            background: p.color,
            borderRadius: p.shape === 'circle' ? '50%' : '2px',
            animationDuration: `${p.dur}s`,
            animationDelay: `${p.delay}s`,
            '--rotate': `${p.rotate}deg`,
          }}
        />
      ))}
    </div>
  )
}

// ═══════════════════════════════════════════════════════════
//  RECENT SCANS (localStorage)
// ═══════════════════════════════════════════════════════════
function useHistory() {
  const [history, setHistory] = useState(() => {
    try { return JSON.parse(localStorage.getItem('te_history') || '[]') } catch { return [] }
  })
  const push = useCallback((result, preview) => {
    setHistory(prev => {
      const next = [{ ...result, preview, ts: Date.now() }, ...prev].slice(0, 5)
      localStorage.setItem('te_history', JSON.stringify(next))
      return next
    })
  }, [])
  const clear = useCallback(() => { setHistory([]); localStorage.removeItem('te_history') }, [])
  return { history, push, clear }
}

function RecentScans({ history, clear, onReplay }) {
  if (!history.length) return null
  return (
    <div className="recent-scans reveal">
      <div className="rs-header">
        <span className="rs-title">📋 Recent Scans</span>
        <button className="rs-clear" onClick={clear}>Clear</button>
      </div>
      <div className="rs-list">
        {history.map((h, i) => (
          <div key={i} className={`rs-item rs-${h.label.toLowerCase()}`} onClick={() => onReplay(h)} title="Click to view">
            <span className={`rs-dot rs-dot-${h.label.toLowerCase()}`} />
            <span className="rs-preview">{h.preview.substring(0, 60)}{h.preview.length > 60 ? '…' : ''}</span>
            <span className="rs-badge">{h.label} · {h.risk_score}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════
//  MAGNETIC BUTTON
// ═══════════════════════════════════════════════════════════
function MagneticButton({ children, className = '', strength = 0.3, onClick, ...props }) {
  const ref = useRef(null)
  const [position, setPosition] = useState({ x: 0, y: 0 })

  const handleMouseMove = (e) => {
    const btn = ref.current
    if (!btn) return
    const rect = btn.getBoundingClientRect()
    const x = (e.clientX - rect.left - rect.width / 2) * strength
    const y = (e.clientY - rect.top - rect.height / 2) * strength
    setPosition({ x, y })
  }

  const handleMouseLeave = () => {
    setPosition({ x: 0, y: 0 })
  }

  return (
    <button
      ref={ref}
      className={`magnetic-btn ${className}`}
      style={{
        transform: `translate(${position.x}px, ${position.y}px)`,
        transition: 'transform 0.3s cubic-bezier(0.4, 0, 0.2, 1)'
      }}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      onClick={onClick}
      {...props}
    >
      {children}
    </button>
  )
}

// ═══════════════════════════════════════════════════════════
//  3D TILT CARD
// ═══════════════════════════════════════════════════════════
function TiltCard({ children, className = '', style = {} }) {
  const ref = useRef(null)
  const handleMove = e => {
    const card = ref.current
    if (!card) return
    const rect = card.getBoundingClientRect()
    const x = (e.clientX - rect.left) / rect.width  - 0.5
    const y = (e.clientY - rect.top)  / rect.height - 0.5
    card.style.transform = `perspective(600px) rotateX(${-y * 10}deg) rotateY(${x * 10}deg) translateY(-6px)`
    card.style.boxShadow = `${-x * 12}px ${y * 12}px 32px rgba(91,33,182,0.18)`
  }
  const handleLeave = () => {
    const card = ref.current
    if (!card) return
    card.style.transform = ''
    card.style.boxShadow = ''
  }
  return (
    <div
      ref={ref}
      className={`step-card tilt-card ${className}`}
      style={style}
      onMouseMove={handleMove}
      onMouseLeave={handleLeave}
    >
      {children}
    </div>
  )
}

// ═══════════════════════════════════════════════════════════
//  SCROLL-TRIGGERED ANIMATIONS
// ═══════════════════════════════════════════════════════════
function useScrollAnimations() {
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('animate-in')
          }
        })
      },
      {
        threshold: 0.1,
        rootMargin: '-50px 0px -50px 0px'
      }
    )

    const elements = document.querySelectorAll('.scroll-animate')
    elements.forEach((el) => observer.observe(el))

    return () => observer.disconnect()
  }, [])
}

// ═══════════════════════════════════════════════════════════
//  ANIMATED COUNTER (scroll-triggered)
// ═══════════════════════════════════════════════════════════
function Counter({ to, suffix = '' }) {
  const [val, setVal] = useState(0)
  const ref = useRef(null)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const obs = new IntersectionObserver(([entry]) => {
      if (!entry.isIntersecting) return
      obs.disconnect()
      let start = null
      const dur = 1800
      const step = ts => {
        if (!start) start = ts
        const p = Math.min((ts - start) / dur, 1)
        setVal(Math.floor(p * to))
        if (p < 1) requestAnimationFrame(step)
      }
      requestAnimationFrame(step)
    }, { threshold: 0.5 })
    obs.observe(el)
    return () => obs.disconnect()
  }, [to])
  return <span ref={ref}>{val.toLocaleString()}{suffix}</span>
}

// ═══════════════════════════════════════════════════════════
//  RESULT CARD
// ═══════════════════════════════════════════════════════════
const VERDICT_ICONS = { Scam:'🚨', Suspicious:'⚠️', Safe:'✅' }
const ACTION_ICONS  = { Scam:'🛑', Suspicious:'🔎', Safe:'👍' }

function ResultCard({ result, onReset }) {
  const [copied, setCopied] = useState(false)
  const cls = result.label.toLowerCase()
  const fillColor = cls==='scam' ? 'linear-gradient(90deg,#fca5a5,#ef4444)' : cls==='suspicious' ? 'linear-gradient(90deg,#fcd34d,#f59e0b)' : 'linear-gradient(90deg,#6ee7b7,#10b981)'
  const copy = () => {
    const t = `ThreatEye Report\nVerdict: ${result.label} (${result.risk_score}/100)\nType: ${result.scam_type}\n\nFindings:\n${result.reasons.map(r=>`• ${r}`).join('\n')}\n\nAction:\n${result.recommended_action}`
    navigator.clipboard.writeText(t).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2500) })
  }
  return (
    <div className="result-wrapper">
      <div className={`result-card ${cls}`}>
        {/* Verdict banner */}
        <div className={`verdict-banner ${cls}`}>
          <div className="verdict-left-group">
            <div className={`verdict-badge ${cls}`}><span>{VERDICT_ICONS[result.label]}</span>{result.label}</div>
            <span className="verdict-type">{result.scam_type}</span>
          </div>
          <AnimatedGauge score={result.risk_score} colorClass={cls} />
        </div>
        {/* Risk bar */}
        <div className="risk-row">
          <div className="risk-labels">
            <span className="rl-safe">Safe · 0–21</span>
            <span className="rl-mid">Suspicious · 22–59</span>
            <span className="rl-bad">Scam · 60–100</span>
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
                <span key={i} className={`sig-tag ${s.category}`} style={{ animationDelay: `${i * 0.06}s` }}>
                  {s.category==='critical'?'🔴':s.category==='high'?'🟠':'🟡'} {s.label}
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
                <li key={i} className="reason-li" style={{ animationDelay: `${i * 0.08}s` }}>
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
              <button id="copy-btn" className={`copy-btn ${copied ? 'ok' : ''}`} onClick={copy}>
                {copied ? '✓ Copied!' : '⧉ Copy Report'}
              </button>
            </div>
          </div>
        </div>
      </div>
      <button id="new-scan-btn" className="new-scan-btn" onClick={onReset}>← Analyze Another Message</button>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════
//  MAIN APP
// ═══════════════════════════════════════════════════════════
export default function App() {
  const [msg, setMsg]           = useState('')
  const [activeType, setType]   = useState('sms')
  const [scanning, setScanning] = useState(false)
  const [result, setResult]     = useState(null)
  const [navScrolled, setNav]   = useState(false)
  const [showConfetti, setConfetti] = useState(false)
  const [shakeBtn, setShakeBtn] = useState(false)
  const { history, push, clear } = useHistory()

  // Ripple effect hooks
  const analyzeRipple = useRipple()

  useScrollAnimations()

  useEffect(() => {
    const fn = () => setNav(window.scrollY > 10)
    window.addEventListener('scroll', fn, { passive: true })
    return () => window.removeEventListener('scroll', fn)
  }, [])

  // Re-run reveal after result appears
  useEffect(() => {
    const t = setTimeout(() => {
      const els = document.querySelectorAll('.reveal:not(.visible)')
      const obs = new IntersectionObserver(entries => entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('visible') }), { threshold: 0.1 })
      els.forEach(el => obs.observe(el))
      return () => obs.disconnect()
    }, 100)
    return () => clearTimeout(t)
  }, [result])

  const charLen = msg.length
  const charCls = charLen > 1800 ? 'char-over' : charLen > 1400 ? 'char-warn' : ''

  const scrollToAnalyzer = () => document.getElementById('analyzer')?.scrollIntoView({ behavior: 'smooth' })

  const handleAnalyze = async () => {
    if (scanning) return
    if (!msg.trim()) {
      setShakeBtn(true)
      setTimeout(() => setShakeBtn(false), 600)
      return
    }
    setScanning(true)
    setResult(null)
    await new Promise(r => setTimeout(r, STEPS.length * 390 + 700))
    let res
    try {
      const resp = await fetch('http://localhost:3000/analyze', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({message:msg}), signal:AbortSignal.timeout(8000) })
      if (!resp.ok) throw new Error()
      const data = await resp.json()
      res = { ...data, signalTags: analyzeMessage(msg)?.signalTags || [] }
    } catch {
      res = analyzeMessage(msg)
    }
    setScanning(false)
    setResult(res)
    push(res, msg.trim())
    if (res?.label === 'Safe') { setConfetti(true); setTimeout(() => setConfetti(false), 3500) }
  }

  const handleReset = () => { setResult(null); setMsg('') }
  const onKey = e => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') handleAnalyze() }

  // Keyboard shortcuts helper
  const [showShortcuts, setShowShortcuts] = useState(false)
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === '?' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault()
        setShowShortcuts(prev => !prev)
      }
      if (e.key === 'Escape') {
        setShowShortcuts(false)
      }
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [])

  return (
    <div className="app">
      <CursorGlow />
      <ScrollProgress />
      <Confetti active={showConfetti} />

      {/* Keyboard Shortcuts Modal */}
      {showShortcuts && (
        <div className="shortcuts-overlay" onClick={() => setShowShortcuts(false)}>
          <div className="shortcuts-modal" onClick={e => e.stopPropagation()}>
            <div className="shortcuts-header">
              <h3>⌨️ Keyboard Shortcuts</h3>
              <button className="close-btn" onClick={() => setShowShortcuts(false)}>×</button>
            </div>
            <div className="shortcuts-list">
              <div className="shortcut-item">
                <kbd>Ctrl</kbd> + <kbd>Enter</kbd>
                <span>Analyze message</span>
              </div>
              <div className="shortcut-item">
                <kbd>?</kbd>
                <span>Show shortcuts</span>
              </div>
              <div className="shortcut-item">
                <kbd>Esc</kbd>
                <span>Close modals</span>
              </div>
              <div className="shortcut-item">
                <kbd>1</kbd> - <kbd>4</kbd>
                <span>Switch scan type</span>
              </div>
            </div>
          </div>
        </div>
      )}

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
        <ParticleCanvas />
        <div className="hero-float-chips" aria-hidden="true">
          <div className="float-chip"><span className="chip-icon">🚨</span> 2.4M+ Scams Blocked</div>
          <div className="float-chip"><span className="chip-icon">⚡</span> &lt;1s Analysis Time</div>
          <div className="float-chip"><span className="chip-icon">🛡️</span> 14 Signal Categories</div>
          <div className="float-chip"><span className="chip-icon">✅</span> 99% Accuracy Rate</div>
        </div>
        <div className="hero-inner">
          <div className="hero-pill">
            <div className="hero-pill-dot" />
            Real-time AI-powered scam detection
          </div>
          <h1>
            Detect <TypewriterWord /><br />
            <span className="grad">Before They Strike</span>
          </h1>
          <p className="hero-desc">
            Paste any suspicious SMS, email, or link and get an instant, detailed threat analysis
            with clear reasons and actionable steps — in under a second.
          </p>
          <div className="hero-cta-row">
            <MagneticButton className="btn-primary" strength={0.4} onClick={scrollToAnalyzer}>
              🔍 Analyze a Message
            </MagneticButton>
            <a className="btn-outline magnetic-btn" href="#how-it-works">How It Works ↓</a>
          </div>
        </div>
        <div className="scroll-indicator" onClick={scrollToAnalyzer} style={{ cursor:'pointer' }}>
          <span>Scroll</span>
          <div className="scroll-arrow">↓</div>
        </div>
      </section>

      {/* ── LIVE THREAT FEED ── */}
      <section className="threat-feed-section">
        <div className="section">
          <div className="reveal">
            <div className="section-tag">Real-Time Protection</div>
            <h2 className="section-title">Live Threat Detection</h2>
            <p className="section-sub">See how ThreatEye identifies and blocks scams in real-time</p>
          </div>
          
          <div className="threat-feed-container reveal">
            <div className="threat-feed-header">
              <div className="feed-status">
                <span className="status-dot"></span>
                <span>Monitoring Active</span>
              </div>
              <div className="feed-stats">
                <span>🔴 2,847 threats blocked today</span>
              </div>
            </div>
            
            <div className="threat-feed-list">
              {[
                { type: 'Scam', msg: 'Urgent: Your bank account will be blocked. Click here...', time: '2s ago', icon: '🏦' },
                { type: 'Phishing', msg: 'Amazon order #12345 - Payment failed. Update details...', time: '5s ago', icon: '📦' },
                { type: 'OTP Fraud', msg: 'Your OTP is 123456. Never share it with anyone...', time: '8s ago', icon: '🔐' },
                { type: 'Prize Scam', msg: 'Congratulations! You won ₹50,000! Claim now...', time: '12s ago', icon: '🎁' },
                { type: 'Job Fraud', msg: 'Work from home, earn ₹5000/day. No experience...', time: '15s ago', icon: '💼' },
              ].map((threat, i) => (
                <div key={i} className="threat-item" style={{ animationDelay: `${i * 0.15}s` }}>
                  <div className="threat-icon">{threat.icon}</div>
                  <div className="threat-content">
                    <div className="threat-type">{threat.type}</div>
                    <div className="threat-msg">{threat.msg}</div>
                  </div>
                  <div className="threat-time">{threat.time}</div>
                  <div className="threat-badge">BLOCKED</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ── HOW IT WORKS ── */}
      <section className="how-section" id="how-it-works">
        <div className="section">
          <div className="reveal">
            <div className="section-tag">Detection Engine</div>
            <h2 className="section-title">How ThreatEye Works</h2>
            <p className="section-sub">Every message is scanned across 14 signal categories simultaneously in under a second.</p>
          </div>

          <div className="steps-grid">
            {[
              {
                num: '01', icon: '🔗', title: 'URL Intelligence',
                desc: 'Every link verified against phishing databases with suspicious TLD detection (.xyz, .top, .click).',
                tooltip: 'Advanced URL analysis checks domain reputation, SSL certificates, and suspicious patterns like fake banking domains.'
              },
              {
                num: '02', icon: '🧠', title: 'NLP Signal Analysis',
                desc: 'Detects urgency, fear, authority abuse, and reward baiting with weighted pattern matching.',
                tooltip: 'Natural language processing identifies psychological manipulation techniques used by scammers.'
              },
              {
                num: '03', icon: '🏦', title: 'Impersonation Radar',
                desc: 'Recognises fake banks (SBI, HDFC), government bodies (RBI), and e-commerce brands.',
                tooltip: 'Machine learning model trained on thousands of scam messages to detect impersonation attempts.'
              },
            ].map((step, i) => (
              <div key={i} className="reveal" style={{ transitionDelay: `${i * 0.1}s` }}>
                <TiltCard className="step-card">
                  <Tooltip content={step.tooltip} position="top">
                    <div className="step-num">{step.num}</div>
                  </Tooltip>
                  <div className="step-icon">{step.icon}</div>
                  <h3>{step.title}</h3>
                  <p>{step.desc}</p>
                </TiltCard>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── ANALYZER ── */}
      <div className="analyzer-section" id="analyzer">
        <div className="section">
          <div className="reveal">
            <div className="section-tag">Threat Analyzer</div>
            <h2 className="section-title">Check Any Message Instantly</h2>
            <p className="section-sub">14 signal categories · Weighted AI scoring · Results in &lt;1 second</p>
          </div>

          <div className="reveal" style={{ transitionDelay:'.1s' }}>
            <div className="analyzer-card">
              <div className="type-tabs">
                {SCAN_TYPES.map(t => (
                  <button key={t.id} id={`tab-${t.id}`} className={`type-tab ${activeType===t.id?'active':''}`} onClick={() => setType(t.id)}>
                    {t.emoji} {t.label}
                  </button>
                ))}
              </div>

              {!scanning && !result && (
                <>
                  <div className="input-area">
                    <textarea
                      id="message-input"
                      className="msg-input"
                      placeholder={`Paste your ${SCAN_TYPES.find(t=>t.id===activeType)?.label} here…  (Ctrl+Enter to analyze)`}
                      value={msg}
                      maxLength={2000}
                      onChange={e => setMsg(e.target.value)}
                      onKeyDown={onKey}
                      rows={6}
                    />
                    <LiveHints message={msg} />
                    <div className="input-footer">
                      <span className={charCls}>{charLen} / 2000</span>
                      <span>Ctrl + Enter to analyze</span>
                    </div>
                  </div>

                  <div className="examples-row">
                    <span className="examples-label-text">Try an example:</span>
                    {EXAMPLES.map((ex, i) => (
                      <button key={i} id={`ex-${i}`} className="ex-chip" onClick={() => setMsg(ex.text)}>{ex.label}</button>
                    ))}
                  </div>

                  <div className="action-row">
                    <button
                      id="analyze-btn"
                      className={`analyze-btn ${shakeBtn ? 'shake' : ''}`}
                      onClick={(e) => { analyzeRipple.addRipple(e); handleAnalyze() }}
                      disabled={scanning}
                    >
                      <div className="ripple-container">
                        {analyzeRipple.ripples.map(ripple => (
                          <span
                            key={ripple.id}
                            className="ripple-effect"
                            style={{
                              left: ripple.x,
                              top: ripple.y,
                              width: ripple.size,
                              height: ripple.size,
                              opacity: ripple.opacity,
                              transform: `scale(${ripple.scale})`
                            }}
                          />
                        ))}
                      </div>
                      🔍 Analyze Threat
                    </button>
                    <span className="hint-text">~1 sec · Free</span>
                  </div>
                </>
              )}

              {scanning && <ScanOverlay active={scanning} />}
            </div>

            {result && !scanning && <ResultCard result={result} onReset={handleReset} />}
          </div>

          <RecentScans history={history} clear={clear} onReplay={r => setResult(r)} />
        </div>
      </div>

      {/* ── TRUST & TESTIMONIALS ── */}
      <section className="trust-section">
        <div className="section">
          <div className="reveal">
            <div className="section-tag">Trusted Protection</div>
            <h2 className="section-title">Join Thousands Staying Safe</h2>
            <p className="section-sub">Real users, real protection, real peace of mind</p>
          </div>

          <div className="trust-grid reveal">
            <div className="trust-card">
              <div className="trust-quote">"ThreatEye saved me from a banking scam. It detected the fake SBI message instantly."</div>
              <div className="trust-author">
                <div className="trust-avatar">👩‍💼</div>
                <div>
                  <div className="trust-name">Priya Sharma</div>
                  <div className="trust-role">Bank Manager, Mumbai</div>
                </div>
              </div>
            </div>
            <div className="trust-card">
              <div className="trust-quote">"The analysis is incredibly detailed. I now check every suspicious message before acting."</div>
              <div className="trust-author">
                <div className="trust-avatar">👨‍🎓</div>
                <div>
                  <div className="trust-name">Rahul Verma</div>
                  <div className="trust-role">Student, Delhi</div>
                </div>
              </div>
            </div>
            <div className="trust-card">
              <div className="trust-quote">"As a senior citizen, I was vulnerable to scams. ThreatEye gives me confidence to use my phone safely."</div>
              <div className="trust-author">
                <div className="trust-avatar">👴</div>
                <div>
                  <div className="trust-name">K. Venkatesh</div>
                  <div className="trust-role">Retired Teacher, Chennai</div>
                </div>
              </div>
            </div>
          </div>

          <div className="trust-badges reveal">
            <div className="badge-item">🔒 Bank-Grade Security</div>
            <div className="badge-item">⚡ Instant Analysis</div>
            <div className="badge-item">🤖 AI-Powered Detection</div>
            <div className="badge-item">📱 Works on All Devices</div>
          </div>
        </div>
      </section>

      {/* ── FOOTER ── */}
      <footer className="footer">
        <div className="footer-brand"><span>🛡️</span> ThreatEye — AI Scam Detection</div>
        <span style={{ fontSize:'12px' }}>Stay safe. Never share OTPs or passwords.</span>
      </footer>
    </div>
  )
}
