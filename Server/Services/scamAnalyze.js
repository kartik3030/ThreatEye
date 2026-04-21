function analyzeMessage(text) {
    if (!text || typeof text !== "string" || text.trim().length < 5) {
        return {
            label: "Safe",
            isScam: false,
            isSuspicious: false,
            risk_score: 0,
            reasons: [],
            scam_type: "None",
            recommended_action: "Insufficient content"
        };
    }

    const lower = text.toLowerCase();
    const normalized = lower.replace(/[\.\-\_\s]/g, "");

    const matchRaw = (r) => r.test(lower);
    const matchNormalized = (r) => r.test(normalized);

    let highRisk = 0;
    let mediumRisk = 0;
    let lowRisk = 0;

    const reasons = new Set();
    let scamType = "None";

    // Priority system for scam type
    const priority = {
        "OTP Fraud": 3,
        "Payment Scam": 2,
        "Phishing": 2,
        "Lottery Scam": 1,
        "None": 0
    };

    const setType = (type) => {
        if (priority[type] > priority[scamType]) {
            scamType = type;
        }
    };

    // =========================
    // HIGH-RISK SIGNALS
    // =========================

    if (matchNormalized(/otp|ones?timepassword|verificationcode|passcode/)) {
        highRisk += 50;
        reasons.add("Requests OTP or sensitive credentials");
        setType("OTP Fraud");
    }

    if (
        matchNormalized(/sendmoney|paynow|scanqr|collectrequest|recharge/) ||
        matchRaw(/upi:\/\/pay|@\w{2,}|paytm|gpay|phonepe/)
    ) {
        highRisk += 40;
        reasons.add("Direct payment request detected");
        setType("Payment Scam");
    }

    // =========================
    // MEDIUM-RISK SIGNALS
    // =========================

    if (
        matchRaw(/https?:\/\/|www\./) ||
        matchNormalized(/bitly|tinyurl|tme|googl|hxxp/) ||
        matchRaw(/\.(xyz|top|ru|click|link)\b/)
    ) {
        mediumRisk += 30;
        reasons.add("Contains suspicious or shortened link");
        setType("Phishing");
    }

    if (
        matchRaw(/\b(bank|sbi|hdfc|icici|axis|paypal|upi|income tax|police|rbi|aadhaar|pan|gov|government)\b/)
    ) {
        mediumRisk += 20;
        reasons.add("Impersonates authority or financial institution");
    }

    if (
        matchNormalized(/urgent|immediately|actnow|expires|deadline|blocked|suspend|kyc|verify|lastchance|finalnotice/)
    ) {
        mediumRisk += 20;
        reasons.add("Creates urgency or fear pressure");
    }

    // =========================
    // LOW-RISK SIGNALS
    // =========================

    if (
        matchNormalized(/won|winner|prize|lottery|reward|gift|cashback|bonus|earned/)
    ) {
        lowRisk += 20;
        reasons.add("Uses reward bait or lottery language");
        setType("Lottery Scam");
    }

    // =========================
    // FINAL SCORING
    // =========================

    const finalScore = Math.min(highRisk + mediumRisk + lowRisk, 100);

    let label = "Safe";
    if (finalScore >= 70) label = "Scam";
    else if (finalScore >= 45) label = "Suspicious";

    const isScam = label === "Scam";
    const isSuspicious = label === "Suspicious";

    const recommendations = {
        Scam: "CRITICAL: Do not engage. Block sender. Avoid links and payments.",
        Suspicious: "CAUTION: Verify sender identity before any action.",
        Safe: "No strong scam indicators detected."
    };

    return {
        label,
        isScam,
        isSuspicious,
        risk_score: finalScore,
        reasons: Array.from(reasons),
        scam_type: scamType,
        recommended_action: recommendations[label]
    };
}

module.exports = { analyzeMessage };