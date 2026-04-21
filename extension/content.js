const nodeMap = new Map();
const processedTexts = new Set();

function generateId(text) {
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
        hash = (hash << 5) - hash + text.charCodeAt(i);
        hash |= 0;
    }
    return "msg_" + Math.abs(hash);
}

function scanMessages() {
    // WhatsApp specific selector
    const nodes = document.querySelectorAll("div.message-in span.selectable-text");

    nodes.forEach((node) => {
        const text = node.innerText.trim();
        if (!text || processedTexts.has(text)) return;

        const id = generateId(text);
        processedTexts.add(text);
        nodeMap.set(id, node);

        chrome.runtime.sendMessage({
            type: "NEW_MESSAGE",
            payload: { id, text, source: "whatsapp" }
        });
    });
}

// Throttle observer to prevent lag
let timeout = null;
const observer = new MutationObserver(() => {
    if (timeout) return;
    timeout = setTimeout(() => {
        scanMessages();
        timeout = null;
    }, 1000);
});

observer.observe(document.body, { childList: true, subtree: true });

// UI Update Listener
chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type !== "SCAN_RESULT") return;

    const { id, label, risk_score } = msg.payload;
    let node = nodeMap.get(id);

    // If node was recycled by React/WhatsApp, try to find it again
    if (!node || !node.isConnected) {
        const candidates = document.querySelectorAll("span.selectable-text");
        for (let el of candidates) {
            if (generateId(el.innerText.trim()) === id) {
                node = el;
                nodeMap.set(id, el); // Update map with fresh reference
                break;
            }
        }
    }

    if (node && (label === "Scam" || label === "Suspicious")) {
        applyStyle(node, label === "Scam" ? "red" : "orange", risk_score);
    }
});

function applyStyle(node, color, score) {
    const rgba = color === "red" ? "rgba(255,0,0,0.2)" : "rgba(255,165,0,0.2)";
    node.style.backgroundColor = rgba;
    node.style.borderLeft = `4px solid ${color}`;
    node.style.padding = "2px 5px";
    node.style.borderRadius = "2px";
    node.title = `ThreatEye Analysis: ${score}% Risk`;
}

scanMessages();