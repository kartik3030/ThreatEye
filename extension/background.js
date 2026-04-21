async function analyzeMessage(data) {
  try {
    const res = await fetch("http://localhost:3000/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(data)
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    return await res.json();

  } catch (err) {
    console.error("API Error:", err);
    throw err;
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type !== "NEW_MESSAGE") return;

  if (!msg.payload || typeof msg.payload !== "object") {
    sendResponse({ status: "error", error: "Invalid payload" });
    return;
  }

  analyzeMessage(msg.payload)
    .then((result) => {
      chrome.tabs.query(
        { url: ["https://web.whatsapp.com/*"] },
        (tabs) => {
          tabs.forEach((tab) => {
            chrome.tabs.sendMessage(tab.id, {
              type: "SCAN_RESULT",
              payload: result
            }).catch(() => { });
          });
        }
      );

      sendResponse({ status: "done" });
    })
    .catch((err) => {
      sendResponse({
        status: "error",
        error: err.message || "Unknown error"
      });
    });

  return true; // REQUIRED for async response
});