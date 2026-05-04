# Threat-Eye Extension

Threat-Eye is a browser extension that analyzes DOM content and user messages to detect potential threats using Groq LLM. It performs real-time classification and flags suspicious or harmful content directly on web pages.

---

## Features

- Real-time DOM content analysis  
- Message scanning for threat detection  
- AI-powered classification using Groq LLM  
- Lightweight and fast execution  
- In-browser alerts or highlighting  

---

## Tech Stack

- HTML, CSS, JavaScript  
- Chrome Extension APIs  
- Node.js / Express (optional backend)  
- Groq LLM API  

---

## Project Structure
threat-eye/
│── extension/
│ │── manifest.json
│ │── content.js
│ │── background.js
│ │── popup/
│ │ │── popup.html
│ │ │── popup.js
│ │ │── popup.css
│
│── server/ (optional)
│ │── index.js
│ │── routes/
│ │── controllers/
│
│── README.md

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/threat-eye.git

   Open Chrome and navigate to:

chrome://extensions/
Enable Developer Mode
Click Load Unpacked
Select the extension/ folder
Usage
Open any website
Enable the Threat-Eye extension
It scans content and flags potential threats in real time
Future Improvements
Improved context-aware detection
Custom threat filters
Multi-browser support
Analytics dashboard
License

MIT License
