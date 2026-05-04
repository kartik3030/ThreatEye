Threat-Eye Extension

Threat-Eye is a web extension that analyzes DOM content and user messages to detect potential threats using Groq LLM. It performs real-time risk classification and flags suspicious content directly within the browser.

Features
DOM scanning for visible text and user-generated content
Real-time threat detection using Groq LLM
Risk classification (e.g., safe, suspicious, high-risk)
Lightweight and fast execution inside the browser
Seamless integration with web pages
Tech Stack
Frontend: JavaScript, HTML, CSS
Backend: Node.js / Express (for API handling if used)
AI Model: Groq LLM API
Extension APIs: Chrome Extension APIs
Project Structure
threat-eye/
│── extension/
│   │── manifest.json
│   │── content.js
│   │── background.js
│   │── popup/
│   │   │── popup.html
│   │   │── popup.js
│   │   │── popup.css
│
│── server/ (optional)
│   │── index.js
│   │── routes/
│   │── controllers/
│
│── README.md
How It Works
Content script extracts DOM text and user messages
Data is sent to the backend or directly to Groq API
LLM analyzes content and assigns a threat level
Results are displayed in the extension UI or highlighted on the page
Installation

Clone the repository:

git clone https://github.com/your-username/threat-eye.git

Open Chrome and go to:

chrome://extensions/
Enable Developer Mode
Click Load Unpacked
Select the extension/ folder
Usage
Open any website
Activate the Threat-Eye extension
It automatically scans content and highlights or reports threats
Future Improvements
Advanced NLP filtering and context awareness
Custom user-defined threat rules
Dashboard for analytics and logs
Support for multiple browsers (Firefox, Edge)
License

MIT License
