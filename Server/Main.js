require("dotenv").config();
const express = require("express");
const http = require("http");
const cors = require("cors");
const { Server } = require("socket.io");
const { analyzeMessage } = require("./services/scamAnalyze");

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: { origin: "*" }
});

const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

/* =========================
   SOCKET (Dashboard only)
========================= */
io.on("connection", (socket) => {
    console.log("Connected:", socket.id);

    socket.on("register", (role) => {
        if (role === "dashboard") {
            socket.join("admin_reports");
            console.log(`Socket ${socket.id} joined Dashboard room`);
        }
    });

    socket.on("disconnect", () => {
        console.log("Disconnected:", socket.id);
    });
});

/* =========================
   REST (Extension uses this)
========================= */
app.post("/analyze", (req, res) => {
    try {
        const { id, text, source } = req.body;

        if (!text || typeof text !== "string") {
            return res.status(400).json({ error: "Invalid text input" });
        }

        const result = analyzeMessage(text);

        const payload = {
            id: id || Date.now().toString(),
            text,
            source: source || "unknown",
            ...result,
            timestamp: Date.now()
        };

        // Push to dashboard (real-time)
        io.to("admin_reports").emit("dashboard:update", payload);

        return res.json(payload);

    } catch (err) {
        console.error("Analyze API error:", err);
        return res.status(500).json({ error: "Server error" });
    }
});

/* =========================
   HEALTH CHECK
========================= */
app.get("/", (req, res) => {
    res.json({ status: "ThreatEye API Active" });
});

/* =========================
   START SERVER
========================= */
server.listen(PORT, () => {
    console.log(`ThreatEye Server: http://localhost:${PORT}`);
});