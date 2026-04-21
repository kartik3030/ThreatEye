const { analyzeMessage } = require("../services/scamAnalyze");

function initSocket(io) {
    io.on("connection", (socket) => {
        console.log("Connected:", socket.id);

        // Dashboard registration only
        socket.on("register:dashboard", () => {
            socket.join("admin_dashboards");
            console.log(`Dashboard connected: ${socket.id}`);
        });

        socket.on("disconnect", () => {
            console.log("Disconnected:", socket.id);
        });
    });
}

module.exports = { initSocket };