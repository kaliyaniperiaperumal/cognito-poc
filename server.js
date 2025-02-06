require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const authRoutes = require("./authRoutes");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());

// Routes
app.use("/auth", authRoutes);

// Health check endpoint
app.get("/", (req, res) => {
  res.send("AWS Cognito Auth API is running");
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
