// ----------------------
// GLOB_AI BACKEND SERVER
// ----------------------

const express = require('express');
const multer = require('multer');
const googleResponse = await fetch(
  `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_API_KEY}`,
  { method: 'POST', ... }
);
const cors = require('cors');
require('dotenv').config();

const app = express();
const upload = multer();

// ✅ Enable CORS for all origins (for frontend use)
app.use(cors());

// ✅ Optional: Middleware to log incoming requests
app.use((req, res, next) => {
  console.log(`📩 ${req.method} ${req.originalUrl}`);
  next();
});

// ✅ Home route to check if server is live
app.get('/', (req, res) => {
  res.send("🧠 GLOB_AI backend is live and ready.");
});

// ✅ Link analysis route
app.post('/analyze-link/', upload.none(), async (req, res) => {
  const link = req.body.link;
  console.log("🔗 Received link:", link);

  if (!link) {
    return res.status(400).json({ safe: null, message: "No link provided." });
  }

  try {
    const googleResponse = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_API_KEY}`,
      {
        method: "POST",
        body: JSON.stringify({
          client: {
            clientId: "glob_ai",
            clientVersion: "1.0"
          },
          threatInfo: {
            threatTypes: [
              "MALWARE",
              "SOCIAL_ENGINEERING",
              "UNWANTED_SOFTWARE",
              "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: link }]
          }
        }),
        headers: {
          "Content-Type": "application/json"
        }
      }
    );

    const result = await googleResponse.json();
    console.log("📬 Google API Response:", JSON.stringify(result, null, 2));

    if (result && result.matches && result.matches.length > 0) {
      console.log("❌ Link is unsafe.");
      res.json({ safe: false });
    } else {
      console.log("✅ Link is safe.");
      res.json({ safe: true });
    }

  } catch (error) {
    console.error("❌ Error analyzing link:", error);
    res.status(500).json({
      safe: null,
      message: "Error while analyzing the link. Please check server logs."
    });
  }
});

// ✅ Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 GLOB_AI backend running on http://localhost:${PORT}`);
});
