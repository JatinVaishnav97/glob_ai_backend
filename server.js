// ----------------------
// GLOB_AI BACKEND SERVER
// ----------------------

const express = require('express');
const multer = require('multer');
const fetch = require('node-fetch');
const cors = require('cors');
require('dotenv').config();

const app = express();
const upload = multer();

// ✅ Enable CORS for all routes (important for frontend)
app.use(cors());

// ✅ Root route (optional for browser test)
app.get('/', (req, res) => {
  res.send("🧠 GLOB_AI backend is running");
});

// ✅ Analyze link route
app.post('/analyze-link/', upload.none(), async (req, res) => {
  const link = req.body.link;

  // Log incoming link
  console.log("🔗 Received link:", link);

  if (!link) {
    console.log("⚠️ No link provided in request");
    return res.json({ safe: null, message: "No link provided." });
  }

  try {
    // Prepare Google Safe Browsing API request
    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_API_KEY}`, {
      method: "POST",
      body: JSON.stringify({
        client: { clientId: "glob_ai", clientVersion: "1.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: link }]
        }
      }),
      headers: { "Content-Type": "application/json" }
    });

    const result = await response.json();

    // Log Google response
    console.log("📬 Google API Response:", JSON.stringify(result, null, 2));

    if (result && result.matches && result.matches.length > 0) {
      console.log("❌ Link is unsafe!");
      res.json({ safe: false });
    } else {
      console.log("✅ Link is safe");
      res.json({ safe: true });
    }

  } catch (err) {
    console.error("❌ Error contacting Google API:", err);
    res.json({ safe: null, message: "Error while analyzing the link." });
  }
});

// ✅ Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 GLOB_AI backend running at http://localhost:${PORT}`);
});
