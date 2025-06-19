// ----------------------
// GLOB_AI BACKEND SERVER
// ----------------------

const express = require('express');
const multer = require('multer');
const cors = require('cors');
require('dotenv').config();

const app = express();
const upload = multer();

// ✅ Enable CORS for all origins (frontend compatibility)
app.use(cors());

// ✅ Log incoming requests
app.use((req, res, next) => {
  console.log(`📩 ${req.method} ${req.originalUrl}`);
  next();
});

// ✅ Home route to verify server is running
app.get('/', (req, res) => {
  res.send("🧠 GLOB_AI backend is live and ready.");
});

// ✅ Suspicious-looking phishing domain patterns
const suspiciousPatterns = [
  "paypai", "secure-login", "verify-user", "account-update", "login-check",
  ".xyz", ".top", "confirm-details", "update-now", "webscr", "signin"
];

// ✅ Adult & drug keyword detection
const adultOrDrugKeywords = [
  "porn", "xxx", "sex", "camgirl", "nsfw", "redtube", "xvideos",
  "weed", "cocaine", "heroin", "pill", "drugstore", "mdma", "420"
];

function looksSuspicious(link) {
  return suspiciousPatterns.some(pattern => link.toLowerCase().includes(pattern));
}

function isAdultOrDrugLink(link) {
  return adultOrDrugKeywords.some(word => link.toLowerCase().includes(word));
}

// ✅ Analyze link route
app.post('/analyze-link/', upload.none(), async (req, res) => {
  const link = req.body.link;
  console.log("🔗 Received link:", link);

  if (!link) {
    return res.status(400).json({ safe: null, message: "No link provided." });
  }

  // 🔎 Custom adult/drug filter
  if (isAdultOrDrugLink(link)) {
    console.log("🚫 Detected adult/drug keyword in link.");
    return res.json({ safe: false, reason: "Blocked: adult or drug-related content" });
  }

  // 🔎 Custom suspicious domain pattern check
  if (looksSuspicious(link)) {
    console.log("🚨 Custom rule triggered: suspicious-looking URL");
    return res.json({ safe: false, reason: "Blocked: suspicious domain pattern" });
  }

  // ✅ Google Safe Browsing API check
  try {
    const googleResponse = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_API_KEY}`,
      {
        method: "POST",
        body: JSON.stringify({
          client: { clientId: "glob_ai", clientVersion: "1.0" },
          threatInfo: {
            threatTypes: [
              "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: link }]
          }
        }),
        headers: { "Content-Type": "application/json" }
      }
    );

    const result = await googleResponse.json();
    console.log("📬 Google API Response:", JSON.stringify(result, null, 2));

    if (result && result.matches && result.matches.length > 0) {
      console.log("❌ Google flagged this link.");
      return res.json({ safe: false, reason: "Blocked by Google Safe Browsing" });
    }

    console.log("✅ Link is safe.");
    res.json({ safe: true });

  } catch (error) {
    console.error("❌ Error analyzing link:", error);
    res.status(500).json({
      safe: null,
      message: "Error while analyzing the link. Please check server logs."
    });
  }
});

// ✅ Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 GLOB_AI backend running on http://localhost:${PORT}`);
});
