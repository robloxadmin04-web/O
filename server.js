"use strict";

// O Protector backend: login/session auth + SERVER-SIDE Lua obfuscation.
// The obfuscation engine runs only here, so the browser never sees it. Each
// build can be locked to a per-script key that is validated at runtime through
// /api/verify â€” the closest realistic step toward a Luarmor-style model.

const crypto = require("crypto");
const path = require("path");
const express = require("express");
const engine = require("./obfuscator-engine");

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === "production";

// Render terminates TLS at its proxy, so trust it for req.ip and secure cookies.
app.set("trust proxy", 1);

// --- Configuration ------------------------------------------------------
// Set these as environment variables in Render. Never commit real values.

const SESSION_SECRET =
  process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

if (!process.env.SESSION_SECRET) {
  console.warn(
    "SESSION_SECRET is not set. Using a temporary one; every restart logs users out."
  );
}

const USER_EMAIL = (process.env.LOGIN_EMAIL || "admin@example.com").toLowerCase();
const USER_PASSWORD = process.env.LOGIN_PASSWORD || "changeme123";

const COOKIE_NAME = "o_session";
const SESSION_TTL_MS = 1000 * 60 * 60 * 8; // 8 hours
const MAX_ATTEMPTS = 8;
const ATTEMPT_WINDOW_MS = 1000 * 60 * 10; // 10 minutes

// Public base URL used inside key-locked scripts to call back to /api/verify.
// Set PUBLIC_URL in Render (e.g. https://your-app.onrender.com). When empty,
// key locking still issues a key but the runtime check is skipped (fails open).
const PUBLIC_URL = (process.env.PUBLIC_URL || "").replace(/\/+$/, "");

// --- Password handling --------------------------------------------------

const PASSWORD_SALT = crypto.randomBytes(16);
const PASSWORD_HASH = crypto.scryptSync(USER_PASSWORD, PASSWORD_SALT, 64);

function passwordMatches(candidate) {
  const hash = crypto.scryptSync(String(candidate), PASSWORD_SALT, 64);
  return crypto.timingSafeEqual(hash, PASSWORD_HASH);
}

// --- Session cookie -----------------------------------------------------

function signPayload(payload) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("base64url");
}

function createSessionToken(email) {
  const payload = Buffer.from(
    JSON.stringify({ email: email, exp: Date.now() + SESSION_TTL_MS })
  ).toString("base64url");
  return payload + "." + signPayload(payload);
}

function readSessionToken(token) {
  if (!token || token.indexOf(".") === -1) {
    return null;
  }
  const parts = token.split(".");
  const payload = parts[0];
  const signature = parts[1];
  const expected = signPayload(payload);

  if (signature.length !== expected.length) {
    return null;
  }
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    return null;
  }
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!data.exp || data.exp < Date.now()) {
      return null;
    }
    return data;
  } catch (err) {
    return null;
  }
}

function parseCookies(header) {
  const jar = {};
  if (!header) {
    return jar;
  }
  header.split(";").forEach(function (pair) {
    const index = pair.indexOf("=");
    if (index > 0) {
      jar[pair.slice(0, index).trim()] = decodeURIComponent(
        pair.slice(index + 1).trim()
      );
    }
  });
  return jar;
}

function currentSession(req) {
  return readSessionToken(parseCookies(req.headers.cookie)[COOKIE_NAME]);
}

function requireAuth(req, res, next) {
  const session = currentSession(req);
  if (!session) {
    if (req.path.startsWith("/api/")) {
      return res.status(401).json({ error: "Not signed in." });
    }
    return res.redirect("/");
  }
  req.session = session;
  next();
}

// --- Rate limiting (in memory, per instance) ----------------------------

const attempts = new Map();

function tooManyAttempts(ip) {
  const now = Date.now();
  const record = attempts.get(ip);
  if (!record || now - record.first > ATTEMPT_WINDOW_MS) {
    attempts.set(ip, { count: 1, first: now });
    return false;
  }
  record.count += 1;
  return record.count > MAX_ATTEMPTS;
}

function clearAttempts(ip) {
  attempts.delete(ip);
}

// --- Key store (in memory, per instance) --------------------------------
// Maps issued key -> { email, created }. Cleared on restart. For durable keys,
// swap this for a database or a signed-key scheme.

const issuedKeys = new Map();

function issueKey(email) {
  const key = engine.makeKey();
  issuedKeys.set(key, { email: email, created: Date.now() });
  return key;
}

// --- Middleware ---------------------------------------------------------

app.use(express.json({ limit: "256kb" })); // larger: obfuscation payloads
app.use(express.static(path.join(__dirname, "public")));

// --- Auth routes --------------------------------------------------------

app.post("/api/login", function (req, res) {
  const ip = req.ip || "unknown";

  if (tooManyAttempts(ip)) {
    return res
      .status(429)
      .json({ error: "Too many attempts. Try again in a few minutes." });
  }

  const email = String((req.body && req.body.email) || "").trim().toLowerCase();
  const password = String((req.body && req.body.password) || "");

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  const emailOk = email === USER_EMAIL;
  const passwordOk = passwordMatches(password);

  if (!emailOk || !passwordOk) {
    return res.status(401).json({ error: "Incorrect email or password." });
  }

  clearAttempts(ip);

  res.cookie(COOKIE_NAME, createSessionToken(email), {
    httpOnly: true,
    sameSite: "lax",
    secure: IS_PROD,
    path: "/",
    maxAge: SESSION_TTL_MS
  });

  res.json({ ok: true, redirect: "/dashboard" });
});

app.post("/api/logout", function (req, res) {
  res.clearCookie(COOKIE_NAME, { path: "/" });
  res.json({ ok: true });
});

app.get("/api/me", requireAuth, function (req, res) {
  res.json({ email: req.session.email });
});

// --- Obfuscation route (protected) --------------------------------------
// Body: { source: string, options?: {...}, lockKey?: boolean }
// Returns: { ok, output, key?, chars }

app.post("/api/obfuscate", requireAuth, function (req, res) {
  const source = String((req.body && req.body.source) || "");
  if (!source.trim()) {
    return res.status(400).json({ error: "Provide some Lua source to protect." });
  }
  if (source.length > 200000) {
    return res.status(413).json({ error: "Script too large (200KB max)." });
  }

  const raw = (req.body && req.body.options) || {};
  const options = {
    renameLocals: raw.renameLocals !== false,
    encodeStrings: raw.encodeStrings !== false,
    mangleNumbers: raw.mangleNumbers !== false,
    injectJunk: raw.injectJunk !== false,
    antiTamper: raw.antiTamper !== false,
    minify: raw.minify !== false,
    watermark: typeof raw.watermark === "string" ? raw.watermark : "Protected by O Protector"
  };

  let key = null;
  if (req.body && req.body.lockKey) {
    key = issueKey(req.session.email);
    options.keyInfo = {
      key: key,
      verifyUrl: PUBLIC_URL ? PUBLIC_URL + "/api/verify" : ""
    };
  }

  try {
    const output = engine.obfuscate(source, options);
    res.json({ ok: true, output: output, key: key, chars: output.length });
  } catch (err) {
    res.status(500).json({ error: "Obfuscation failed: " + err.message });
  }
});

// --- Key validation callback (public) -----------------------------------
// Called by key-locked scripts at runtime. Returns { valid: true|false }.
// Public on purpose: the running script has no session cookie.

app.get("/api/verify", function (req, res) {
  const key = String(req.query.key || "");
  const valid = issuedKeys.has(key);
  res.json({ valid: valid });
});

// --- Pages --------------------------------------------------------------

app.get("/dashboard", requireAuth, function (req, res) {
  res.sendFile(path.join(__dirname, "views", "dashboard.html"));
});

app.get("/healthz", function (req, res) {
  res.type("text").send("ok");
});

app.use(function (req, res) {
  res.status(404).type("text").send("Not found");
});

app.listen(PORT, function () {
  console.log("Server listening on port " + PORT);
});
