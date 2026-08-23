const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 10000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const ROOT = __dirname;
const DB = path.join(ROOT, "keys.json");

// Session tồn tại 30 phút.
// Có thể đổi nếu muốn.
const SESSION_TTL = 30 * 60 * 1000;

if (!ADMIN_PASSWORD) {
  console.error("ERROR: ADMIN_PASSWORD is not configured.");
  process.exit(1);
}

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Methods",
    "GET,POST,PATCH,DELETE,OPTIONS"
  );
  res.header(
    "Access-Control-Allow-Headers",
    "Content-Type, x-admin-password, Authorization"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

app.use(express.json({ limit: "1mb" }));

/* =========================
   DATABASE
========================= */

function loadKeys() {
  try {
    if (!fs.existsSync(DB)) return [];

    const data = JSON.parse(
      fs.readFileSync(DB, "utf8")
    );

    return Array.isArray(data) ? data : [];
  } catch (error) {
    console.error("Database error:", error);
    return [];
  }
}

function saveKeys(keys) {
  fs.writeFileSync(
    DB,
    JSON.stringify(keys, null, 2),
    "utf8"
  );
}

/* =========================
   KEY
========================= */

function makeKey() {
  const part = () =>
    crypto
      .randomBytes(2)
      .toString("hex")
      .toUpperCase();

  return `HK-${part()}-${part()}-${part()}`;
}

function expiration(type, custom) {
  const now = Date.now();

  const map = {
    "1h": 3600000,
    "6h": 21600000,
    "12h": 43200000,
    "1d": 86400000,
    "3d": 259200000,
    "7d": 604800000,
    "14d": 1209600000,
    "30d": 2592000000,
    "3m": 7776000000,
    "6m": 15552000000,
    "1y": 31536000000
  };

  if (type === "forever") return null;

  if (type === "custom") {
    const timestamp = new Date(custom).getTime();

    if (!Number.isFinite(timestamp)) {
      return null;
    }

    return new Date(timestamp).toISOString();
  }

  return new Date(
    now + (map[type] || map["30d"])
  ).toISOString();
}

/* =========================
   ADMIN AUTH
========================= */

function adminAuth(req, res, next) {
  const supplied = req.headers["x-admin-password"];

  if (!supplied || supplied !== ADMIN_PASSWORD) {
    return res.status(401).json({
      error: "Unauthorized"
    });
  }

  next();
}

/* =========================
   COMMON KEY CHECK
========================= */

function findValidKey(input, deviceId) {
  if (!input) {
    return {
      ok: false,
      status: 400,
      code: "KEY_REQUIRED",
      message: "Key is required"
    };
  }

  if (!deviceId) {
    return {
      ok: false,
      status: 400,
      code: "DEVICE_REQUIRED",
      message: "Device ID is required"
    };
  }

  const keys = loadKeys();

  const key = keys.find(
    x =>
      String(x.key).trim().toUpperCase() === input
  );

  if (!key) {
    return {
      ok: false,
      status: 404,
      code: "INVALID_KEY",
      message: "Invalid key"
    };
  }

  if (key.disabled) {
    return {
      ok: false,
      status: 403,
      code: "KEY_DISABLED",
      message: "Key is disabled"
    };
  }

  if (
    key.expiresAt !== null &&
    key.expiresAt &&
    Date.now() >= new Date(key.expiresAt).getTime()
  ) {
    return {
      ok: false,
      status: 403,
      code: "KEY_EXPIRED",
      message: "Key expired"
    };
  }

  if (key.deviceId && key.deviceId !== deviceId) {
    return {
      ok: false,
      status: 403,
      code: "DEVICE_MISMATCH",
      message: "Key is already activated on another device"
    };
  }

  return {
    ok: true,
    key,
    keys
  };
}

/* =========================
   SESSION
========================= */

function createSession(key, deviceId) {
  const token = crypto.randomBytes(32).toString("hex");

  return {
    token,
    keyId: key.id,
    deviceId,
    expiresAt: Date.now() + SESSION_TTL
  };
}

function getBearerToken(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.slice(7).trim();
}

/*
  Session lưu trong RAM.
  Restart Render sẽ xóa session cũ.
  Người dùng phải kích hoạt lại.
*/
const sessions = new Map();

function requireSession(req, res, next) {
  const token = getBearerToken(req);

  if (!token) {
    return res.status(401).json({
      valid: false,
      code: "SESSION_REQUIRED",
      message: "Valid session required"
    });
  }

  const session = sessions.get(token);

  if (!session) {
    return res.status(401).json({
      valid: false,
      code: "SESSION_INVALID",
      message: "Session is invalid"
    });
  }

  if (Date.now() >= session.expiresAt) {
    sessions.delete(token);

    return res.status(401).json({
      valid: false,
      code: "SESSION_EXPIRED",
      message: "Session expired"
    });
  }

  const keys = loadKeys();

  const key = keys.find(
    x => x.id === session.keyId
  );

  if (!key || key.disabled) {
    sessions.delete(token);

    return res.status(403).json({
      valid: false,
      code: "KEY_DISABLED",
      message: "Key is no longer valid"
    });
  }

  if (
    key.expiresAt !== null &&
    key.expiresAt &&
    Date.now() >= new Date(key.expiresAt).getTime()
  ) {
    sessions.delete(token);

    return res.status(403).json({
      valid: false,
      code: "KEY_EXPIRED",
      message: "Key expired"
    });
  }

  if (key.deviceId !== session.deviceId) {
    sessions.delete(token);

    return res.status(403).json({
      valid: false,
      code: "DEVICE_MISMATCH",
      message: "Device mismatch"
    });
  }

  req.session = session;
  req.key = key;

  next();
}

/* =========================
   ADMIN: LIST
========================= */

app.get("/api/keys", adminAuth, (req, res) => {
  res.json(loadKeys());
});

/* =========================
   ADMIN: CREATE
========================= */

app.post("/api/keys", adminAuth, (req, res) => {
  const keys = loadKeys();

  const type =
    String(req.body.duration || "30d");

  const key = {
    id: crypto.randomUUID(),
    key: makeKey(),
    createdAt: new Date().toISOString(),
    expiresAt: expiration(
      type,
      req.body.custom
    ),
    disabled: false,
    deviceId: null,
    boundAt: null
  };

  keys.push(key);
  saveKeys(keys);

  res.json(key);
});

/* =========================
   ADMIN: UPDATE
========================= */

app.patch("/api/keys/:id", adminAuth, (req, res) => {
  const keys = loadKeys();

  const key = keys.find(
    x => x.id === req.params.id
  );

  if (!key) {
    return res.status(404).json({
      error: "Key not found"
    });
  }

  if (
    Object.prototype.hasOwnProperty.call(
      req.body,
      "disabled"
    )
  ) {
    key.disabled = Boolean(req.body.disabled);
  }

  if (req.body.resetDevice === true) {
    key.deviceId = null;
    key.boundAt = null;
  }

  // Nếu admin khóa hoặc reset device,
  // xóa session liên quan.
  for (const [token, session] of sessions) {
    if (session.keyId === key.id) {
      sessions.delete(token);
    }
  }

  saveKeys(keys);

  res.json(key);
});

/* =========================
   ADMIN: DELETE
========================= */

app.delete("/api/keys/:id", adminAuth, (req, res) => {
  const keys = loadKeys();

  const filtered = keys.filter(
    x => x.id !== req.params.id
  );

  for (const [token, session] of sessions) {
    if (session.keyId === req.params.id) {
      sessions.delete(token);
    }
  }

  saveKeys(filtered);

  res.json({
    ok: true
  });
});

/* =========================
   ACTIVATE
========================= */

app.post("/api/activate", (req, res) => {
  const input =
    String(req.body.key || "")
      .trim()
      .toUpperCase();

  const deviceId =
    String(req.body.deviceId || "").trim();

  const result = findValidKey(
    input,
    deviceId
  );

  if (!result.ok) {
    return res.status(result.status).json({
      valid: false,
      code: result.code,
      message: result.message
    });
  }

  const { key, keys } = result;

  /*
    Chưa có device:
    bind key vào thiết bị đầu tiên.
  */
  if (!key.deviceId) {
    key.deviceId = deviceId;
    key.boundAt = new Date().toISOString();

    saveKeys(keys);
  }

  const session = createSession(
    key,
    deviceId
  );

  sessions.set(
    session.token,
    session
  );

  return res.json({
    valid: true,
    firstActivation: !key.boundAt
      ? true
      : false,
    deviceBound: true,
    expiresAt: key.expiresAt,
    sessionToken: session.token,
    sessionExpiresAt: new Date(
      session.expiresAt
    ).toISOString()
  });
});

/* =========================
   CHECK KEY
   KHÔNG TẠO SESSION
========================= */

app.post("/api/check", (req, res) => {
  const input =
    String(req.body.key || "")
      .trim()
      .toUpperCase();

  const deviceId =
    String(req.body.deviceId || "").trim();

  const result = findValidKey(
    input,
    deviceId
  );

  if (!result.ok) {
    return res.status(result.status).json({
      valid: false,
      code: result.code,
      message: result.message
    });
  }

  const { key } = result;

  res.json({
    valid: true,
    deviceBound: Boolean(key.deviceId),
    deviceId: key.deviceId || null,
    expiresAt: key.expiresAt
  });
});

/* =========================
   SESSION CHECK
========================= */

app.get("/api/session", requireSession, (req, res) => {
  res.json({
    valid: true,
    expiresAt: req.key.expiresAt,
    sessionExpiresAt: new Date(
      req.session.expiresAt
    ).toISOString()
  });
});

/* =========================
   LOGOUT
========================= */

app.post("/api/logout", requireSession, (req, res) => {
  const token = getBearerToken(req);

  sessions.delete(token);

  res.json({
    ok: true
  });
});

/* =========================
   PROTECTED APP API
========================= */

/*
  Những API thực sự thuộc app chính
  phải đặt requireSession.
*/

app.get("/api/app/access", requireSession, (req, res) => {
  res.json({
    allowed: true,
    product: "AIMHELP OB54",
    deviceId: req.session.deviceId,
    keyExpiresAt: req.key.expiresAt
  });
});

/* =========================
   HEALTH
========================= */

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "hk-key-manager",
    system: "1-key-1-device-session"
  });
});

/* =========================
   START
========================= */

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `HK Key Manager running on ${PORT}`
  );
});
