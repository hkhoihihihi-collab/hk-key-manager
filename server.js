const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "CHANGE_ME_NOW";
const DB = path.join(__dirname, "keys.json");

app.use(express.json());
app.use(express.static(__dirname));

function load() {
  try {
    return JSON.parse(fs.readFileSync(DB, "utf8"));
  } catch {
    return [];
  }
}

function save(data) {
  fs.writeFileSync(DB, JSON.stringify(data, null, 2));
}

function makeKey() {
  const p = () => crypto.randomBytes(2).toString("hex").toUpperCase();
  return `HK-${p()}-${p()}-${p()}`;
}

function duration(type, custom) {
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
    const time = new Date(custom).getTime();
    return Number.isFinite(time) ? new Date(time).toISOString() : null;
  }

  return new Date(now + (map[type] || 86400000)).toISOString();
}

function auth(req, res, next) {
  if (req.headers["x-admin-password"] !== ADMIN_PASSWORD) {
    return res.status(401).json({
      error: "Unauthorized"
    });
  }

  next();
}

/* =========================
   ADMIN
========================= */

app.get("/api/keys", auth, (req, res) => {
  res.json(load());
});

app.post("/api/keys", auth, (req, res) => {
  const keys = load();

  const key = {
    id: crypto.randomUUID(),
    key: makeKey(),
    createdAt: new Date().toISOString(),

    expiresAt: duration(
      req.body.duration || "30d",
      req.body.custom
    ),

    disabled: false,

    // Chưa có thiết bị nào sử dụng
    deviceId: null,

    // App được phép sử dụng key
    appId: String(req.body.appId || "all").trim()
  };

  keys.push(key);
  save(keys);

  res.json(key);
});

app.patch("/api/keys/:id", auth, (req, res) => {
  const keys = load();

  const k = keys.find(
    x => x.id === req.params.id
  );

  if (!k) {
    return res.status(404).json({
      error: "Not found"
    });
  }

  if ("disabled" in req.body) {
    k.disabled = !!req.body.disabled;
  }

  /*
   * Admin có thể reset thiết bị của key
   * bằng:
   * { "resetDevice": true }
   */
  if (req.body.resetDevice === true) {
    k.deviceId = null;
  }

  save(keys);

  res.json(k);
});

app.delete("/api/keys/:id", auth, (req, res) => {
  const keys = load().filter(
    x => x.id !== req.params.id
  );

  save(keys);

  res.json({
    ok: true
  });
});

/* =========================
   VERIFY KEY
========================= */

app.post("/api/verify", (req, res) => {
  const inputKey = String(
    req.body.key || ""
  ).trim();

  const deviceId = String(
    req.body.deviceId || ""
  ).trim();

  const appId = String(
    req.body.appId || "all"
  ).trim();

  if (!inputKey) {
    return res.status(400).json({
      valid: false,
      code: "KEY_REQUIRED",
      message: "Key is required"
    });
  }

  if (!deviceId) {
    return res.status(400).json({
      valid: false,
      code: "DEVICE_REQUIRED",
      message: "Device ID is required"
    });
  }

  const keys = load();

  const k = keys.find(
    x => x.key === inputKey
  );

  if (!k) {
    return res.status(404).json({
      valid: false,
      code: "INVALID_KEY",
      message: "Invalid key"
    });
  }

  if (k.disabled) {
    return res.status(403).json({
      valid: false,
      code: "KEY_DISABLED",
      message: "Key is disabled"
    });
  }

  if (
    k.expiresAt !== null &&
    Date.now() >= new Date(k.expiresAt).getTime()
  ) {
    return res.status(403).json({
      valid: false,
      code: "KEY_EXPIRED",
      message: "Key expired"
    });
  }

  /*
   * Kiểm tra App ID
   */
  if (
    k.appId &&
    k.appId !== "all" &&
    k.appId !== appId
  ) {
    return res.status(403).json({
      valid: false,
      code: "APP_NOT_ALLOWED",
      message: "Key is not allowed for this app"
    });
  }

  /*
   * KEY CHƯA TỪNG GẮN THIẾT BỊ
   * → khóa vào thiết bị đầu tiên
   */
  if (!k.deviceId) {
    k.deviceId = deviceId;
    k.boundAt = new Date().toISOString();

    save(keys);

    return res.json({
      valid: true,
      firstActivation: true,
      message: "Key activated successfully",
      expiresAt: k.expiresAt
    });
  }

  /*
   * ĐÚNG THIẾT BỊ ĐÃ ĐĂNG KÝ
   */
  if (k.deviceId === deviceId) {
    return res.json({
      valid: true,
      firstActivation: false,
      message: "Key verified",
      expiresAt: k.expiresAt
    });
  }

  /*
   * THIẾT BỊ KHÁC
   */
  return res.status(403).json({
    valid: false,
    code: "DEVICE_MISMATCH",
    message: "Key is already activated on another device"
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "hk-key-manager"
  });
});

app.listen(
  PORT,
  "0.0.0.0",
  () => console.log(`Listening on ${PORT}`)
);
