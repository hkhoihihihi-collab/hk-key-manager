const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 10000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const ROOT = __dirname;
const DB = path.join(ROOT, "keys.json");

if (!ADMIN_PASSWORD) {
  console.error("ERROR: ADMIN_PASSWORD is not configured.");
  process.exit(1);
}

app.use(express.json({ limit: "1mb" }));
app.use(express.static(ROOT));

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
   KEY GENERATOR
========================= */

function makeKey() {
  const part = () =>
    crypto
      .randomBytes(2)
      .toString("hex")
      .toUpperCase();

  return `HK-${part()}-${part()}-${part()}`;
}

/* =========================
   EXPIRATION
========================= */

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

  if (type === "forever") {
    return null;
  }

  if (type === "custom") {
    const timestamp =
      new Date(custom).getTime();

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
  const supplied =
    req.headers["x-admin-password"];

  if (
    !supplied ||
    supplied !== ADMIN_PASSWORD
  ) {
    return res.status(401).json({
      error: "Unauthorized"
    });
  }

  next();
}

/* =========================
   ADMIN: LIST
========================= */

app.get(
  "/api/keys",
  adminAuth,
  (req, res) => {
    res.json(loadKeys());
  }
);

/* =========================
   ADMIN: CREATE
========================= */

app.post(
  "/api/keys",
  adminAuth,
  (req, res) => {
    const keys = loadKeys();

    const type =
      String(
        req.body.duration || "30d"
      );

    const key = {
      id: crypto.randomUUID(),

      key: makeKey(),

      createdAt:
        new Date().toISOString(),

      expiresAt:
        expiration(
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
  }
);

/* =========================
   ADMIN: UPDATE
========================= */

app.patch(
  "/api/keys/:id",
  adminAuth,
  (req, res) => {
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
      key.disabled =
        Boolean(req.body.disabled);
    }

    if (
      req.body.resetDevice === true
    ) {
      key.deviceId = null;
      key.boundAt = null;
    }

    saveKeys(keys);

    res.json(key);
  }
);

/* =========================
   ADMIN: DELETE
========================= */

app.delete(
  "/api/keys/:id",
  adminAuth,
  (req, res) => {
    const keys = loadKeys();

    const filtered =
      keys.filter(
        x => x.id !== req.params.id
      );

    saveKeys(filtered);

    res.json({
      ok: true
    });
  }
);

/* =========================
   VERIFY KEY
========================= */

app.post(
  "/api/verify",
  (req, res) => {

    const input =
      String(
        req.body.key || ""
      )
      .trim()
      .toUpperCase();

    const deviceId =
      String(
        req.body.deviceId || ""
      ).trim();

    if (!input) {
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

    const keys = loadKeys();

    const key =
      keys.find(
        x =>
          String(x.key)
            .trim()
            .toUpperCase() === input
      );

    if (!key) {
      return res.status(404).json({
        valid: false,
        code: "INVALID_KEY",
        message: "Invalid key"
      });
    }

    if (key.disabled) {
      return res.status(403).json({
        valid: false,
        code: "KEY_DISABLED",
        message: "Key is disabled"
      });
    }

    if (
      key.expiresAt !== null &&
      key.expiresAt &&
      Date.now() >=
        new Date(
          key.expiresAt
        ).getTime()
    ) {
      return res.status(403).json({
        valid: false,
        code: "KEY_EXPIRED",
        message: "Key expired"
      });
    }

    /*
      KEY CHƯA GẮN DEVICE
      => thiết bị đầu tiên được đăng ký
    */

    if (!key.deviceId) {

      key.deviceId =
        deviceId;

      key.boundAt =
        new Date().toISOString();

      saveKeys(keys);

      return res.json({
        valid: true,
        firstActivation: true,
        deviceBound: true,
        expiresAt: key.expiresAt
      });
    }

    /*
      ĐÚNG DEVICE
    */

    if (
      key.deviceId === deviceId
    ) {
      return res.json({
        valid: true,
        firstActivation: false,
        deviceBound: true,
        expiresAt: key.expiresAt
      });
    }

    /*
      DEVICE KHÁC
    */

    return res.status(403).json({
      valid: false,
      code: "DEVICE_MISMATCH",
      message:
        "Key is already activated on another device"
    });
  }
);

/* =========================
   HEALTH
========================= */

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      ok: true,
      service: "hk-key-manager",
      system: "1-key-1-device"
    });
  }
);

/* =========================
   START
========================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `HK Key Manager running on ${PORT}`
    );
  }
);
