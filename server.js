const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 10000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const ROOT = __dirname;
const DB = path.join(ROOT, "keys.json");

/*
  File app được bảo vệ.
  Không được để express.static phục vụ trực tiếp file này.
*/
const APP_FILE = "donhayhoangkhoiv2vip.html";

if (!ADMIN_PASSWORD) {
  console.error("ERROR: ADMIN_PASSWORD chưa được cấu hình trên Render.");
  process.exit(1);
}

app.use(express.json({ limit: "1mb" }));

/* =====================================================
   DATABASE
===================================================== */

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

/* =====================================================
   KEY
===================================================== */

function makeKey() {
  const part = () =>
    crypto
      .randomBytes(2)
      .toString("hex")
      .toUpperCase();

  return `HK-${part()}-${part()}-${part()}`;
}

function getExpiration(type, custom) {
  const now = Date.now();

  const durations = {
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
    const date = new Date(custom);

    if (Number.isNaN(date.getTime())) {
      return new Date(
        now + durations["30d"]
      ).toISOString();
    }

    return date.toISOString();
  }

  return new Date(
    now + (durations[type] || durations["30d"])
  ).toISOString();
}

/* =====================================================
   DEVICE ID
===================================================== */

function cleanDeviceId(value) {
  return String(value || "").trim();
}

/* =====================================================
   SESSION
===================================================== */

/*
  Session nằm trong RAM.

  Render restart/redeploy thì session cũ sẽ mất,
  người dùng chỉ cần nhập key lại.
*/
const sessions = new Map();

const SESSION_TIME = 1000 * 60 * 60 * 24;

function createSession(keyId, deviceId) {
  const token =
    crypto.randomBytes(32).toString("hex");

  sessions.set(token, {
    keyId,
    deviceId,
    createdAt: Date.now(),
    expiresAt:
      Date.now() + SESSION_TIME
  });

  return token;
}

function getCookie(req, name) {
  const header = req.headers.cookie || "";

  const cookies = {};

  header.split(";").forEach(item => {
    const index = item.indexOf("=");

    if (index === -1) return;

    const key =
      item.slice(0, index).trim();

    const value =
      item.slice(index + 1).trim();

    cookies[key] = decodeURIComponent(value);
  });

  return cookies[name];
}

function getSession(req) {
  const token =
    getCookie(req, "hk_session");

  if (!token) return null;

  const session =
    sessions.get(token);

  if (!session) return null;

  if (
    Date.now() >
    session.expiresAt
  ) {
    sessions.delete(token);
    return null;
  }

  return {
    token,
    ...session
  };
}

/* =====================================================
   ADMIN AUTH
===================================================== */

function adminAuth(req, res, next) {
  const password =
    req.headers["x-admin-password"];

  if (
    !password ||
    password !== ADMIN_PASSWORD
  ) {
    return res.status(401).json({
      error: "Unauthorized"
    });
  }

  next();
}

/* =====================================================
   ADMIN API
===================================================== */

app.get(
  "/api/keys",
  adminAuth,
  (req, res) => {
    res.json(loadKeys());
  }
);

app.post(
  "/api/keys",
  adminAuth,
  (req, res) => {

    const keys = loadKeys();

    const duration =
      String(
        req.body.duration || "30d"
      );

    const key = {
      id: crypto.randomUUID(),

      key: makeKey(),

      createdAt:
        new Date().toISOString(),

      expiresAt:
        getExpiration(
          duration,
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

app.patch(
  "/api/keys/:id",
  adminAuth,
  (req, res) => {

    const keys = loadKeys();

    const key =
      keys.find(
        item =>
          item.id === req.params.id
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

    /*
      Admin có thể reset thiết bị.
    */
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

app.delete(
  "/api/keys/:id",
  adminAuth,
  (req, res) => {

    const keys = loadKeys();

    const filtered =
      keys.filter(
        item =>
          item.id !== req.params.id
      );

    saveKeys(filtered);

    res.json({
      ok: true
    });
  }
);

/* =====================================================
   VERIFY KEY
===================================================== */

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
      cleanDeviceId(
        req.body.deviceId
      );

    if (!input) {
      return res.status(400).json({
        valid: false,
        code: "KEY_REQUIRED",
        message: "Vui lòng nhập key"
      });
    }

    if (!deviceId) {
      return res.status(400).json({
        valid: false,
        code: "DEVICE_REQUIRED",
        message: "Không xác định được thiết bị"
      });
    }

    const keys = loadKeys();

    const key =
      keys.find(
        item =>
          String(item.key)
            .toUpperCase() === input
      );

    if (!key) {
      return res.status(404).json({
        valid: false,
        code: "INVALID_KEY",
        message: "Key không tồn tại"
      });
    }

    if (key.disabled) {
      return res.status(403).json({
        valid: false,
        code: "KEY_DISABLED",
        message: "Key đã bị khóa"
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
        message: "Key đã hết hạn"
      });
    }

    /*
      KEY CHƯA CÓ DEVICE
      => khóa vào thiết bị đầu tiên.
    */

    let firstActivation = false;

    if (!key.deviceId) {

      key.deviceId =
        deviceId;

      key.boundAt =
        new Date().toISOString();

      saveKeys(keys);

      firstActivation = true;

    } else if (
      key.deviceId !== deviceId
    ) {

      /*
        KEY ĐÃ THUỘC THIẾT BỊ KHÁC
      */

      return res.status(403).json({
        valid: false,
        code: "DEVICE_MISMATCH",
        message:
          "Key đã được kích hoạt trên thiết bị khác"
      });
    }

    /*
      Tạo session.
    */

    const token =
      createSession(
        key.id,
        deviceId
      );

    /*
      Cookie HttpOnly:
      JavaScript bên ngoài không đọc được.
    */

    res.setHeader(
      "Set-Cookie",
      [
        `hk_session=${encodeURIComponent(token)}`,
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=86400",
        "Secure"
      ].join("; ")
    );

    /*
      Trả thông tin key cho key.html
      để hiển thị key + hạn sử dụng.
    */

    return res.json({
      valid: true,

      firstActivation,

      key: key.key,

      expiresAt:
        key.expiresAt,

      deviceBound: true,

      sessionCreated: true
    });
  }
);

/* =====================================================
   SESSION INFO
===================================================== */

app.get(
  "/api/session",
  (req, res) => {

    const session =
      getSession(req);

    if (!session) {
      return res.status(401).json({
        authenticated: false
      });
    }

    const keys =
      loadKeys();

    const key =
      keys.find(
        item =>
          item.id ===
          session.keyId
      );

    if (!key) {
      return res.status(401).json({
        authenticated: false
      });
    }

    if (key.disabled) {
      return res.status(403).json({
        authenticated: false,
        code: "KEY_DISABLED"
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
        authenticated: false,
        code: "KEY_EXPIRED"
      });
    }

    if (
      key.deviceId !==
      session.deviceId
    ) {
      return res.status(403).json({
        authenticated: false,
        code: "DEVICE_MISMATCH"
      });
    }

    res.json({
      authenticated: true,
      key: key.key,
      expiresAt:
        key.expiresAt
    });
  }
);

/* =====================================================
   LOGOUT
===================================================== */

app.post(
  "/api/logout",
  (req, res) => {

    const session =
      getSession(req);

    if (session) {
      sessions.delete(
        session.token
      );
    }

    res.setHeader(
      "Set-Cookie",
      "hk_session=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax; Secure"
    );

    res.json({
      ok: true
    });
  }
);

/* =====================================================
   HEALTH
===================================================== */

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      ok: true,
      service: "hk-key-manager",
      system: "1-key-1-device",
      sessionProtection: true
    });
  }
);

/* =====================================================
   PROTECTED APP
===================================================== */

/*
  QUAN TRỌNG:

  Route này phải nằm TRƯỚC express.static.

  Người không có session sẽ bị đưa về key.html.
*/

app.get(
  `/${APP_FILE}`,
  (req, res) => {

    const session =
      getSession(req);

    if (!session) {
      return res.redirect(
        "/key.html?login=required"
      );
    }

    const keys = loadKeys();

    const key =
      keys.find(
        item =>
          item.id ===
          session.keyId
      );

    if (!key) {
      return res.redirect(
        "/key.html?session=invalid"
      );
    }

    if (key.disabled) {
      return res.redirect(
        "/key.html?session=disabled"
      );
    }

    if (
      key.expiresAt !== null &&
      key.expiresAt &&
      Date.now() >=
        new Date(
          key.expiresAt
        ).getTime()
    ) {
      return res.redirect(
        "/key.html?session=expired"
      );
    }

    if (
      key.deviceId !==
      session.deviceId
    ) {
      return res.redirect(
        "/key.html?session=device"
      );
    }

    /*
      Session hợp lệ.
      Mới trả file app.
    */

    return res.sendFile(
      path.join(
        ROOT,
        APP_FILE
      )
    );
  }
);

/* =====================================================
   STATIC FILES
===================================================== */

/*
  Chặn express.static phục vụ APP_FILE.
  Nếu không có đoạn này, người dùng có thể bypass
  route bảo vệ ở trên.
*/

app.use(
  (req, res, next) => {

    if (
      req.path ===
      `/${APP_FILE}`
    ) {
      return res.redirect(
        "/key.html?login=required"
      );
    }

    next();
  }
);

app.use(
  express.static(ROOT, {
    index: false
  })
);

/* =====================================================
   START
===================================================== */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `HK Key Manager listening on ${PORT}`
    );
  }
);
