const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 10000;
const ROOT = __dirname;
const DB_FILE = path.join(ROOT, "keys.json");

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!ADMIN_PASSWORD) {
  console.error("ADMIN_PASSWORD is not configured.");
  process.exit(1);
}

app.use(express.json({ limit: "1mb" }));

/* =========================
   CORS
========================= */

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET,POST,PATCH,DELETE,OPTIONS"
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, x-admin-password, Authorization"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

/* =========================
   STATIC ADMIN PANEL
========================= */

app.use(express.static(ROOT));

/* =========================
   DATABASE
========================= */

function loadKeys() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      fs.writeFileSync(DB_FILE, "[]", "utf8");
      return [];
    }

    const raw = fs.readFileSync(DB_FILE, "utf8").trim();

    if (!raw) {
      return [];
    }

    const data = JSON.parse(raw);

    return Array.isArray(data) ? data : [];
  } catch (err) {
    console.error("loadKeys:", err);
    return [];
  }
}

function saveKeys(keys) {
  const tempFile = DB_FILE + ".tmp";

  fs.writeFileSync(
    tempFile,
    JSON.stringify(keys, null, 2),
    "utf8"
  );

  fs.renameSync(tempFile, DB_FILE);
}

/* =========================
   HELPERS
========================= */

function makeKey() {
  const part = () =>
    crypto.randomBytes(2).toString("hex").toUpperCase();

  return `HK-${part()}-${part()}-${part()}`;
}

function createId() {
  return crypto.randomUUID();
}

function expiration(duration, custom) {
  const now = Date.now();

  const durations = {
    "1h": 1 * 60 * 60 * 1000,
    "6h": 6 * 60 * 60 * 1000,
    "12h": 12 * 60 * 60 * 1000,
    "1d": 1 * 24 * 60 * 60 * 1000,
    "3d": 3 * 24 * 60 * 60 * 1000,
    "7d": 7 * 24 * 60 * 60 * 1000,
    "14d": 14 * 24 * 60 * 60 * 1000,
    "30d": 30 * 24 * 60 * 60 * 1000,
    "3m": 90 * 24 * 60 * 60 * 1000,
    "6m": 180 * 24 * 60 * 60 * 1000,
    "1y": 365 * 24 * 60 * 60 * 1000
  };

  if (duration === "forever") {
    return null;
  }

  if (duration === "custom") {
    const timestamp = new Date(custom).getTime();

    if (!Number.isFinite(timestamp)) {
      return null;
    }

    return new Date(timestamp).toISOString();
  }

  const ms =
    durations[duration] ||
    durations["30d"];

  return new Date(now + ms).toISOString();
}

function isKeyExpired(key) {
  if (!key.expiresAt) {
    return false;
  }

  const timestamp =
    new Date(key.expiresAt).getTime();

  if (!Number.isFinite(timestamp)) {
    return false;
  }

  return Date.now() >= timestamp;
}

/* =========================
   ADMIN AUTH
========================= */

function adminAuth(req, res, next) {
  const password =
    req.headers["x-admin-password"];

  if (
    typeof password !== "string" ||
    password !== ADMIN_PASSWORD
  ) {
    return res.status(401).json({
      error: "Unauthorized"
    });
  }

  next();
}

/* =========================
   ADMIN: GET KEYS
========================= */

app.get(
  "/api/keys",
  adminAuth,
  (req, res) => {
    res.json(loadKeys());
  }
);

/* =========================
   ADMIN: CREATE KEY
========================= */

app.post(
  "/api/keys",
  adminAuth,
  (req, res) => {
    const keys = loadKeys();

    const duration =
      String(
        req.body.duration || "30d"
      );

    const custom =
      req.body.custom || "";

    const appId =
      String(
        req.body.appId || "all"
      ).trim() || "all";

    const key = {
      id: createId(),

      key: makeKey(),

      appId,

      createdAt:
        new Date().toISOString(),

      expiresAt:
        expiration(
          duration,
          custom
        ),

      disabled: false,

      deviceId: null,

      boundAt: null
    };

    keys.push(key);

    saveKeys(keys);

    return res.status(201).json(key);
  }
);

/* =========================
   ADMIN: PATCH KEY
========================= */

app.patch(
  "/api/keys/:id",
  adminAuth,
  (req, res) => {
    const keys = loadKeys();

    const key =
      keys.find(
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
      Object.prototype.hasOwnProperty.call(
        req.body,
        "appId"
      )
    ) {
      key.appId =
        String(
          req.body.appId || "all"
        ).trim() || "all";
    }

    /*
      Cho phép reset device nếu sau này
      admin panel gửi resetDevice:true.
    */
    if (req.body.resetDevice === true) {
      key.deviceId = null;
      key.boundAt = null;
    }

    saveKeys(keys);

    res.json(key);
  }
);

/* =========================
   ADMIN: DELETE KEY
========================= */

app.delete(
  "/api/keys/:id",
  adminAuth,
  (req, res) => {
    const keys = loadKeys();

    const exists =
      keys.some(
        x => x.id === req.params.id
      );

    if (!exists) {
      return res.status(404).json({
        error: "Key not found"
      });
    }

    const filtered =
      keys.filter(
        x => x.id !== req.params.id
      );

    saveKeys(filtered);

    /*
      Session liên quan key này sẽ
      tự mất quyền ở lần kiểm tra tiếp theo
      vì key không còn tồn tại.
    */

    res.json({
      ok: true
    });
  }
);

/* =========================
   FIND KEY
========================= */

function findKey(input) {
  const keys = loadKeys();

  const normalized =
    String(input || "")
      .trim()
      .toUpperCase();

  return {
    keys,

    key:
      keys.find(
        x =>
          String(x.key)
            .trim()
            .toUpperCase() === normalized
      )
  };
}

/* =========================
   VALIDATE KEY
========================= */

function validateKey(
  input,
  deviceId,
  appId
) {
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

  const result =
    findKey(input);

  const key =
    result.key;

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

  if (isKeyExpired(key)) {
    return {
      ok: false,
      status: 403,
      code: "KEY_EXPIRED",
      message: "Key expired"
    };
  }

  /*
    all = dùng được cho mọi app.
    Nếu key có App ID cụ thể thì phải khớp.
  */
  if (
    appId &&
    key.appId &&
    key.appId !== "all" &&
    key.appId !== appId
  ) {
    return {
      ok: false,
      status: 403,
      code: "APP_MISMATCH",
      message: "Key is not valid for this app"
    };
  }

  /*
    Key đã bind thiết bị khác.
  */
  if (
    key.deviceId &&
    key.deviceId !== deviceId
  ) {
    return {
      ok: false,
      status: 403,
      code: "DEVICE_MISMATCH",
      message:
        "Key is already activated on another device"
    };
  }

  return {
    ok: true,
    key,
    keys: result.keys
  };
}

/* =========================
   SESSION
========================= */

/*
  SESSION KHÔNG CÓ TTL RIÊNG.

  Không có:
    SESSION_TTL = 30 phút

  Session chỉ mất quyền khi:
  - key hết hạn
  - key bị khóa
  - key bị xóa
  - device không còn khớp
  - appId không còn hợp lệ

  LƯU Ý:
  sessions nằm trong RAM.
  Render restart/redeploy => session mất.
*/

const sessions = new Map();

function createSession(
  key,
  deviceId,
  appId
) {
  const token =
    crypto.randomBytes(32).toString("hex");

  const session = {
    token,

    keyId: key.id,

    deviceId,

    appId:
      appId ||
      key.appId ||
      "all",

    createdAt:
      Date.now(),

    /*
      null = không có thời hạn session.
    */
    expiresAt: null
  };

  sessions.set(
    token,
    session
  );

  return session;
}

function getBearerToken(req) {
  const authorization =
    req.headers.authorization || "";

  if (
    typeof authorization !== "string"
  ) {
    return null;
  }

  if (
    !authorization.startsWith(
      "Bearer "
    )
  ) {
    return null;
  }

  return authorization
    .slice(7)
    .trim();
}

/* =========================
   VALIDATE SESSION
========================= */

function validateSession(token) {
  if (!token) {
    return {
      ok: false,
      code: "SESSION_REQUIRED",
      message: "Session required"
    };
  }

  const session =
    sessions.get(token);

  if (!session) {
    return {
      ok: false,
      code: "SESSION_INVALID",
      message: "Session invalid"
    };
  }

  /*
    KHÔNG kiểm tra session TTL.
    Session không tự hết hạn.
  */

  const keys =
    loadKeys();

  const key =
    keys.find(
      x =>
        x.id === session.keyId
    );

  /*
    Key bị xóa.
  */
  if (!key) {
    sessions.delete(token);

    return {
      ok: false,
      code: "KEY_NOT_FOUND",
      message: "Key no longer exists"
    };
  }

  /*
    Key bị khóa.
  */
  if (key.disabled) {
    sessions.delete(token);

    return {
      ok: false,
      code: "KEY_DISABLED",
      message: "Key is disabled"
    };
  }

  /*
    Key hết hạn.
  */
  if (isKeyExpired(key)) {
    sessions.delete(token);

    return {
      ok: false,
      code: "KEY_EXPIRED",
      message: "Key expired"
    };
  }

  /*
    Device phải vẫn đúng.
  */
  if (
    key.deviceId !==
    session.deviceId
  ) {
    sessions.delete(token);

    return {
      ok: false,
      code: "DEVICE_MISMATCH",
      message: "Device mismatch"
    };
  }

  /*
    App ID phải còn hợp lệ.
  */
  if (
    key.appId &&
    key.appId !== "all" &&
    session.appId !== key.appId
  ) {
    sessions.delete(token);

    return {
      ok: false,
      code: "APP_MISMATCH",
      message: "App mismatch"
    };
  }

  return {
    ok: true,
    session,
    key
  };
}

/* =========================
   REQUIRE SESSION
========================= */

function requireSession(
  req,
  res,
  next
) {
  const token =
    getBearerToken(req);

  const result =
    validateSession(token);

  if (!result.ok) {
    return res.status(401).json({
      valid: false,
      code: result.code,
      message: result.message
    });
  }

  req.session =
    result.session;

  req.key =
    result.key;

  next();
}

/* =========================
   ACTIVATE
========================= */

app.post(
  "/api/activate",
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

    const appId =
      String(
        req.body.appId || ""
      ).trim();

    const result =
      validateKey(
        input,
        deviceId,
        appId
      );

    if (!result.ok) {
      return res
        .status(result.status)
        .json({
          valid: false,
          code: result.code,
          message: result.message
        });
    }

    const key =
      result.key;

    const keys =
      result.keys;

    const firstActivation =
      !key.deviceId;

    /*
      Bind device lần đầu.
    */
    if (!key.deviceId) {
      key.deviceId =
        deviceId;

      key.boundAt =
        new Date().toISOString();

      saveKeys(keys);
    }

    /*
      Tạo session không TTL.
    */
    const session =
      createSession(
        key,
        deviceId,
        appId ||
          key.appId ||
          "all"
      );

    return res.json({
      valid: true,

      firstActivation,

      deviceBound: true,

      appId:
        key.appId || "all",

      keyExpiresAt:
        key.expiresAt,

      sessionToken:
        session.token,

      /*
        null = session không tự hết hạn.
      */
      sessionExpiresAt: null
    });
  }
);

/* =========================
   CHECK KEY
========================= */

app.post(
  "/api/check",
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

    const appId =
      String(
        req.body.appId || ""
      ).trim();

    const result =
      validateKey(
        input,
        deviceId,
        appId
      );

    if (!result.ok) {
      return res
        .status(result.status)
        .json({
          valid: false,
          code: result.code,
          message: result.message
        });
    }

    const key =
      result.key;

    return res.json({
      valid: true,

      deviceBound:
        Boolean(key.deviceId),

      appId:
        key.appId || "all",

      expiresAt:
        key.expiresAt
    });
  }
);

/* =========================
   SESSION CHECK
========================= */

app.get(
  "/api/session",
  requireSession,
  (req, res) => {
    return res.json({
      valid: true,

      appId:
        req.session.appId,

      deviceId:
        req.session.deviceId,

      keyExpiresAt:
        req.key.expiresAt,

      /*
        Session không có expiry riêng.
      */
      sessionExpiresAt: null
    });
  }
);

/* =========================
   APP ACCESS
========================= */

app.get(
  "/api/app/access",
  requireSession,
  (req, res) => {
    return res.json({
      allowed: true,

      app:
        "AIMHELP OB54",

      appId:
        req.session.appId,

      deviceId:
        req.session.deviceId,

      keyExpiresAt:
        req.key.expiresAt
    });
  }
);

/* =========================
   LOGOUT
========================= */

app.post(
  "/api/logout",
  requireSession,
  (req, res) => {
    const token =
      getBearerToken(req);

    sessions.delete(token);

    return res.json({
      ok: true
    });
  }
);

/* =========================
   HEALTH
========================= */

app.get(
  "/api/health",
  (req, res) => {
    return res.json({
      ok: true,
      service:
        "hk-key-manager",
      session:
        "persistent-until-key-invalid",
      version:
        "3"
    });
  }
);

/* =========================
   API 404
========================= */

app.use(
  "/api",
  (req, res) => {
    return res.status(404).json({
      error:
        "API route not found"
    });
  }
);

/* =========================
   FALLBACK
========================= */

app.get(
  "*",
  (req, res) => {
    res.sendFile(
      path.join(
        ROOT,
        "index.html"
      )
    );
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
      `HK Key Manager running on port ${PORT}`
    );
    console.log(
      "Session mode: persistent until key becomes invalid"
    );
  }
);
