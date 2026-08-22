const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 10000;
const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || "CHANGE_ME_NOW";

const ROOT = __dirname;
const DB = path.join(ROOT, "keys.json");
const KEY_PAGE = path.join(ROOT, "key.html");
const ADMIN_PAGE = path.join(ROOT, "index.html");

app.use(express.json({ limit: "1mb" }));

/*
|--------------------------------------------------------------------------
| Static files
|--------------------------------------------------------------------------
*/

app.use(express.static(ROOT));

/*
 * Explicit routes.
 * This also fixes:
 * Cannot GET /key.html
 */

app.get("/key.html", (req, res) => {
  if (!fs.existsSync(KEY_PAGE)) {
    return res.status(404).send("key.html not found");
  }

  res.sendFile(KEY_PAGE);
});

app.get("/", (req, res) => {
  if (!fs.existsSync(ADMIN_PAGE)) {
    return res.status(404).send("index.html not found");
  }

  res.sendFile(ADMIN_PAGE);
});

/*
|--------------------------------------------------------------------------
| Database
|--------------------------------------------------------------------------
*/

function loadKeys() {
  try {
    if (!fs.existsSync(DB)) {
      return [];
    }

    const raw = fs.readFileSync(DB, "utf8");
    const data = JSON.parse(raw);

    return Array.isArray(data) ? data : [];
  } catch (error) {
    console.error("Database read error:", error);
    return [];
  }
}

function saveKeys(data) {
  fs.writeFileSync(
    DB,
    JSON.stringify(data, null, 2),
    "utf8"
  );
}

/*
|--------------------------------------------------------------------------
| Key generator
|--------------------------------------------------------------------------
*/

function makeKey() {
  const part = () =>
    crypto
      .randomBytes(2)
      .toString("hex")
      .toUpperCase();

  return `HK-${part()}-${part()}-${part()}`;
}

/*
|--------------------------------------------------------------------------
| Expiration
|--------------------------------------------------------------------------
*/

function getExpiration(type, custom) {
  const now = Date.now();

  const durations = {
    "1h": 60 * 60 * 1000,
    "6h": 6 * 60 * 60 * 1000,
    "12h": 12 * 60 * 60 * 1000,
    "1d": 24 * 60 * 60 * 1000,
    "3d": 3 * 24 * 60 * 60 * 1000,
    "7d": 7 * 24 * 60 * 60 * 1000,
    "14d": 14 * 24 * 60 * 60 * 1000,
    "30d": 30 * 24 * 60 * 60 * 1000,
    "3m": 90 * 24 * 60 * 60 * 1000,
    "6m": 180 * 24 * 60 * 60 * 1000,
    "1y": 365 * 24 * 60 * 60 * 1000
  };

  if (type === "forever") {
    return null;
  }

  if (type === "custom") {
    const timestamp = new Date(custom).getTime();

    if (!Number.isFinite(timestamp)) {
      return null;
    }

    return new Date(timestamp).toISOString();
  }

  const ms =
    durations[type] ||
    durations["30d"];

  return new Date(now + ms).toISOString();
}

/*
|--------------------------------------------------------------------------
| Admin authentication
|--------------------------------------------------------------------------
*/

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

/*
|--------------------------------------------------------------------------
| ADMIN: list keys
|--------------------------------------------------------------------------
*/

app.get(
  "/api/keys",
  adminAuth,
  (req, res) => {
    res.json(loadKeys());
  }
);

/*
|--------------------------------------------------------------------------
| ADMIN: create key
|--------------------------------------------------------------------------
*/

app.post(
  "/api/keys",
  adminAuth,
  (req, res) => {

    const keys = loadKeys();

    const duration =
      String(
        req.body.duration || "30d"
      );

    const appId =
      String(
        req.body.appId || "all"
      ).trim();

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

      /*
       * Chưa khóa thiết bị.
       * Thiết bị đầu tiên dùng key
       * sẽ được ghi vào đây.
       */
      deviceId: null,

      boundAt: null,

      /*
       * all = dùng cho mọi app.
       * Hoặc có thể đặt App ID cụ thể.
       */
      appId: appId || "all"
    };

    keys.push(key);
    saveKeys(keys);

    res.json(key);
  }
);

/*
|--------------------------------------------------------------------------
| ADMIN: khóa / mở khóa / reset device
|--------------------------------------------------------------------------
*/

app.patch(
  "/api/keys/:id",
  adminAuth,
  (req, res) => {

    const keys = loadKeys();

    const key = keys.find(
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
     * Reset device:
     *
     * {
     *   "resetDevice": true
     * }
     *
     * Sau đó key có thể được
     * kích hoạt trên thiết bị mới.
     */

    if (req.body.resetDevice === true) {
      key.deviceId = null;
      key.boundAt = null;
    }

    saveKeys(keys);

    res.json(key);
  }
);

/*
|--------------------------------------------------------------------------
| ADMIN: delete key
|--------------------------------------------------------------------------
*/

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

/*
|--------------------------------------------------------------------------
| VERIFY
|
| POST /api/verify
|
| Body:
|
| {
|   "key": "HK-XXXX-XXXX-XXXX",
|   "deviceId": "AHK-...",
|   "appId": "all"
| }
|
|--------------------------------------------------------------------------
*/

app.post(
  "/api/verify",
  (req, res) => {

    const inputKey =
      String(
        req.body.key || ""
      ).trim().toUpperCase();

    const deviceId =
      String(
        req.body.deviceId || ""
      ).trim();

    const appId =
      String(
        req.body.appId || "all"
      ).trim();

    /*
     * Không có key.
     */

    if (!inputKey) {
      return res.status(400).json({
        valid: false,
        code: "KEY_REQUIRED",
        message: "Key is required"
      });
    }

    /*
     * Không có deviceId.
     */

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
        item =>
          String(item.key)
            .trim()
            .toUpperCase() === inputKey
      );

    /*
     * Key không tồn tại.
     */

    if (!key) {
      return res.status(404).json({
        valid: false,
        code: "INVALID_KEY",
        message: "Invalid key"
      });
    }

    /*
     * Key bị khóa.
     */

    if (key.disabled) {
      return res.status(403).json({
        valid: false,
        code: "KEY_DISABLED",
        message: "Key is disabled"
      });
    }

    /*
     * Key hết hạn.
     */

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
     * Kiểm tra App ID.
     */

    if (
      key.appId &&
      key.appId !== "all" &&
      key.appId !== appId
    ) {
      return res.status(403).json({
        valid: false,
        code: "APP_NOT_ALLOWED",
        message:
          "Key is not allowed for this app"
      });
    }

    /*
     * =====================================================
     * 1 KEY = 1 DEVICE
     * =====================================================
     *
     * Key chưa từng được kích hoạt:
     * → khóa vào thiết bị đầu tiên.
     */

    if (!key.deviceId) {

      key.deviceId = deviceId;

      key.boundAt =
        new Date().toISOString();

      saveKeys(keys);

      return res.json({
        valid: true,

        firstActivation: true,

        deviceBound: true,

        message:
          "Key activated successfully",

        expiresAt:
          key.expiresAt
      });
    }

    /*
     * Đúng thiết bị đã đăng ký:
     * → cho phép sử dụng.
     */

    if (key.deviceId === deviceId) {

      return res.json({
        valid: true,

        firstActivation: false,

        deviceBound: true,

        message:
          "Key verified",

        expiresAt:
          key.expiresAt
      });
    }

    /*
     * Key đã thuộc về thiết bị khác:
     * → từ chối.
     */

    return res.status(403).json({

      valid: false,

      code: "DEVICE_MISMATCH",

      message:
        "Key is already activated on another device"
    });
  }
);

/*
|--------------------------------------------------------------------------
| HEALTH CHECK
|--------------------------------------------------------------------------
*/

app.get(
  "/api/health",
  (req, res) => {

    res.json({
      ok: true,
      service: "hk-key-manager",
      keySystem: "1-key-1-device"
    });
  }
);

/*
|--------------------------------------------------------------------------
| 404 API
|--------------------------------------------------------------------------
*/

app.use(
  "/api",
  (req, res) => {

    res.status(404).json({
      error: "API endpoint not found"
    });
  }
);

/*
|--------------------------------------------------------------------------
| START SERVER
|--------------------------------------------------------------------------
*/

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `HK Key Manager listening on port ${PORT}`
    );

    console.log(
      `Key page: /key.html`
    );

    console.log(
      `Verify API: /api/verify`
    );
  }
);
