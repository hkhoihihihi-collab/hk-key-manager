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
  try { return JSON.parse(fs.readFileSync(DB, "utf8")); }
  catch { return []; }
}
function save(data) { fs.writeFileSync(DB, JSON.stringify(data, null, 2)); }

function makeKey() {
  const p = () => crypto.randomBytes(2).toString("hex").toUpperCase();
  return `HK-${p()}-${p()}-${p()}`;
}

function duration(type, custom) {
  const now = Date.now();
  const map = {
    "1h": 3600000, "6h": 21600000, "12h": 43200000,
    "1d": 86400000, "3d": 259200000, "7d": 604800000,
    "14d": 1209600000, "30d": 2592000000,
    "3m": 7776000000, "6m": 15552000000, "1y": 31536000000
  };
  if (type === "forever") return null;
  if (type === "custom") return new Date(custom).getTime();
  return now + (map[type] || 86400000);
}

function auth(req,res,next) {
  if (req.headers["x-admin-password"] !== ADMIN_PASSWORD)
    return res.status(401).json({error:"Unauthorized"});
  next();
}

app.get("/api/keys", auth, (req,res) => res.json(load()));

app.post("/api/keys", auth, (req,res) => {
  const keys=load();
  const key={id:crypto.randomUUID(), key:makeKey(), createdAt:new Date().toISOString(),
    expiresAt:duration(req.body.duration || "30d", req.body.custom), disabled:false};
  keys.push(key); save(keys); res.json(key);
});

app.patch("/api/keys/:id", auth, (req,res) => {
  const keys=load(), k=keys.find(x=>x.id===req.params.id);
  if(!k) return res.status(404).json({error:"Not found"});
  if("disabled" in req.body) k.disabled=!!req.body.disabled;
  save(keys); res.json(k);
});

app.delete("/api/keys/:id", auth, (req,res) => {
  const keys=load().filter(x=>x.id!==req.params.id); save(keys); res.json({ok:true});
});

app.post("/api/verify", (req,res) => {
  const input=String(req.body.key||"").trim();
  const k=load().find(x=>x.key===input);
  const valid=!!k && !k.disabled && (k.expiresAt===null || Date.now()<new Date(k.expiresAt).getTime());
  res.json({valid});
});

app.listen(PORT,"0.0.0.0",()=>console.log(`Listening on ${PORT}`));
