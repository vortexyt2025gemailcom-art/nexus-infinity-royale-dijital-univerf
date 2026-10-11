import { getStore } from "@netlify/blobs";
import {
  createHash, createHmac, randomBytes, randomUUID, scryptSync,
  timingSafeEqual,
} from "node:crypto";

const store = getStore("nexus-infinity-royale");
const STATE_KEY = "shared-state-v1";
const ACCESS_MS = 12 * 60 * 60 * 1000;
const REFRESH_MS = 60 * 24 * 60 * 60 * 1000;
const OWNER_MS = 6 * 60 * 60 * 1000;

const blankState = () => ({
  users: {}, nameIndex: {}, sessions: {}, refreshSessions: {}, tree: {},
});
const sha = (s) => createHash("sha256").update(String(s)).digest("hex");
const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
});
const fail = (message, status = 400) => json({ ok: false, error: message }, status);
const safeEqual = (a, b) => {
  const aa = Buffer.from(String(a)); const bb = Buffer.from(String(b));
  return aa.length === bb.length && timingSafeEqual(aa, bb);
};

async function readState() {
  const entry = await store.getWithMetadata(STATE_KEY, { type: "json", consistency: "strong" });
  return { state: entry?.data || blankState(), etag: entry?.etag || null };
}

// Optimistic compare-and-swap against the single small state document prevents
// lost updates for balances/code redemption during concurrent requests.
async function mutate(fn) {
  for (let attempt = 0; attempt < 12; attempt++) {
    const { state, etag } = await readState();
    const result = await fn(state);
    if (result?.noWrite) return result;
    let saved;
    try {
      saved = etag
        ? await store.setJSON(STATE_KEY, state, { onlyIfMatch: etag })
        : await store.setJSON(STATE_KEY, state, { onlyIfNew: true });
    } catch {
      await new Promise((r) => setTimeout(r, 15 + Math.random() * 35));
      continue;
    }
    if (saved?.modified) return result;
    await new Promise((r) => setTimeout(r, 15 + Math.random() * 35));
  }
  throw new Error("Hay muchas operaciones al mismo tiempo. Intenta otra vez.");
}

function parts(path) {
  if (typeof path !== "string" || !path.trim() || path.length > 240) return null;
  const p = path.split("/").filter(Boolean);
  if (!p.length || p.some((x) => x === "." || x === ".." || x.includes("\\"))) return null;
  return p;
}
function getPath(root, path) {
  const p = parts(path); if (!p) return null;
  let v = root;
  for (const key of p) { if (v == null || typeof v !== "object") return null; v = v[key]; }
  return v === undefined ? null : v;
}
function setPath(root, path, value) {
  const p = parts(path); if (!p) return false;
  let target = root;
  for (const key of p.slice(0, -1)) {
    if (!target[key] || typeof target[key] !== "object" || Array.isArray(target[key])) target[key] = {};
    target = target[key];
  }
  if (value === null) delete target[p[p.length - 1]];
  else target[p[p.length - 1]] = value;
  return true;
}
function publicUser(u) { return { n: u.nick, c: u.coins, t: u.sec, g: u.spins }; }
function syncPublic(state, u) {
  state.tree.u ||= {};
  state.tree.u[u.id] = publicUser(u);
  const nameKey = u.nick.toLowerCase();
  state.tree.names ||= {};
  const old = state.tree.names[nameKey] || {};
  state.tree.names[nameKey] = { ...old, u: u.id, n: u.nick, p: u.photo || "" };
  state.tree.pf ||= {};
  state.tree.pf[u.id] = { r: u.realName || "" };
}
function authUser(state, req) {
  const header = req.headers.get("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return null;
  const s = state.sessions[sha(token)];
  if (!s || s.exp < Date.now()) return null;
  const u = state.users[s.uid];
  return u ? { user: u, uid: u.id } : null;
}
function ownerValid(req) {
  const secret = process.env.OWNER_PIN || "";
  const token = req.headers.get("x-owner-token") || "";
  if (!secret || !token.includes(".")) return false;
  const i = token.indexOf("."); const expText = token.slice(0, i); const sig = token.slice(i + 1);
  const exp = Number(expText);
  if (!Number.isFinite(exp) || exp < Date.now() || exp > Date.now() + OWNER_MS + 60_000) return false;
  const expected = createHmac("sha256", secret).update(expText).digest("base64url");
  return safeEqual(sig, expected);
}
function tokenPair(state, user) {
  const accessToken = randomBytes(32).toString("base64url");
  const refreshToken = randomBytes(48).toString("base64url");
  state.sessions[sha(accessToken)] = { uid: user.id, exp: Date.now() + ACCESS_MS };
  state.refreshSessions[sha(refreshToken)] = { uid: user.id, exp: Date.now() + REFRESH_MS };
  return { idToken: accessToken, localId: user.id, refreshToken, expiresIn: String(ACCESS_MS / 1000) };
}

async function handle(req, body) {
  const action = body.action;
  if (action === "owner-verify") {
    const secret = process.env.OWNER_PIN || "";
    if (!secret) return fail("Falta configurar OWNER_PIN en las variables de Netlify.", 503);
    const pin = String(body.pin || "").trim();
    if (!safeEqual(pin, secret)) return fail("Código de dueño incorrecto.", 403);
    const expText = String(Date.now() + OWNER_MS);
    const sig = createHmac("sha256", secret).update(expText).digest("base64url");
    return json({ ok: true, ownerToken: `${expText}.${sig}` });
  }

  if (action === "auth-register") {
    const nick = String(body.name || "").trim();
    const realName = String(body.realName || "").trim().slice(0, 30);
    const password = String(body.password || "");
    if (!/^\w{3,16}$/.test(nick)) return fail("El nombre debe tener 3 a 16 letras, números o _.");
    if (!realName) return fail("Pon tu nombre.");
    if (password.length < 6 || password.length > 128) return fail("La contraseña debe tener entre 6 y 128 caracteres.");
    return mutate((state) => {
      const key = nick.toLowerCase();
      if (state.nameIndex[key]) return { noWrite: true, response: { ok: false, error: "Ese nombre ya fue usado." } };
      const id = randomUUID(); const salt = randomBytes(16).toString("hex");
      const hash = scryptSync(password, salt, 64).toString("hex");
      const user = { id, nick, realName, salt, passwordHash: hash, photo: String(body.photo || "").slice(0, 160_000), coins: 500, sec: 0, spins: 0, timeRemainder: 0, lastHeartbeat: Date.now(), lastSpinAt: 0, spinCount: 0, rewardedSpin: 0, createdAt: Date.now() };
      state.users[id] = user; state.nameIndex[key] = id; syncPublic(state, user);
      return { response: { ok: true, ...tokenPair(state, user) } };
    }).then((r) => json(r.response));
  }

  if (action === "auth-login") {
    const nick = String(body.name || "").trim(); const password = String(body.password || "");
    return mutate((state) => {
      const id = state.nameIndex[nick.toLowerCase()]; const user = id && state.users[id];
      if (!user) return { noWrite: true, response: { ok: false, error: "Nombre o contraseña incorrectos." } };
      const check = scryptSync(password, user.salt, 64).toString("hex");
      if (!safeEqual(check, user.passwordHash)) return { noWrite: true, response: { ok: false, error: "Nombre o contraseña incorrectos." } };
      return { response: { ok: true, ...tokenPair(state, user) } };
    }).then((r) => json(r.response));
  }

  if (action === "auth-refresh") {
    const refreshToken = String(body.refreshToken || "");
    return mutate((state) => {
      const key = sha(refreshToken); const session = state.refreshSessions[key];
      if (!session || session.exp < Date.now()) return { noWrite: true, response: { ok: false, error: "La sesión venció. Inicia sesión otra vez." } };
      const user = state.users[session.uid]; if (!user) return { noWrite: true, response: { ok: false, error: "La cuenta no existe." } };
      const pair = tokenPair(state, user);
      // Rotate the refresh credential while issuing a new short-lived access token.
      delete state.refreshSessions[key];
      delete state.refreshSessions[sha(pair.refreshToken)];
      const nextRefresh = randomBytes(48).toString("base64url");
      state.refreshSessions[sha(nextRefresh)] = { uid: user.id, exp: Date.now() + REFRESH_MS };
      return { response: { ok: true, id_token: pair.idToken, user_id: user.id, refresh_token: nextRefresh } };
    }).then((r) => json(r.response));
  }

  // All reads use strong consistency so a player sees current shared data.
  if (action === "get") {
    const { state } = await readState(); const path = String(body.path || "");
    const p = parts(path); if (!p) return fail("Ruta inválida.");
    const auth = authUser(state, req); const owner = ownerValid(req);
    if (p[0] === "owners" || p[0] === "refreshSessions" || p[0] === "sessions") return json({ ok: true, value: null });
    if (p[0] === "pf" && p[1] && !owner && auth?.uid !== p[1]) return fail("No autorizado.", 403);
    if (p[0] === "codes" && p.length === 1 && !owner) return json({ ok: true, value: null });
    let value;
    if (p[0] === "u" && p.length === 1) {
      value = {}; for (const u of Object.values(state.users)) value[u.id] = publicUser(u);
    } else if (p[0] === "u" && p[1] && state.users[p[1]]) {
      value = publicUser(state.users[p[1]]);
    } else {
      value = getPath(state.tree, path);
      if (p[0] === "codes" && p.length === 2 && value && !owner) {
        value = { n: value.n, m: value.m, by: value.by || {} };
      }
    }
    return json({ ok: true, value: value ?? null });
  }

  if (action === "search-users") {
    const { state } = await readState();
    const prefix = String(body.prefix || "").trim().toLowerCase().slice(0, 16);
    const users = Object.values(state.users)
      .filter((u) => u.nick.toLowerCase().startsWith(prefix))
      .sort((a, b) => a.nick.localeCompare(b.nick))
      .slice(0, 20)
      .map((u) => ({ u: u.id, n: u.nick, p: u.photo || "" }));
    return json({ ok: true, users });
  }

  return mutate((state) => {
    const auth = authUser(state, req); const user = auth?.user; const owner = ownerValid(req);
    if (action === "wallet") {
      if (!user) return { noWrite: true, response: { ok: false, error: "Inicia sesión." } };
      return { noWrite: true, response: { ok: true, coins: user.coins, sec: user.sec, spins: user.spins } };
    }
    if (action === "heartbeat") {
      if (!user) return { noWrite: true, response: { ok: false, error: "Inicia sesión." } };
      const now = Date.now(); const dt = Math.floor((now - (user.lastHeartbeat || now)) / 1000);
      const active = dt >= 0 && dt <= 75 ? Math.min(45, dt) : 0;
      user.lastHeartbeat = now; user.sec += active; user.timeRemainder += active;
      const minutes = Math.floor(user.timeRemainder / 60); const earned = minutes * 50;
      user.timeRemainder %= 60; user.coins += earned; syncPublic(state, user);
      return { response: { ok: true, coins: user.coins, sec: user.sec, spins: user.spins, earned } };
    }
    if (action === "spin") {
      if (!user) return { noWrite: true, response: { ok: false, error: "Inicia sesión para girar." } };
      if (Date.now() - (user.lastSpinAt || 0) < 1200) return { noWrite: true, response: { ok: false, error: "Espera un momento antes de volver a girar." } };
      user.lastSpinAt = Date.now(); user.spinCount += 1; user.spins += 1; syncPublic(state, user);
      return { response: { ok: true, coins: user.coins, sec: user.sec, spins: user.spins } };
    }
    if (action === "spin-reward") {
      if (!user) return { noWrite: true, response: { ok: false, error: "Inicia sesión." } };
      if (!user.spinCount || user.rewardedSpin >= user.spinCount) return { noWrite: true, response: { ok: false, error: "No hay una recompensa pendiente." } };
      const seconds = Math.max(0.5, Math.min(120, Number(body.seconds) || 5));
      if (Date.now() - user.lastSpinAt < seconds * 1000 - 500) return { noWrite: true, response: { ok: false, error: "Espera a que termine el tiempo de la recompensa." } };
      const amount = Math.max(1, Math.min(100, Math.round(seconds * 50 / 60)));
      user.coins += amount; user.rewardedSpin = user.spinCount; syncPublic(state, user);
      return { response: { ok: true, coins: user.coins, sec: user.sec, spins: user.spins, earned: amount } };
    }
    if (action === "spend" || action === "admin-grant") {
      if (!user) return { noWrite: true, response: { ok: false, error: "Inicia sesión." } };
      const amount = Math.floor(Number(body.amount));
      if (!(amount > 0 && amount <= 100000)) return { noWrite: true, response: { ok: false, error: "Cantidad inválida." } };
      if (action === "admin-grant" && !owner) return { noWrite: true, response: { ok: false, error: "Solo el dueño puede añadir monedas." } };
      if (action === "spend" && user.coins < amount) return { noWrite: true, response: { ok: false, error: "No tienes suficientes monedas." } };
      user.coins += action === "spend" ? -amount : amount; syncPublic(state, user);
      return { response: { ok: true, coins: user.coins, sec: user.sec, spins: user.spins } };
    }
    if (action === "transfer") {
      if (!user) return { noWrite: true, response: { ok: false, error: "Inicia sesión." } };
      const amount = Math.floor(Number(body.amount)); const target = state.users[String(body.to || "")];
      if (!target || target.id === user.id) return { noWrite: true, response: { ok: false, error: "Jugador no válido." } };
      if (!(amount > 0 && amount <= 100000)) return { noWrite: true, response: { ok: false, error: "Cantidad inválida." } };
      if (user.coins < amount) return { noWrite: true, response: { ok: false, error: "Monedas insuficientes." } };
      user.coins -= amount; target.coins += amount; syncPublic(state, user); syncPublic(state, target);
      return { response: { ok: true, coins: user.coins, sec: user.sec, spins: user.spins } };
    }
    if (action !== "set") return { noWrite: true, response: { ok: false, error: "Acción no reconocida." } };

    const path = String(body.path || ""); const p = parts(path); if (!p) return { noWrite: true, response: { ok: false, error: "Ruta inválida." } };
    const value = body.value;
    if (p[0] === "an" || p[0] === "hw" || p[0] === "owners" || (p[0] === "codes" && p.length === 2)) {
      if (!owner) return { noWrite: true, response: { ok: false, error: "Solo el dueño puede modificar esta sección." } };
    }
    if (p[0] === "u" && p[1]) {
      if (!user || user.id !== p[1]) return { noWrite: true, response: { ok: false, error: "No puedes modificar la cuenta de otro jugador." } };
      syncPublic(state, user); return { response: { ok: true } };
    }
    if (p[0] === "names" && p[1]) {
      if (!user || state.nameIndex[p[1].toLowerCase()] !== user.id) return { noWrite: true, response: { ok: false, error: "No puedes cambiar el perfil de otro jugador." } };
      if (p.length === 2 && value && typeof value === "object") {
        const publicName = state.tree.names?.[p[1].toLowerCase()] || {};
        state.tree.names ||= {}; state.tree.names[p[1].toLowerCase()] = { ...publicName, u: user.id, n: user.nick, p: user.photo || "" };
      } else if (p[2] === "p") {
        const photo = String(value || ""); if (photo.length > 160_000) return { noWrite: true, response: { ok: false, error: "La foto es demasiado grande." } };
        user.photo = photo; state.tree.names ||= {}; state.tree.names[p[1].toLowerCase()] = { u: user.id, n: user.nick, p: photo };
      } else return { noWrite: true, response: { ok: false, error: "Cambio de perfil no permitido." } };
      syncPublic(state, user); return { response: { ok: true } };
    }
    if (p[0] === "pf" && p[1]) {
      if (!user || user.id !== p[1]) return { noWrite: true, response: { ok: false, error: "No autorizado." } };
      user.realName = String(value?.r || user.realName).slice(0, 30); syncPublic(state, user);
      return { response: { ok: true } };
    }
    if (p[0] === "codes" && p.length === 2) {
      if (!/^[0-9A-Z]{30,128}$/.test(p[1]) || !value || !Number.isFinite(Number(value.n)) || Number(value.n) <= 0 || Number(value.n) > 1000000) return { noWrite: true, response: { ok: false, error: "Código o cantidad inválidos." } };
      const existing = getPath(state.tree, path);
      if (existing) return { noWrite: true, response: { ok: false, error: "Ese código ya existe." } };
      setPath(state.tree, path, { n: Math.floor(Number(value.n)), m: Math.max(1, Math.min(100000, Math.floor(Number(value.m) || 1))), by: {}, createdAt: Date.now() });
      return { response: { ok: true } };
    }
    if (p[0] === "codes" && p[2] === "by" && p[3]) {
      if (!user || user.id !== p[3] || value !== true) return { noWrite: true, response: { ok: false, error: "No autorizado para canjear ese código." } };
      const code = getPath(state.tree, `codes/${p[1]}`);
      if (!code || !(code.n > 0)) return { noWrite: true, response: { ok: false, error: "Código inválido." } };
      code.by ||= {};
      if (code.by[user.id]) return { noWrite: true, response: { ok: false, error: "Ya canjeaste este código." } };
      if (Object.keys(code.by).length >= (code.m || 1)) return { noWrite: true, response: { ok: false, error: "Este código ya se agotó." } };
      code.by[user.id] = true; setPath(state.tree, `codes/${p[1]}`, code); user.coins += code.n; syncPublic(state, user);
      return { response: { ok: true } };
    }
    if (p.length === 1 && p[0] === "an") {
      if (value && typeof value === "object") {
        const t = String(value.t || "").slice(0, 300); const i = String(value.i || "");
        if (i.length > 2_500_000) return { noWrite: true, response: { ok: false, error: "La imagen del anuncio es demasiado grande." } };
        setPath(state.tree, path, { t, i, id: Number(value.id) || Date.now() });
      } else setPath(state.tree, path, null);
      return { response: { ok: true } };
    }
    if (p.length === 1 && p[0] === "hw") { setPath(state.tree, path, !!value); return { response: { ok: true } }; }
    if (p[0] === "owners") { setPath(state.tree, path, { enabled: true }); return { response: { ok: true } }; }
    return { noWrite: true, response: { ok: false, error: "Escritura no permitida." } };
  }).then((r) => json(r.response));
}

export default async (req) => {
  if (req.method !== "POST") return json({ ok: false, error: "Usa POST." }, 405);
  try {
    const body = await req.json();
    return await handle(req, body || {});
  } catch (error) {
    return fail(error?.message || "Error interno.", 500);
  }
};
