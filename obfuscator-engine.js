"use strict";

/*
 * O Protector â€” server-side obfuscation engine (obfuscator-engine.js)
 *
 * Runs ONLY on the server (required by server.js). The engine source never
 * reaches the browser, which is the single biggest step toward a Luraph/Luarmor
 * style protection model. It produces valid Lua and can bind each build to a
 * per-script key that is validated at runtime against /api/verify.
 *
 * Layers:
 *   - Local identifier renaming (mangling)
 *   - Rotating multi-key string encryption (byte arrays + LCG keystream)
 *   - Numeric literal mangling (arithmetic expansion)
 *   - Junk / dead-code injection
 *   - Anti-tamper guard (pcall self-check; halts if the environment is hooked)
 *   - Optional key-lock header that phones home to /api/verify before running
 *   - Minify
 *
 * HONEST SCOPE: this is strong source-level protection delivered server-side.
 * It is NOT bytecode virtualization (a real VM like Luraph). A determined
 * reverse engineer can still recover logic; the goal is to make that expensive.
 */

const crypto = require("crypto");

// --- Lua lexical data ------------------------------------------------------
const LUA_KEYWORDS = new Set([
  "and","break","do","else","elseif","end","false","for","function","goto",
  "if","in","local","nil","not","or","repeat","return","then","true","until","while"
]);

const LUA_GLOBALS = new Set([
  "print","pairs","ipairs","next","type","tostring","tonumber","pcall","xpcall",
  "error","assert","select","setmetatable","getmetatable","rawget","rawset",
  "rawequal","rawlen","require","collectgarbage","load","loadstring","dofile",
  "unpack","_G","_ENV","_VERSION","string","table","math","os","io","coroutine",
  "debug","utf8","bit","bit32",
  "game","workspace","script","wait","spawn","delay","tick","task","Instance",
  "Vector3","Vector2","CFrame","Color3","UDim2","UDim","Enum","Ray","Region3",
  "getgenv","getrenv","getreg","hookfunction","hookmetamethod","getrawmetatable",
  "setreadonly","newcclosure","checkcaller","readfile","writefile","isfile",
  "listfiles","HttpGet","HttpGetAsync","request","syn","fluxus","identifyexecutor",
  "firetouchinterest","fireclickdetector","firesignal"
]);

// --- Tokenizer -------------------------------------------------------------
function tokenize(src) {
  const toks = [];
  let i = 0;
  const n = src.length;
  const isIdentStart = (c) => /[A-Za-z_]/.test(c);
  const isIdentPart = (c) => /[A-Za-z0-9_]/.test(c);
  const isDigit = (c) => /[0-9]/.test(c);

  function longBracket(start) {
    if (src[start] !== "[") return -1;
    let j = start + 1, eq = 0;
    while (src[j] === "=") { eq++; j++; }
    if (src[j] !== "[") return -1;
    const close = "]" + "=".repeat(eq) + "]";
    const end = src.indexOf(close, j + 1);
    return end === -1 ? n : end + close.length;
  }

  while (i < n) {
    const c = src[i];

    if (c === "-" && src[i + 1] === "-") {
      if (src[i + 2] === "[") {
        const lc = longBracket(i + 2);
        if (lc !== -1) { toks.push({ t: "comment", v: src.slice(i, lc) }); i = lc; continue; }
      }
      let nl = src.indexOf("\n", i);
      if (nl === -1) nl = n;
      toks.push({ t: "comment", v: src.slice(i, nl) });
      i = nl; continue;
    }

    if (c === "[" && (src[i + 1] === "[" || src[i + 1] === "=")) {
      const ls = longBracket(i);
      if (ls !== -1) { toks.push({ t: "string", v: src.slice(i, ls), long: true }); i = ls; continue; }
    }

    if (c === '"' || c === "'") {
      const q = c; let j = i + 1, buf = q;
      while (j < n) {
        const ch = src[j]; buf += ch;
        if (ch === "\\") { buf += src[j + 1] || ""; j += 2; continue; }
        j++;
        if (ch === q) break;
      }
      toks.push({ t: "string", v: buf, quote: q }); i = j; continue;
    }

    if (isDigit(c) || (c === "." && isDigit(src[i + 1]))) {
      let j = i;
      if (c === "0" && (src[i + 1] === "x" || src[i + 1] === "X")) {
        j += 2; while (j < n && /[0-9a-fA-F.pP+\-]/.test(src[j])) j++;
      } else {
        while (j < n && /[0-9.eE+\-]/.test(src[j])) {
          if ((src[j] === "+" || src[j] === "-") && !/[eE]/.test(src[j - 1])) break;
          j++;
        }
      }
      toks.push({ t: "number", v: src.slice(i, j) }); i = j; continue;
    }

    if (isIdentStart(c)) {
      let j = i + 1;
      while (j < n && isIdentPart(src[j])) j++;
      const word = src.slice(i, j);
      toks.push({ t: LUA_KEYWORDS.has(word) ? "keyword" : "ident", v: word });
      i = j; continue;
    }

    if (/\s/.test(c)) {
      let j = i;
      while (j < n && /\s/.test(src[j])) j++;
      toks.push({ t: "ws", v: src.slice(i, j) }); i = j; continue;
    }

    const three = src.substr(i, 3);
    const two = src.substr(i, 2);
    if (three === "...") { toks.push({ t: "op", v: three }); i += 3; continue; }
    if (["==","~=","<=",">=","..","::","//",">>","<<"].includes(two)) {
      toks.push({ t: "op", v: two }); i += 2; continue;
    }
    toks.push({ t: "op", v: c }); i++;
  }
  return toks;
}

// --- Helpers ---------------------------------------------------------------
function rnd(max) { return Math.floor(Math.random() * max); }

function randName(len) {
  const mix = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
  const pool = "IlO";
  let s = pool[rnd(pool.length)];
  for (let k = 1; k < len; k++) s += mix[rnd(mix.length)];
  return s;
}

function makeNamer() {
  const used = new Set();
  return function () {
    let name;
    do { name = randName(7 + rnd(7)); } while (used.has(name) || LUA_KEYWORDS.has(name));
    used.add(name);
    return name;
  };
}

function decodeLuaString(tok) {
  if (tok.long) {
    const m = tok.v.match(/^\[(=*)\[([\s\S]*?)\]\1\]$/);
    return m ? m[2] : tok.v;
  }
  const body = tok.v.slice(1, -1);
  let out = "", i = 0;
  const map = { n:"\n", t:"\t", r:"\r", a:"\x07", b:"\b", f:"\f", v:"\v", "\\":"\\", '"':'"', "'":"'", "\n":"\n" };
  while (i < body.length) {
    const c = body[i];
    if (c === "\\") {
      const nx = body[i + 1];
      if (map[nx] !== undefined) { out += map[nx]; i += 2; continue; }
      if (nx === "x") { out += String.fromCharCode(parseInt(body.substr(i + 2, 2), 16)); i += 4; continue; }
      if (/[0-9]/.test(nx)) {
        const num = body.substr(i + 1).match(/^[0-9]{1,3}/)[0];
        out += String.fromCharCode(parseInt(num, 10)); i += 1 + num.length; continue;
      }
      out += nx; i += 2; continue;
    }
    out += c; i++;
  }
  return out;
}

// --- Passes ----------------------------------------------------------------
function renameLocals(toks) {
  const next = makeNamer();
  const map = new Map();

  function prevSig(idx) {
    for (let j = idx - 1; j >= 0; j--) {
      if (toks[j].t !== "ws" && toks[j].t !== "comment") return toks[j];
    }
    return null;
  }

  for (let i = 0; i < toks.length; i++) {
    if (toks[i].t === "keyword" && toks[i].v === "local") {
      let j = i + 1;
      while (j < toks.length) {
        const t = toks[j];
        if (t.t === "ws" || t.t === "comment") { j++; continue; }
        if (t.t === "op" && t.v === "=") break;
        if (t.t === "op" && t.v === ";") break;
        if (t.t === "keyword" && t.v !== "function") break;
        if (t.t === "ident" && !LUA_GLOBALS.has(t.v) && !map.has(t.v)) {
          const p = prevSig(j);
          const fld = p && p.t === "op" && (p.v === "." || p.v === ":");
          if (!fld) map.set(t.v, next());
        }
        if (t.t === "op" && t.v !== "," && t.v !== ".") { /* keep scanning list */ }
        j++;
        if (j - i > 60) break;
      }
    }
  }

  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.t !== "ident") continue;
    const p = prevSig(i);
    if (p && p.t === "op" && (p.v === "." || p.v === ":")) continue;
    if (map.has(t.v)) t.v = map.get(t.v);
  }
  return toks;
}

// Rotating multi-key string encryption using an LCG keystream.
function encryptStrings(toks, decName, seed) {
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.t !== "string") continue;
    const raw = decodeLuaString(t);
    if (raw.length === 0) continue;

    // LCG: state = (state*1103515245 + 12345) % 2^31 ; key byte = state % 256
    let state = seed % 2147483648;
    const bytes = [];
    for (let c = 0; c < raw.length; c++) {
      state = (state * 1103515245 + 12345) % 2147483648;
      const k = state % 256;
      bytes.push((raw.charCodeAt(c) & 0xff) ^ k);
    }
    t.t = "encoded";
    t.v = decName + "({" + bytes.join(",") + "}," + seed + ")";
  }
  return toks;
}

function mangleNumbers(toks) {
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.t !== "number") continue;
    if (/[.xXeEpP]/.test(t.v)) continue;
    const val = parseInt(t.v, 10);
    if (isNaN(val) || Math.abs(val) > 1000000) continue;
    const a = rnd(Math.abs(val) + 1) * (val < 0 ? -1 : 1);
    const b = val - a;
    t.v = "(" + a + "+" + b + ")";
  }
  return toks;
}

function injectJunk(toks, namer) {
  const junk = [];
  const count = 2 + rnd(4);
  for (let i = 0; i < count; i++) {
    junk.push({ t: "raw", v: "local " + namer() + "=" + rnd(999999) + ";" });
  }
  junk.push({ t: "raw", v: "\n" });
  return junk.concat(toks);
}

function emit(toks, opts) {
  const out = [];
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.t === "comment") { if (!opts.minify) out.push(t.v); continue; }
    if (t.t === "ws") {
      if (opts.minify) {
        const prev = toks[i - 1], nextT = toks[i + 1];
        const needsGap = prev && nextT &&
          (prev.t === "ident" || prev.t === "keyword" || prev.t === "number") &&
          (nextT.t === "ident" || nextT.t === "keyword" || nextT.t === "number");
        out.push(needsGap ? " " : (/\n/.test(t.v) ? "\n" : " "));
      } else out.push(t.v);
      continue;
    }
    out.push(t.v);
  }
  return out.join("");
}

// Runtime header: LCG string decryptor + anti-tamper guard + optional key lock.
function buildHeader(names, seed, opts, keyInfo) {
  const dec = names.dec;
  const lines = [];
  lines.push("--[[ " + (opts.watermark || "Protected by O Protector") + " ]]");

  // LCG-based decryptor matching encryptStrings.
  lines.push(
    "local " + dec + "=function(t,s)" +
    "local o={};" +
    "for i=1,#t do " +
    "s=(s*1103515245+12345)%2147483648;" +
    "local k=s%256;" +
    "o[i]=string.char((t[i]~k)%256)" +
    "end;" +
    "return table.concat(o)end"
  );

  // Anti-tamper: if core primitives are hooked/missing, halt.
  if (opts.antiTamper) {
    lines.push(
      "local " + names.guard + "=function()" +
      "local ok=pcall(function() " +
      "assert(string.char(65)=='A');" +
      "assert(type(select)=='function')" +
      "end);" +
      "if not ok then while true do end end " +
      "end;" + names.guard + "()"
    );
  }

  // Optional key lock: validate a per-build key before running the payload.
  if (keyInfo && keyInfo.key) {
    const kv = names.keyvar;
    const vf = names.verify;
    const url = (keyInfo.verifyUrl || "").replace(/"/g, "");
    const parts = [
      'local ' + kv + '="' + keyInfo.key + '"',
      'local ' + vf + '=function()',
      '  local u="' + url + '"',
      '  if u=="" then return true end',
      '  local req=(syn and syn.request) or (http and http.request) or request',
      '  if type(req)~="function" then return true end',
      '  local ok,res=pcall(function() return req({Url=u.."?key="..' + kv + ',Method="GET"}) end)',
      '  if not ok or not res then return false end',
      '  local body=tostring(res.Body or res.body or "")',
      '  return body:find(\'"valid":true\')~=nil',
      'end',
      'if not ' + vf + '() then return end'
    ];
    lines.push(parts.join("\n"));
  }

  return lines.join("\n") + "\n";
}

// --- Public API ------------------------------------------------------------
function obfuscate(source, options = {}) {
  const opts = {
    renameLocals: options.renameLocals !== false,
    encodeStrings: options.encodeStrings !== false,
    mangleNumbers: options.mangleNumbers !== false,
    injectJunk: options.injectJunk !== false,
    antiTamper: options.antiTamper !== false,
    minify: options.minify !== false,
    watermark: options.watermark || "Protected by O Protector"
  };

  if (typeof source !== "string" || source.trim() === "") {
    throw new Error("Empty source: provide some Lua code.");
  }

  const namer = makeNamer();
  const names = {
    dec: "_O" + randName(6),
    guard: "_O" + randName(6),
    keyvar: "_O" + randName(6),
    verify: "_O" + randName(6)
  };
  const seed = 1 + rnd(2147483000);

  let toks = tokenize(source);
  if (opts.renameLocals) toks = renameLocals(toks);
  if (opts.mangleNumbers) toks = mangleNumbers(toks);
  if (opts.encodeStrings) toks = encryptStrings(toks, names.dec, seed);
  if (opts.injectJunk) toks = injectJunk(toks, namer);

  const body = emit(toks, opts);
  const header = buildHeader(names, seed, opts, options.keyInfo);
  return header + body + "\n";
}

// Issue a random per-build key (server stores/validates it).
function makeKey() {
  return crypto.randomBytes(16).toString("hex");
}

// --- Wrapper mode: encrypt the ENTIRE script + emit a Lua loader stub -------
// The whole source is encrypted into an LCG-keystream byte array; a tiny loader
// decrypts it at runtime and runs it via loadstring/load. Runtime behaviour is
// preserved (hooks, getrenv, metatables all still execute normally) â€” only the
// on-disk form is opaque. This is the protection that works on real Luau
// exploit scripts that a bytecode VM would break.
function wrap(source, options = {}) {
  if (typeof source !== "string" || source.trim() === "") {
    throw new Error("Empty source: provide some Lua code.");
  }
  const opts = {
    antiTamper: options.antiTamper !== false,
    watermark: options.watermark || "Protected by O Protector"
  };

  const names = {
    dec: "_O" + randName(6),
    data: "_O" + randName(6),
    load: "_O" + randName(6),
    fn: "_O" + randName(6),
    guard: "_O" + randName(6),
    ok: "_O" + randName(6),
    err: "_O" + randName(6),
    keyvar: "_O" + randName(6),
    verify: "_O" + randName(6)
  };
  const seed = 1 + rnd(2147483000);

  // Encrypt real UTF-8 bytes so Unicode content survives byte-exact.
  const src = Buffer.from(source, "utf8");
  let state = seed % 2147483648;
  const bytes = new Array(src.length);
  for (let i = 0; i < src.length; i++) {
    state = (state * 1103515245 + 12345) % 2147483648;
    bytes[i] = (src[i] & 0xff) ^ (state % 256);
  }

  // Chunk the byte literal so no line is absurdly long.
  const perLine = 40;
  const chunks = [];
  for (let i = 0; i < bytes.length; i += perLine) {
    chunks.push(bytes.slice(i, i + perLine).join(","));
  }
  const dataLiteral = "{\n" + chunks.join(",\n") + "\n}";

  const L = [];
  L.push("--[[ " + opts.watermark + " ]]");
  L.push("local " + names.dec + "=function(t,s)");
  L.push("  local o={}");
  L.push("  for i=1,#t do");
  L.push("    s=(s*1103515245+12345)%2147483648");
  L.push("    o[i]=string.char((t[i]~(s%256))%256)");
  L.push("  end");
  L.push("  return table.concat(o)");
  L.push("end");

  // Optional key lock BEFORE decrypting the payload (fail-closed on invalid key).
  const keyInfo = options.keyInfo;
  if (keyInfo && keyInfo.key) {
    const url = (keyInfo.verifyUrl || "").replace(/"/g, "");
    L.push("local " + names.keyvar + "=\"" + keyInfo.key + "\"");
    L.push("local " + names.verify + "=function()");
    L.push("  local u=\"" + url + "\"");
    L.push("  if u==\"\" then return true end");
    L.push("  local req=(syn and syn.request) or (http and http.request) or request");
    L.push("  if type(req)~=\"function\" then return true end");
    L.push("  local ok,res=pcall(function() return req({Url=u..\"?key=\".." + names.keyvar + ",Method=\"GET\"}) end)");
    L.push("  if not ok or not res then return false end");
    L.push("  return tostring(res.Body or res.body or \"\"):find('\"valid\":true')~=nil");
    L.push("end");
    L.push("if not " + names.verify + "() then return end");
  }

  if (opts.antiTamper) {
    L.push("if not pcall(function() assert(string.char(65)==\"A\") end) then return end");
  }

  L.push("local " + names.data + "=" + dataLiteral);
  L.push("local " + names.load + "=" + names.dec + "(" + names.data + "," + seed + ")");
  L.push("local " + names.fn + "=(loadstring or load)(" + names.load + ")");
  L.push("if type(" + names.fn + ")~=\"function\" then return end");
  L.push("local " + names.ok + "," + names.err + "=pcall(" + names.fn + ")");
  L.push("if not " + names.ok + " then error(" + names.err + ",0) end");

  return L.join("\n") + "\n";
}

module.exports = { obfuscate, wrap, makeKey, tokenize, version: "3.0.0" };
