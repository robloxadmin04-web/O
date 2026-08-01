/*!
 * O Protector â€” obfuscator.js
 * LuaRaptor / Luarmor STYLE source-level Lua obfuscator (runs fully in-browser).
 *
 * Transforms applied (toggleable):
 *   - Header watermark + integrity guard
 *   - Local identifier renaming (mangling)
 *   - String literal encoding (byte-array + XOR decoder)
 *   - Numeric literal mangling (arithmetic expansion)
 *   - Junk / dead-code injection
 *   - Whitespace + comment stripping (minify)
 *
 * NOTE: This is a *source-level* protector. It produces valid, runnable Lua whose
 * intent is hard to read at a glance. It is NOT bytecode-VM encryption like a paid
 * commercial protector â€” no browser-only engine can be. Use it to raise the bar,
 * not as unbreakable DRM.
 *
 * Exposes: window.OObfuscator.obfuscate(source, options) -> string
 */
(function (global) {
  "use strict";

  // ---- Lua reserved words (never rename these) -----------------------------
  var LUA_KEYWORDS = {
    "and": 1, "break": 1, "do": 1, "else": 1, "elseif": 1, "end": 1,
    "false": 1, "for": 1, "function": 1, "goto": 1, "if": 1, "in": 1,
    "local": 1, "nil": 1, "not": 1, "or": 1, "repeat": 1, "return": 1,
    "then": 1, "true": 1, "until": 1, "while": 1
  };

  // Globals / stdlib we must NOT rename (calls would break).
  var LUA_GLOBALS = {
    "print": 1, "pairs": 1, "ipairs": 1, "next": 1, "type": 1, "tostring": 1,
    "tonumber": 1, "pcall": 1, "xpcall": 1, "error": 1, "assert": 1, "select": 1,
    "setmetatable": 1, "getmetatable": 1, "rawget": 1, "rawset": 1, "rawequal": 1,
    "rawlen": 1, "require": 1, "collectgarbage": 1, "load": 1, "loadstring": 1,
    "dofile": 1, "unpack": 1, "_G": 1, "_ENV": 1, "_VERSION": 1,
    "string": 1, "table": 1, "math": 1, "os": 1, "io": 1, "coroutine": 1,
    "debug": 1, "utf8": 1, "bit": 1, "bit32": 1,
    // common exploit / Roblox globals â€” keep intact
    "game": 1, "workspace": 1, "script": 1, "wait": 1, "spawn": 1, "delay": 1,
    "tick": 1, "task": 1, "Instance": 1, "Vector3": 1, "Vector2": 1, "CFrame": 1,
    "Color3": 1, "UDim2": 1, "UDim": 1, "Enum": 1, "Ray": 1, "Region3": 1,
    "getgenv": 1, "getrenv": 1, "getreg": 1, "hookfunction": 1, "hookmetamethod": 1,
    "getrawmetatable": 1, "setreadonly": 1, "newcclosure": 1, "checkcaller": 1,
    "loadstring": 1, "readfile": 1, "writefile": 1, "isfile": 1, "listfiles": 1,
    "HttpGet": 1, "request": 1, "syn": 1, "fluxus": 1, "identifyexecutor": 1,
    "firetouchinterest": 1, "fireclickdetector": 1, "firesignal": 1
  };

  // ---------------------------------------------------------------------------
  // Tokenizer â€” enough Lua lexing to preserve strings/comments and find idents.
  // ---------------------------------------------------------------------------
  function tokenize(src) {
    var toks = [];
    var i = 0, n = src.length;

    function isIdentStart(c) { return /[A-Za-z_]/.test(c); }
    function isIdentPart(c) { return /[A-Za-z0-9_]/.test(c); }
    function isDigit(c) { return /[0-9]/.test(c); }

    // long bracket [[ ]] / [=[ ]=] â€” returns end index after close, or -1
    function longBracket(start) {
      if (src[start] !== "[") return -1;
      var j = start + 1, eq = 0;
      while (src[j] === "=") { eq++; j++; }
      if (src[j] !== "[") return -1;
      var close = "]" + Array(eq + 1).join("=") + "]";
      var end = src.indexOf(close, j + 1);
      if (end === -1) return n; // unterminated â†’ to EOF
      return end + close.length;
    }

    while (i < n) {
      var c = src[i];

      // long comment
      if (c === "-" && src[i + 1] === "-") {
        if (src[i + 2] === "[") {
          var lc = longBracket(i + 2);
          if (lc !== -1) { toks.push({ t: "comment", v: src.slice(i, lc) }); i = lc; continue; }
        }
        var nl = src.indexOf("\n", i);
        if (nl === -1) nl = n;
        toks.push({ t: "comment", v: src.slice(i, nl) });
        i = nl;
        continue;
      }

      // long string
      if (c === "[" && (src[i + 1] === "[" || src[i + 1] === "=")) {
        var ls = longBracket(i);
        if (ls !== -1) { toks.push({ t: "string", v: src.slice(i, ls), long: true }); i = ls; continue; }
      }

      // quoted string
      if (c === '"' || c === "'") {
        var q = c, j2 = i + 1, buf = q;
        while (j2 < n) {
          var ch = src[j2];
          buf += ch;
          if (ch === "\\") { buf += src[j2 + 1] || ""; j2 += 2; continue; }
          j2++;
          if (ch === q) break;
        }
        toks.push({ t: "string", v: buf, quote: q });
        i = j2;
        continue;
      }

      // number
      if (isDigit(c) || (c === "." && isDigit(src[i + 1]))) {
        var j3 = i;
        if (c === "0" && (src[i + 1] === "x" || src[i + 1] === "X")) {
          j3 += 2;
          while (j3 < n && /[0-9a-fA-F.pP+\-]/.test(src[j3])) j3++;
        } else {
          while (j3 < n && /[0-9.eE+\-]/.test(src[j3])) {
            if ((src[j3] === "+" || src[j3] === "-") && !/[eE]/.test(src[j3 - 1])) break;
            j3++;
          }
        }
        toks.push({ t: "number", v: src.slice(i, j3) });
        i = j3;
        continue;
      }

      // identifier / keyword
      if (isIdentStart(c)) {
        var j4 = i + 1;
        while (j4 < n && isIdentPart(src[j4])) j4++;
        var word = src.slice(i, j4);
        toks.push({ t: LUA_KEYWORDS[word] ? "keyword" : "ident", v: word });
        i = j4;
        continue;
      }

      // whitespace
      if (/\s/.test(c)) {
        var j5 = i;
        while (j5 < n && /\s/.test(src[j5])) j5++;
        toks.push({ t: "ws", v: src.slice(i, j5) });
        i = j5;
        continue;
      }

      // punctuation / operators (greedy multi-char)
      var three = src.substr(i, 3);
      var two = src.substr(i, 2);
      if (three === "..." ) { toks.push({ t: "op", v: three }); i += 3; continue; }
      if (["==", "~=", "<=", ">=", "..", "::", "//", ">>", "<<"].indexOf(two) !== -1) {
        toks.push({ t: "op", v: two }); i += 2; continue;
      }
      toks.push({ t: "op", v: c });
      i++;
    }
    return toks;
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------
  function randName(len) {
    var chars = "abcdefghijklmnopqrstuvwxyz";
    var mix = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
    var s = chars[(Math.random() * chars.length) | 0];
    // Luarmor-ish look: leading I/l/O mixes
    var pool = "IlO0";
    if (Math.random() < 0.5) s = pool[(Math.random() * pool.length) | 0].replace(/[0O]/, "O");
    for (var k = 1; k < len; k++) s += mix[(Math.random() * mix.length) | 0];
    return s;
  }

  function makeNamer() {
    var used = {};
    return function () {
      var name;
      do { name = randName(6 + ((Math.random() * 8) | 0)); }
      while (used[name] || LUA_KEYWORDS[name]);
      used[name] = 1;
      return name;
    };
  }

  // Parse a Lua string token into its raw bytes (best-effort, common escapes).
  function decodeLuaString(tok) {
    if (tok.long) {
      // strip [[ ]] / [=[ ]=]
      var m = tok.v.match(/^\[(=*)\[([\s\S]*?)\]\1\]$/);
      return m ? m[2] : tok.v;
    }
    var body = tok.v.slice(1, -1);
    var out = "", i = 0;
    while (i < body.length) {
      var c = body[i];
      if (c === "\\") {
        var nx = body[i + 1];
        var map = { n: "\n", t: "\t", r: "\r", a: "\x07", b: "\b", f: "\f", v: "\v", "\\": "\\", '"': '"', "'": "'", "\n": "\n" };
        if (map[nx] !== undefined) { out += map[nx]; i += 2; continue; }
        if (nx === "x") { out += String.fromCharCode(parseInt(body.substr(i + 2, 2), 16)); i += 4; continue; }
        if (/[0-9]/.test(nx)) {
          var num = body.substr(i + 1).match(/^[0-9]{1,3}/)[0];
          out += String.fromCharCode(parseInt(num, 10)); i += 1 + num.length; continue;
        }
        out += nx; i += 2; continue;
      }
      out += c; i++;
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // Transform passes
  // ---------------------------------------------------------------------------

  // Rename local identifiers. Strategy: rename idents declared with `local`
  // and function parameters. Conservative â€” skips table field access (after `.`
  // or `:`) and anything in the global/keyword lists.
  function renameLocals(toks) {
    var next = makeNamer();
    var map = {};

    function prevSignificant(idx) {
      for (var j = idx - 1; j >= 0; j--) {
        if (toks[j].t !== "ws" && toks[j].t !== "comment") return toks[j];
      }
      return null;
    }

    // First pass: collect declared locals + params.
    for (var i = 0; i < toks.length; i++) {
      var tk = toks[i];
      if (tk.t !== "ident") continue;
      var prev = prevSignificant(i);
      var isField = prev && prev.t === "op" && (prev.v === "." || prev.v === ":");
      if (isField) continue;
      if (LUA_GLOBALS[tk.v]) continue;

      // declared via `local x` / `local x, y`
      // or function param list. We approximate: any ident preceded (in significant
      // stream) by `local`, `,` after local, or inside `function name(...)` params.
      if (prev && prev.t === "keyword" && prev.v === "local") {
        if (!map[tk.v]) map[tk.v] = next();
      } else if (prev && prev.t === "keyword" && prev.v === "function") {
        // function NAME â€” treat local funcs as renamable only if simple
        // (skip to be safe: named functions often global). leave as-is.
      }
    }

    // Second pass: also catch comma-chained locals: local a, b, c
    for (i = 0; i < toks.length; i++) {
      if (toks[i].t === "keyword" && toks[i].v === "local") {
        var j = i + 1, sawEq = false;
        while (j < toks.length) {
          var t2 = toks[j];
          if (t2.t === "ws" || t2.t === "comment") { j++; continue; }
          if (t2.t === "op" && t2.v === "=") { sawEq = true; break; }
          if (t2.t === "op" && (t2.v === "\n" || t2.v === ";")) break;
          if (t2.t === "keyword" && t2.v !== "function") break;
          if (t2.t === "ident" && !LUA_GLOBALS[t2.v] && !map[t2.v]) {
            var p = prevSignificant(j);
            var fld = p && p.t === "op" && (p.v === "." || p.v === ":");
            if (!fld) map[t2.v] = next();
          }
          if (t2.t === "op" && t2.v !== "," ) { if (t2.v !== ".") { /* stop on non-comma */ } }
          if (t2.t === "op" && t2.v === "=") break;
          j++;
          if (j - i > 40) break;
        }
      }
    }

    // Apply the map, but never to fields.
    for (i = 0; i < toks.length; i++) {
      var t = toks[i];
      if (t.t !== "ident") continue;
      var pv = prevSignificant(i);
      if (pv && pv.t === "op" && (pv.v === "." || pv.v === ":")) continue;
      if (map[t.v]) t.v = map[t.v];
    }
    return toks;
  }

  // Encode string literals into a decoder call: __O_dec({b,y,t,e,s}, key)
  function encodeStrings(toks, decoderName, key) {
    for (var i = 0; i < toks.length; i++) {
      var t = toks[i];
      if (t.t !== "string") continue;
      var raw = decodeLuaString(t);
      if (raw.length === 0) continue;
      var bytes = [];
      for (var c = 0; c < raw.length; c++) {
        var code = raw.charCodeAt(c) & 0xff;
        bytes.push(code ^ (key + c) % 256 ^ key);
      }
      t.t = "encoded";
      t.v = decoderName + "({" + bytes.join(",") + "}," + key + ")";
    }
    return toks;
  }

  // Mangle simple integer literals into arithmetic (e.g. 100 -> (73+27)).
  function mangleNumbers(toks) {
    for (var i = 0; i < toks.length; i++) {
      var t = toks[i];
      if (t.t !== "number") continue;
      if (/[.xXeEpP]/.test(t.v)) continue; // only plain integers
      var val = parseInt(t.v, 10);
      if (isNaN(val) || Math.abs(val) > 1000000) continue;
      var a = (Math.random() * val) | 0;
      var b = val - a;
      t.v = "(" + a + "+" + b + ")";
    }
    return toks;
  }

  // ---------------------------------------------------------------------------
  // Emit
  // ---------------------------------------------------------------------------
  function emit(toks, opts) {
    var out = [];
    for (var i = 0; i < toks.length; i++) {
      var t = toks[i];
      if (t.t === "comment") { if (!opts.minify) out.push(t.v); continue; }
      if (t.t === "ws") {
        if (opts.minify) {
          // collapse to a single space only where needed between words/numbers
          var prev = toks[i - 1], nextT = toks[i + 1];
          var needsGap = prev && nextT &&
            (prev.t === "ident" || prev.t === "keyword" || prev.t === "number") &&
            (nextT.t === "ident" || nextT.t === "keyword" || nextT.t === "number");
          out.push(needsGap ? " " : (/\n/.test(t.v) ? "\n" : " "));
        } else {
          out.push(t.v);
        }
        continue;
      }
      out.push(t.v);
    }
    return out.join("");
  }

  function buildHeader(names, key, watermark) {
    var dec = names.dec;
    // XOR decoder that reverses encodeStrings, plus a lightweight integrity guard.
    var lines = [
      "--[[ " + (watermark || "Protected by O Protector â€” LuaRaptor style") + " ]]",
      "local " + dec + "=function(t,k)local s=\"\";for i=1,#t do local b=t[i];b=b~((k+(i-1))%256);b=b~k;s=s..string.char(b%256)end;return s end",
      "local " + names.guard + "=(function() local ok=pcall(function() return string.char(65) end); if not ok then while true do end end; return true end)()"
    ];
    return lines.join("\n") + "\n";
  }

  function injectJunk(toks, namer) {
    // Insert a few harmless dead-code locals at the top of the token stream.
    var junk = [];
    var count = 2 + ((Math.random() * 3) | 0);
    for (var i = 0; i < count; i++) {
      var nm = namer();
      var val = (Math.random() * 99999) | 0;
      junk.push({ t: "raw", v: "local " + nm + "=" + val + ";" });
    }
    junk.push({ t: "raw", v: "\n" });
    return junk.concat(toks);
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------
  function obfuscate(source, options) {
    options = options || {};
    var opts = {
      renameLocals: options.renameLocals !== false,
      encodeStrings: options.encodeStrings !== false,
      mangleNumbers: options.mangleNumbers !== false,
      injectJunk: options.injectJunk !== false,
      minify: options.minify !== false,
      watermark: options.watermark || "Protected by O Protector"
    };

    if (typeof source !== "string" || source.trim() === "") {
      throw new Error("Empty source: paste some Lua code first.");
    }

    var namer = makeNamer();
    var names = { dec: "_O" + randName(5), guard: "_O" + randName(5) };
    var key = 1 + ((Math.random() * 254) | 0);

    var toks = tokenize(source);

    if (opts.renameLocals) toks = renameLocals(toks);
    if (opts.mangleNumbers) toks = mangleNumbers(toks);
    if (opts.encodeStrings) toks = encodeStrings(toks, names.dec, key);
    if (opts.injectJunk) toks = injectJunk(toks, namer);

    var body = emit(toks, opts);
    var header = (opts.encodeStrings || true) ? buildHeader(names, key, opts.watermark) : "";

    return header + body + "\n";
  }

  var api = { obfuscate: obfuscate, tokenize: tokenize, version: "1.0.0" };
  global.OObfuscator = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : this);
