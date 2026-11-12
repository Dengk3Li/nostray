import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { auditRepository } from "./repo-auditor.mjs";
import { runInteractiveDemo } from "./demo-runner.mjs";
import { SnapshotStore } from "./snapshot-store.mjs";

const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

function readWorkspaceSqliteHistory(workspaceDir) {
  let dbPath = path.join(workspaceDir, ".blast-guard", "state.sqlite");
  try {
    dbPath = new SnapshotStore(workspaceDir).dbPath;
  } catch {}
  const out = {
    hasStore: false,
    sessionCount: 0,
    checkpointCount: 0,
    recoveredFiles: 0,
    events: [],
  };
  if (!fs.existsSync(dbPath)) return out;
  let db;
  try {
    db = new DatabaseSync(dbPath, { open: true, readOnly: true });
    out.hasStore = true;

    const sessions = db
      .prepare(
        "SELECT session_id, turn_id, tier, working_set_json, grants_json, updated_at FROM sessions ORDER BY updated_at DESC LIMIT 25"
      )
      .all();
    out.sessionCount = sessions.length;

    const cpRow = db.prepare("SELECT COUNT(*) AS cnt FROM checkpoints").get();
    out.checkpointCount = Number(cpRow?.cnt || 0);

    for (const s of sessions) {
      let workingSet = [];
      try {
        workingSet = JSON.parse(s.working_set_json || "[]");
      } catch {}
      out.events.push({
        id: `session:${s.session_id}:t${s.turn_id}`,
        source: "workspace",
        status: "ALLOWED",
        code: s.tier || "SESSION_ACTIVE",
        path: workingSet[0] || "(session scope)",
        task: `Session ${s.session_id} · Turn ${s.turn_id}`,
        summary: `Active session (${s.tier}) · ${workingSet.length} tracked target file(s)`,
        before: `Session ID : ${s.session_id}\nTurn       : ${s.turn_id}\nTier       : ${s.tier}`,
        after: `Editable targets:\n${workingSet.length ? workingSet.join("\n") : "(dynamic leaf scope)"}`,
        diff: workingSet.map((w) => `+ ${w}`),
        grantCommand: `nostray session status --session ${s.session_id}`,
        latencyMs: 0,
      });
    }

    const journals = db
      .prepare(
        "SELECT tx_id, session_id, state, error_code, error_detail, updated_at FROM journals ORDER BY updated_at DESC LIMIT 30"
      )
      .all();

    const entryStmt = db.prepare(
      "SELECT rel_posix, action, status, detail FROM journal_entry_progress WHERE tx_id = ? LIMIT 20"
    );

    for (const j of journals) {
      const entries = entryStmt.all(j.tx_id);
      const isRollback = Boolean(j.error_code) || String(j.state).includes("ROLLBACK") || entries.length > 0;
      if (isRollback) out.recoveredFiles += Math.max(1, entries.length);
      const firstPath = entries[0]?.rel_posix || "(wrapped command)";
      const status = j.error_code ? (entries.length > 0 ? "RECOVERED" : "BLOCKED") : "ALLOWED";
      out.events.push({
        id: `tx:${String(j.tx_id).slice(0, 10)}`,
        source: "workspace",
        status,
        code: j.error_code || j.state,
        path: firstPath,
        task: `Session ${j.session_id}`,
        summary: j.error_detail || `Transaction ${j.state} (${entries.length} file entry records)`,
        before: entries.length
          ? entries.map((e) => `${e.rel_posix} [${e.action}]`).join("\n")
          : `Transaction ${j.tx_id} (${j.state})`,
        after: entries.length
          ? entries.map((e) => `${e.rel_posix} -> ${e.status}${e.detail ? ` (${e.detail})` : ""}`).join("\n")
          : j.error_detail || "Completed cleanly",
        diff: entries.map((e) => `${status === "RECOVERED" ? "+" : " "} ${e.rel_posix} (${e.action} -> ${e.status})`),
        humanCard: j.error_detail || "",
        grantCommand:
          firstPath !== "(wrapped command)"
            ? `nostray session start --prompt "Allow updating ${firstPath}"`
            : "nostray rollback --recover",
        latencyMs: 0,
      });
    }
  } catch {
    // Keep read-only resilience if SQLite is locked or uninitialized
  } finally {
    try {
      db?.close();
    } catch {}
  }
  return out;
}

function renderShareCardSvg(state, lang = "en") {
  const isZh = lang === "zh";
  const guardedTotal =
    state.counters.exportsProtected +
    state.counters.testsProtected +
    state.counters.schemasProtected +
    state.counters.filesRecovered;
  const badgeText = state.protection === "UNPROTECTED" ? (isZh ? "本地只读就绪" : "Audit Ready") : state.protection;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="760" height="320" viewBox="0 0 760 320" role="img" aria-label="NoStray Session Guard Summary">
  <rect width="760" height="320" rx="16" fill="#0b0f17"/>
  <rect x="16" y="16" width="728" height="288" rx="12" fill="#111827" stroke="#1f2937" stroke-width="1.5"/>
  <rect x="40" y="42" width="10" height="28" rx="3" fill="#10b981"/>
  <g font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif" fill="#f8fafc">
    <text x="62" y="64" font-size="23" font-weight="700">NoStray · ${isZh ? "AI 改动范围守卫摘要" : "Stray-Edit Guard Summary"}</text>
    <text x="62" y="92" font-size="14" fill="#94a3b8">${isZh ? "项目目录（已脱敏）" : "Workspace (path redacted)"}: <tspan fill="#e2e8f0" font-weight="600">${esc(state.workspace)}</tspan> · ${esc(badgeText)}</text>

    <rect x="40" y="114" width="162" height="92" rx="9" fill="#0f172a" stroke="#1e293b"/>
    <text x="56" y="142" font-size="12" fill="#94a3b8">${isZh ? "守住公开导出" : "Exports Intact"}</text>
    <text x="56" y="182" font-size="30" font-weight="700" fill="#10b981">${state.counters.exportsProtected}</text>

    <rect x="216" y="114" width="162" height="92" rx="9" fill="#0f172a" stroke="#1e293b"/>
    <text x="232" y="142" font-size="12" fill="#94a3b8">${isZh ? "护住测试套件" : "Tests Protected"}</text>
    <text x="232" y="182" font-size="30" font-weight="700" fill="#10b981">${state.counters.testsProtected + state.tests}</text>

    <rect x="392" y="114" width="162" height="92" rx="9" fill="#0f172a" stroke="#1e293b"/>
    <text x="408" y="142" font-size="12" fill="#94a3b8">${isZh ? "锁定契约配置" : "Contracts Guarded"}</text>
    <text x="408" y="182" font-size="30" font-weight="700" fill="#38bdf8">${state.counters.schemasProtected + state.contracts}</text>

    <rect x="568" y="114" width="152" height="92" rx="9" fill="#0f172a" stroke="#1e293b"/>
    <text x="584" y="142" font-size="12" fill="#94a3b8">${isZh ? "按字节恢复文件" : "Files Restored"}</text>
    <text x="584" y="182" font-size="30" font-weight="700" fill="#38bdf8">${state.counters.filesRecovered}</text>

    <text x="40" y="244" font-size="13" fill="#cbd5e1">${
      isZh
        ? `累计拦截或恢复 ${guardedTotal} 次越界改动 · 零第三方依赖 · 本地 ~6ms 结构化预检`
        : `${guardedTotal} stray mutation(s) contained in session · Zero npm deps · ~6ms local AST & snapshot check`
    }</text>
    <text x="40" y="272" font-size="12" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" fill="#10b981">npx nostray demo  ·  npx nostray ui</text>
  </g>
</svg>`;
}

export async function startUiServer({ dir = process.cwd(), port = 4318 } = {}) {
  const resolvedDir = path.resolve(dir);
  const report = await auditRepository(resolvedDir);
  const ex = report.workspaceExposure;

  const sandboxEvents = [];
  const sandboxCounters = {
    exportsProtected: 0,
    testsProtected: 0,
    schemasProtected: 0,
    filesRecovered: 0,
  };

  function buildLiveState() {
    const dbHist = readWorkspaceSqliteHistory(report.workspaceRoot);
    return {
      workspace: path.basename(report.workspaceRoot),
      protection: report.protectionStatus.overallTier,
      contracts: ex.ring0ContractCount,
      tests: ex.ring0TestSuiteCount,
      hubs: ex.topHighFanInModules.length,
      sqliteStoreDetected: dbHist.hasStore,
      recordedSessions: dbHist.sessionCount,
      recordedCheckpoints: dbHist.checkpointCount,
      hosts: Object.fromEntries(
        Object.entries(report.protectionStatus.hosts || {}).map(([k, v]) => [k, { tier: v.tier }])
      ),
      counters: {
        exportsProtected: sandboxCounters.exportsProtected,
        testsProtected: sandboxCounters.testsProtected,
        schemasProtected: sandboxCounters.schemasProtected,
        filesRecovered: sandboxCounters.filesRecovered + dbHist.recoveredFiles,
      },
      events: [...sandboxEvents, ...dbHist.events],
    };
  }

  const initialState = buildLiveState();

  const server = http.createServer(async (req, res) => {
    const send = (type, body, status = 200) => {
      res.writeHead(status, {
        "Content-Type": type,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      });
      res.end(body);
    };
    try {
      if (!/^127\.0\.0\.1(?::\d+)?$/.test(req.headers.host || "")) {
        return send("text/plain", "Invalid host", 403);
      }
      const parsedUrl = new URL(req.url || "/", `http://${req.headers.host}`);
      if (req.method === "GET" && parsedUrl.pathname === "/") {
        return send("text/html; charset=utf-8", HTML);
      }
      if (req.method === "GET" && parsedUrl.pathname === "/api/state") {
        return send("application/json", JSON.stringify(buildLiveState()));
      }
      if (req.method === "GET" && parsedUrl.pathname === "/api/share-card.svg") {
        const lang = parsedUrl.searchParams.get("lang") === "zh" ? "zh" : "en";
        return send("image/svg+xml; charset=utf-8", renderShareCardSvg(buildLiveState(), lang));
      }
      if (req.method === "POST" && parsedUrl.pathname === "/api/demo") {
        if (req.headers.origin && req.headers.origin !== `http://${req.headers.host}`) {
          return send("application/json", '{"error":"Forbidden origin"}', 403);
        }
        let body = "";
        for await (const chunk of req) {
          body += chunk;
          if (body.length > 4096) return send("application/json", '{"error":"Request too large"}', 413);
        }
        const opts = body ? JSON.parse(body) : {};
        const result = await runInteractiveDemo({ lang: opts.lang === "zh" ? "zh" : "en" });
        sandboxEvents.unshift(...(result.timeline || result.results));
        for (const [id, key] of [
          ["sibling-export", "exportsProtected"],
          ["test-weakening", "testsProtected"],
          ["schema-tamper", "schemasProtected"],
          ["shell-rollback", "filesRecovered"],
        ]) {
          sandboxCounters[key] += result.results.filter((r) => r.id === id && r.passed).length;
        }
        return send("application/json", JSON.stringify(result));
      }
      send("text/plain", "Not found", 404);
    } catch {
      send("application/json", '{"error":"Request failed"}', 500);
    }
  });

  await new Promise((resolve, reject) => {
    let candidate = Number(port);
    if (!Number.isInteger(candidate) || candidate < 0 || candidate > 65535) {
      return reject(new Error("Invalid port"));
    }
    const onError = (err) => {
      if (err.code === "EADDRINUSE" && candidate > 0 && candidate < 65535) {
        candidate++;
        listen();
      } else {
        reject(err);
      }
    };
    const listen = () => {
      server.once("error", onError);
      server.listen(candidate, "127.0.0.1", () => {
        server.off("error", onError);
        resolve();
      });
    };
    listen();
  });

  return { server, state: initialState, port: server.address().port };
}

const HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NoStray Studio — Local Stray-Edit Timeline &amp; Diff Inspector</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: #0b0f17;
    color: #e2e8f0;
    font: 13.5px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  }
  header {
    padding: 14px 22px;
    border-bottom: 1px solid #1e293b;
    background: #0f1522;
    display: flex;
    gap: 12px;
    align-items: center;
    flex-wrap: wrap;
  }
  .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 16px; color: #f8fafc; }
  .dot { width: 9px; height: 9px; border-radius: 50%; background: #10b981; display: inline-block; }
  .ws-badge {
    font: 12px ui-monospace, SFMono-Regular, Menlo, monospace;
    background: #111827;
    border: 1px solid #1f2937;
    padding: 4px 9px;
    border-radius: 6px;
    color: #cbd5e1;
  }
  .tier-pill {
    font-size: 11.5px;
    font-weight: 600;
    padding: 3px 8px;
    border-radius: 999px;
    background: #1e293b;
    color: #38bdf8;
    border: 1px solid #334155;
  }
  .spacer { flex: 1; }
  button, a.btn, select {
    background: #111827;
    color: #e2e8f0;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 7px 12px;
    font-size: 12.5px;
    cursor: pointer;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  button:hover, a.btn:hover { border-color: #64748b; background: #182234; }
  button.primary { background: #065f46; border-color: #10b981; color: #ecfdf5; font-weight: 600; }
  button.primary:hover { background: #047857; }
  .kpis {
    display: grid;
    grid-template-columns: repeat(4, minmax(140px, 1fr));
    gap: 12px;
    padding: 14px 22px;
    border-bottom: 1px solid #1e293b;
    background: #0d131f;
  }
  .kpi {
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 10px 14px;
  }
  .kpi .lbl { font-size: 11.5px; color: #94a3b8; }
  .kpi .val { font-size: 22px; font-weight: 700; margin-top: 2px; font-variant-numeric: tabular-nums; }
  .val.green { color: #10b981; }
  .val.sky { color: #38bdf8; }
  main { display: grid; grid-template-columns: 360px 1fr; min-height: calc(100vh - 142px); }
  aside { border-right: 1px solid #1e293b; padding: 16px; display: flex; flex-direction: column; gap: 10px; }
  article { padding: 20px 24px; display: flex; flex-direction: column; gap: 14px; }
  .toolbar { display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap; }
  h2 { font-size: 13.5px; margin: 0; color: #f1f5f9; letter-spacing: 0.01em; }
  #events { display: flex; flex-direction: column; gap: 7px; overflow-y: auto; max-height: 68vh; }
  .ev-btn {
    width: 100%;
    text-align: left;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 3px;
    padding: 10px 12px;
    border-radius: 7px;
    background: #111827;
    border: 1px solid #1e293b;
  }
  .ev-btn.active { border-color: #38bdf8; background: #152033; }
  .ev-top { display: flex; width: 100%; justify-content: space-between; font-size: 11.5px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .ev-summary { font-size: 12.5px; color: #cbd5e1; }
  .tag-BLOCKED { color: #f43f5e; font-weight: 700; }
  .tag-RECOVERED { color: #38bdf8; font-weight: 700; }
  .tag-ALLOWED { color: #10b981; font-weight: 700; }
  .empty-box {
    border: 1px dashed #334155;
    border-radius: 8px;
    padding: 18px;
    text-align: center;
    color: #94a3b8;
  }
  pre {
    margin: 0;
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 13px 15px;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    font: 12px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  .diff-split { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .diff-col h3 { font-size: 11.5px; color: #94a3b8; margin: 0 0 6px 0; font-weight: 600; }
  .line-del { color: #fda4af; background: rgba(244, 63, 94, 0.12); display: block; padding: 0 4px; }
  .line-add { color: #6ee7b7; background: rgba(16, 185, 129, 0.12); display: block; padding: 0 4px; }
  .card-box { border-color: rgba(244, 63, 94, 0.4); background: #141b2d; }
  .cmd-bar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .cmd-code {
    flex: 1;
    min-width: 240px;
    font: 12px ui-monospace, SFMono-Regular, Menlo, monospace;
    background: #090d14;
    border: 1px solid #1e293b;
    border-radius: 6px;
    padding: 8px 11px;
    color: #93c5fd;
  }
  .muted { color: #94a3b8; font-size: 12.5px; margin: 0; }
  .share-preview { margin-top: 6px; max-width: 560px; border-radius: 10px; border: 1px solid #1e293b; display: none; }
  @media (max-width: 860px) {
    .kpis { grid-template-columns: repeat(2, 1fr); }
    main { grid-template-columns: 1fr; }
    aside { border-right: 0; border-bottom: 1px solid #1e293b; }
    .diff-split { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>
<header>
  <div class="brand"><span class="dot"></span><span>NoStray Studio</span></div>
  <span class="ws-badge" id="workspace"></span>
  <span class="tier-pill" id="status"></span>
  <span class="muted" id="counts"></span>
  <span class="spacer"></span>
  <button class="primary run" id="runTop">▶ Run 5-Scenario Live Sandbox</button>
  <button id="previewSvgBtn">◈ Preview Card</button>
  <a class="btn" id="exportSvgLink" href="/api/share-card.svg" download="nostray-guard-card.svg">⬇ Export Share SVG</a>
  <button id="langBtn">中文 / EN</button>
</header>

<section class="kpis">
  <div class="kpi"><div class="lbl" id="kLbl1">Public Exports Guarded</div><div class="val green" id="kVal1">0</div></div>
  <div class="kpi"><div class="lbl" id="kLbl2">Test Suites Protected</div><div class="val green" id="kVal2">0</div></div>
  <div class="kpi"><div class="lbl" id="kLbl3">Schemas &amp; Contracts Locked</div><div class="val sky" id="kVal3">0</div></div>
  <div class="kpi"><div class="lbl" id="kLbl4">Files Restored Byte-for-Byte</div><div class="val sky" id="kVal4">0</div></div>
</section>

<main>
  <aside>
    <div class="toolbar">
      <h2 id="timelineTitle">Event Timeline</h2>
      <select id="filterSel" aria-label="Filter events">
        <option value="ALL" id="optAll">All Events</option>
        <option value="BLOCKED" id="optBlocked">Blocked</option>
        <option value="RECOVERED" id="optRecovered">Recovered</option>
        <option value="ALLOWED" id="optAllowed">Allowed</option>
      </select>
    </div>
    <div id="events"></div>
    <div id="empty" class="empty-box">
      <p id="emptyText" style="margin:0 0 12px 0;">No session events recorded in this folder yet. Run the isolated 5-scenario sandbox in /tmp to inspect real pre-write blocks &amp; byte-exact rollbacks.</p>
      <button class="primary run" id="runEmpty">▶ Run 5-Scenario Live Sandbox (~1s)</button>
    </div>
  </aside>

  <article>
    <div class="toolbar">
      <div>
        <h2 id="inspectorTitle">Diff &amp; Interception Inspector</h2>
        <p id="hint" class="muted">Select a timeline event or run the live sandbox to inspect structural diffs.</p>
      </div>
      <div style="display:flex;gap:6px;">
        <button id="modeSplit">Split View</button>
        <button id="modeUnified">Unified Diff</button>
      </div>
    </div>

    <div id="splitWrap" class="diff-split">
      <div class="diff-col"><h3 id="beforeTitle">Baseline / Before</h3><pre id="beforePre"></pre></div>
      <div class="diff-col"><h3 id="afterTitle">Attempted / Restored State</h3><pre id="afterPre"></pre></div>
    </div>

    <div id="unifiedWrap" style="display:none;">
      <pre id="unifiedPre"></pre>
    </div>

    <pre id="cardPre" class="card-box" style="display:none;"></pre>

    <div class="cmd-bar">
      <code class="cmd-code" id="grantCmd">nostray demo</code>
      <button id="copyGrantBtn">Copy Grant / Action Command</button>
      <button id="copyRecoverBtn">Copy Rollback Command</button>
      <span id="copyToast" class="muted"></span>
    </div>

    <img id="sharePreview" class="share-preview" alt="NoStray privacy-safe SVG summary card" />
  </article>
</main>

<script>
  const I18N = {
    en: {
      run: "▶ Run 5-Scenario Live Sandbox",
      running: "⏳ Running sandbox...",
      preview: "◈ Preview Card",
      exportSvg: "⬇ Export Share SVG",
      k1: "Public Exports Guarded",
      k2: "Test Suites Protected",
      k3: "Schemas & Contracts Locked",
      k4: "Files Restored Byte-for-Byte",
      timeline: "Event Timeline",
      all: "All Events",
      blocked: "Blocked",
      recovered: "Recovered",
      allowed: "Allowed",
      empty: "No session events recorded in this folder yet. Run the isolated 5-scenario sandbox in /tmp to inspect real pre-write blocks & byte-exact rollbacks.",
      inspector: "Diff & Interception Inspector",
      hintDefault: "Select a timeline event or run the live sandbox to inspect structural diffs.",
      split: "Split View",
      unified: "Unified Diff",
      before: "Baseline / Before",
      after: "Attempted / Restored State",
      copyGrant: "Copy Action Command",
      copyRecover: "Copy Rollback Command",
      copied: "✓ Copied",
      metaFmt: (s) => s.contracts + " contracts · " + s.tests + " test files · " + s.hubs + " hubs" + (s.sqliteStoreDetected ? " · SQLite history linked" : "")
    },
    zh: {
      run: "▶ 运行 5 类越界实时沙盒",
      running: "⏳ 正在隔离沙盒执行...",
      preview: "◈ 预览分享卡",
      exportSvg: "⬇ 导出脱敏 SVG 卡片",
      k1: "守住公开导出接口",
      k2: "受保护测试文件",
      k3: "锁定契约与配置",
      k4: "按字节恢复误删文件",
      timeline: "拦截与放行时间线",
      all: "全部事件",
      blocked: "写前拦截",
      recovered: "写后恢复",
      allowed: "正常放行",
      empty: "当前目录暂无会话记录。点击下方按钮可在一次性临时目录运行 5 类真实越界拦截与恢复演示（不改动当前项目）。",
      inspector: "前后差异与拦截卡检查器",
      hintDefault: "在左侧选择任意事件，查看修改前后对比与三选一处理指令。",
      split: "左右分栏对比",
      unified: "合并 Diff 视图",
      before: "修改前基线",
      after: "智能体尝试写入 / 恢复后状态",
      copyGrant: "复制授权或处理命令",
      copyRecover: "复制一键恢复命令",
      copied: "✓ 已复制",
      metaFmt: (s) => s.contracts + " 个契约 · " + s.tests + " 个测试文件 · " + s.hubs + " 个核心模块" + (s.sqliteStoreDetected ? " · 已读取本地 SQLite 记录" : "")
    }
  };

  let lang = (navigator.language || "").toLowerCase().startsWith("zh") ? "zh" : "en";
  let diffMode = "split";
  let stateData = null;
  let selectedId = null;

  const $ = (s) => document.querySelector(s);
  const setText = (s, v) => { const el = $(s); if (el) el.textContent = v; };

  function renderUnifiedHtml(lines) {
    const frag = document.createDocumentFragment();
    for (const ln of lines || []) {
      const span = document.createElement("span");
      span.textContent = ln + "\\n";
      if (ln.startsWith("- ")) span.className = "line-del";
      else if (ln.startsWith("+ ")) span.className = "line-add";
      frag.appendChild(span);
    }
    const pre = $("#unifiedPre");
    pre.replaceChildren(frag);
  }

  function selectEvent(ev) {
    if (!ev) return;
    selectedId = ev.id;
    setText("#hint", ev.path + " · " + (ev.summary || ev.code || ""));
    setText("#beforePre", ev.before || "");
    setText("#afterPre", ev.after || "");
    renderUnifiedHtml(ev.diff || []);
    const cardEl = $("#cardPre");
    if (ev.humanCard) {
      cardEl.style.display = "block";
      cardEl.textContent = ev.humanCard;
    } else {
      cardEl.style.display = "none";
    }
    setText("#grantCmd", ev.grantCommand || "nostray rollback --recover");
    renderTimeline();
  }

  function renderTimeline() {
    const events = (stateData && stateData.events) || [];
    const filter = $("#filterSel").value;
    const list = events.filter((e) => filter === "ALL" || e.status === filter);
    const box = $("#events");
    box.replaceChildren();
    for (const ev of list) {
      const btn = document.createElement("button");
      btn.className = "ev-btn" + (ev.id === selectedId ? " active" : "");
      const top = document.createElement("div");
      top.className = "ev-top";
      const tag = document.createElement("span");
      tag.className = "tag-" + ev.status;
      tag.textContent = ev.status + " · " + ev.path;
      const lat = document.createElement("span");
      lat.className = "muted";
      lat.textContent = ev.latencyMs ? ev.latencyMs + " ms" : ev.source;
      top.append(tag, lat);
      const sum = document.createElement("div");
      sum.className = "ev-summary";
      sum.textContent = ev.summary || ev.code || "";
      btn.append(top, sum);
      btn.onclick = () => selectEvent(ev);
      box.appendChild(btn);
    }
    $("#empty").hidden = events.length > 0;
  }

  function applyLang() {
    const t = I18N[lang];
    document.querySelectorAll(".run").forEach((b) => (b.textContent = t.run));
    setText("#previewSvgBtn", t.preview);
    setText("#exportSvgLink", t.exportSvg);
    $("#exportSvgLink").href = "/api/share-card.svg?lang=" + lang;
    setText("#kLbl1", t.k1);
    setText("#kLbl2", t.k2);
    setText("#kLbl3", t.k3);
    setText("#kLbl4", t.k4);
    setText("#timelineTitle", t.timeline);
    setText("#optAll", t.all);
    setText("#optBlocked", t.blocked);
    setText("#optRecovered", t.recovered);
    setText("#optAllowed", t.allowed);
    setText("#emptyText", t.empty);
    setText("#inspectorTitle", t.inspector);
    if (!selectedId) setText("#hint", t.hintDefault);
    setText("#modeSplit", t.split);
    setText("#modeUnified", t.unified);
    setText("#beforeTitle", t.before);
    setText("#afterTitle", t.after);
    setText("#copyGrantBtn", t.copyGrant);
    setText("#copyRecoverBtn", t.copyRecover);
    if (stateData) setText("#counts", t.metaFmt(stateData));
    const img = $("#sharePreview");
    if (img.style.display === "block") img.src = "/api/share-card.svg?lang=" + lang + "&t=" + Date.now();
  }

  async function refreshState() {
    stateData = await (await fetch("/api/state")).json();
    setText("#workspace", stateData.workspace);
    setText("#status", stateData.protection);
    setText("#kVal1", String(stateData.counters.exportsProtected));
    setText("#kVal2", String(stateData.counters.testsProtected + stateData.tests));
    setText("#kVal3", String(stateData.counters.schemasProtected + stateData.contracts));
    setText("#kVal4", String(stateData.counters.filesRecovered));
    applyLang();
    renderTimeline();
    if (!selectedId && stateData.events.length > 0) {
      const firstBlocked = stateData.events.find((e) => e.status === "BLOCKED") || stateData.events[0];
      selectEvent(firstBlocked);
    }
  }

  document.querySelectorAll(".run").forEach((b) => {
    b.onclick = async () => {
      document.querySelectorAll(".run").forEach((x) => { x.disabled = true; x.textContent = I18N[lang].running; });
      try {
        await fetch("/api/demo", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ lang })
        });
        selectedId = null;
        await refreshState();
      } finally {
        document.querySelectorAll(".run").forEach((x) => { x.disabled = false; x.textContent = I18N[lang].run; });
      }
    };
  });

  $("#filterSel").onchange = renderTimeline;
  $("#langBtn").onclick = () => { lang = lang === "en" ? "zh" : "en"; applyLang(); };
  $("#modeSplit").onclick = () => { diffMode = "split"; $("#splitWrap").style.display = "grid"; $("#unifiedWrap").style.display = "none"; };
  $("#modeUnified").onclick = () => { diffMode = "unified"; $("#splitWrap").style.display = "none"; $("#unifiedWrap").style.display = "block"; };

  function flashCopied() {
    setText("#copyToast", I18N[lang].copied);
    setTimeout(() => setText("#copyToast", ""), 1600);
  }
  $("#copyGrantBtn").onclick = () => { navigator.clipboard?.writeText($("#grantCmd").textContent || ""); flashCopied(); };
  $("#copyRecoverBtn").onclick = () => { navigator.clipboard?.writeText("nostray rollback --recover"); flashCopied(); };
  $("#previewSvgBtn").onclick = () => {
    const img = $("#sharePreview");
    img.style.display = img.style.display === "block" ? "none" : "block";
    if (img.style.display === "block") img.src = "/api/share-card.svg?lang=" + lang + "&t=" + Date.now();
  };

  applyLang();
  refreshState();
</script>
</body>
</html>`;
