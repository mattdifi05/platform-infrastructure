function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function safeHref(value) {
  try {
    const url = new URL(String(value || ""));
    return (url.protocol === "https:" || url.protocol === "http:") && !url.username && !url.password ? url.href : "";
  } catch {
    return "";
  }
}

function inlineMarkdown(value, allowedHrefs) {
  let escaped = escapeHtml(value);
  escaped = escaped.replace(/!\[([^\]]*)\]\([^)\s]+\)/g, "$1");
  escaped = escaped.replace(/`([^`]+)`/g, "<code>$1</code>");
  escaped = escaped.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  escaped = escaped.replace(/(^|[^*])\*([^*]+)\*/g, "$1<em>$2</em>");
  return escaped.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (match, label, href) => {
    const safe = safeHref(href);
    return safe && allowedHrefs?.has(safe) ? `<a href="${escapeHtml(safe)}" target="_blank" rel="noopener noreferrer">${label}</a>` : label;
  });
}

/**
 * Small, deterministic Markdown subset for model output. HTML is always
 * escaped first; only elements constructed in this function are emitted.
 */
function tableCells(line) {
  if (typeof line !== "string" || !line.includes("|")) return null;
  var cells = [], cell = "", fence = 0;
  for (var i = 0; i < line.length; i += 1) {
    var char = line[i];
    if (char === "\\" && line[i + 1] === "|") { cell += "|"; i += 1; continue; }
    if (char === "`") {
      var count = 1;
      while (line[i + count] === "`") count += 1;
      if (!fence) fence = count; else if (fence === count) fence = 0;
      cell += "`".repeat(count); i += count - 1; continue;
    }
    if (char === "|" && !fence) { cells.push(cell.trim()); cell = ""; }
    else cell += char;
  }
  cells.push(cell.trim());
  if (line.trimStart().startsWith("|")) cells.shift();
  if (line.trimEnd().endsWith("|") && !line.trimEnd().endsWith("\\|")) cells.pop();
  return cells.length >= 1 && cells.length <= 32 ? cells : null;
}

function tableHeader(lines, index) {
  var header = tableCells(lines[index]);
  var divider = tableCells(lines[index + 1]);
  return header && divider && header.length === divider.length && divider.every(function (cell) { return /^:?-{3,}:?$/.test(cell); }) ? header : null;
}

function markdownTable(lines, index, allowedHrefs) {
  var header = tableHeader(lines, index);
  if (!header) return null;
  var divider = tableCells(lines[index + 1]);
  var aligns = divider.map(function (cell) { return cell.endsWith(":") ? (cell.startsWith(":") ? "center" : "right") : "left"; });
  var head = header.map(function (cell, col) { return '<th scope="col" class="server-ai-cell-' + aligns[col] + '">' + inlineMarkdown(cell, allowedHrefs) + '</th>'; }).join("");
  var rows = []; index += 2;
  while (index < lines.length) {
    var cells = tableCells(lines[index]);
    if (!cells || cells.length > header.length) break;
    while (cells.length < header.length) cells.push("");
    rows.push('<tr>' + cells.map(function (cell, col) { return '<td class="server-ai-cell-' + aligns[col] + '">' + inlineMarkdown(cell, allowedHrefs) + '</td>'; }).join("") + '</tr>');
    index += 1;
  }
  return { next: index, html: '<div class="server-ai-table-scroll" tabindex="0" role="region" aria-label="Tabella nella risposta"><table><thead><tr>' + head + '</tr></thead><tbody>' + rows.join("") + '</tbody></table></div>' };
}

export function renderServerAiMarkdown(value, allowedHrefs = new Set()) {
  const lines = String(value ?? "").replace(/\r\n?/g, "\n").split("\n");
  const output = [];
  let index = 0;
  let codeIndex = 0;

  while (index < lines.length) {
    const line = lines[index];
    const fence = line.match(/^```([^`]*)$/);
    if (fence) {
      const language = escapeHtml(fence[1].trim().slice(0, 32));
      const code = [];
      index += 1;
      while (index < lines.length && !/^```\s*$/.test(lines[index])) {
        code.push(lines[index]);
        index += 1;
      }
      if (index < lines.length) index += 1;
      output.push(`<pre class="server-ai-code"><span class="server-ai-code-head"><span>${language || "code"}</span><button type="button" data-ai-copy-code aria-label="Copia codice">Copia</button></span><code>${escapeHtml(code.join("\n"))}</code></pre>`);
      codeIndex += 1;
      continue;
    }
    var table = markdownTable(lines, index, allowedHrefs);
    if (table) { output.push(table.html); index = table.next; continue; }
    const heading = line.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      const level = heading[1].length + 2;
      output.push(`<h${level}>${inlineMarkdown(heading[2], allowedHrefs)}</h${level}>`);
      index += 1;
      continue;
    }
    if (/^\s*[-*]\s+/.test(line)) {
      const entries = [];
      while (index < lines.length && /^\s*[-*]\s+/.test(lines[index])) {
        entries.push(`<li>${inlineMarkdown(lines[index].replace(/^\s*[-*]\s+/, ""), allowedHrefs)}</li>`);
        index += 1;
      }
      output.push(`<ul>${entries.join("")}</ul>`);
      continue;
    }
    if (/^\s*\d+\.\s+/.test(line)) {
      const entries = [];
      while (index < lines.length && /^\s*\d+\.\s+/.test(lines[index])) {
        entries.push(`<li>${inlineMarkdown(lines[index].replace(/^\s*\d+\.\s+/, ""), allowedHrefs)}</li>`);
        index += 1;
      }
      output.push(`<ol>${entries.join("")}</ol>`);
      continue;
    }
    if (!line.trim()) {
      index += 1;
      continue;
    }
    const paragraph = [line];
    index += 1;
    while (index < lines.length && lines[index].trim() && !/^```/.test(lines[index]) && !/^(#{1,3})\s+/.test(lines[index]) && !/^\s*(?:[-*]|\d+\.)\s+/.test(lines[index]) && !tableHeader(lines, index)) {
      paragraph.push(lines[index]);
      index += 1;
    }
    output.push(`<p>${inlineMarkdown(paragraph.join("\n"), allowedHrefs).replaceAll("\n", "<br>")}</p>`);
  }
  return output.join("") || "<p></p>";
}

function gpuMemoryLabel(value) {
  const mib = Number(value);
  if (!Number.isFinite(mib) || mib < 0) return "";
  if (mib >= 1024) return `${Math.round(mib / 102.4) / 10} GB`;
  return `${Math.round(mib)} MB`;
}

/** A compact, presentation-only status. It is deliberately independent of /ps. */
export function formatServerAiGpuStatus(gpu) {
  if (!gpu || gpu.available !== true) return "Non disponibile · CPU possibile";
  const parts = [String(gpu.name || "GPU locale").slice(0, 120)];
  const used = gpuMemoryLabel(gpu.memoryUsedMiB);
  const total = gpuMemoryLabel(gpu.memoryTotalMiB);
  if (used && total) parts.push(`VRAM ${used} / ${total}`);
  const utilization = Number(gpu.utilizationPercent);
  if (Number.isFinite(utilization) && utilization >= 0 && utilization <= 100) parts.push(`${Math.round(utilization)}%`);
  const temperature = Number(gpu.temperatureC);
  if (Number.isFinite(temperature) && temperature >= 0 && temperature <= 150) parts.push(`${Math.round(temperature)} °C`);
  if (gpu.stale === true) parts.push("Dati non aggiornati");
  return parts.join(" · ");
}

export function formatServerAiMachineState(status) {
  const state = String(status?.state || "unavailable").toLowerCase();
  if (state === "active") return "Server AI attivo";
  if (state === "degraded") return "Chat attiva";
  if (state === "disabled") return "Server AI disattivato";
  if (state === "starting") return "Avvio di Server AI";
  if (state === "stopping") return "Arresto di Server AI";
  return "Server AI non disponibile";
}

const aiIcon = (name) => {
  const paths = {
    plus: '<path d="M12 5v14M5 12h14"/>',
    search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 4.5 4.5"/>',
    settings: '<path d="M4 7h7m4 0h5M4 17h3m4 0h9"/><circle cx="13" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>',
    arrow: '<path d="M12 19V5m-6 6 6-6 6 6"/>',
    close: '<path d="m6 6 12 12M6 18 18 6"/>',
    sidebar: '<path d="M9 6h11M9 12h11M9 18h11M4 6h.01M4 12h.01M4 18h.01"/>',
    power: '<path d="M12 3v9m-5.5-7a9 9 0 1 0 11 0"/>',
    attach: '<path d="m20.5 11.5-8.2 8.2a5 5 0 0 1-7.1-7.1l8.6-8.6a3.5 3.5 0 1 1 5 5l-8.7 8.7a2 2 0 1 1-2.8-2.8l7.8-7.8"/>',
    bolt: '<path d="m13 2-9 12h7l-1 8 9-12h-7z"/>',
    more: '<circle cx="12" cy="5" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="12" cy="19" r="1"/>',
    server: '<rect x="4" y="3" width="16" height="7" rx="2"/><rect x="4" y="14" width="16" height="7" rx="2"/><path d="M8 6.5h.01M8 17.5h.01"/>',
    cube: '<path d="m12 3 9 5v9l-9 5-9-5V8l9-5Zm0 9v10M3 8l9 5 9-5"/>',
    activity: '<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M9 8h6M9 12h6M9 16h3"/>',
    diagonal: '<path d="M6 18 18 6M7 6h11v11"/>',
  };
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.plus}</svg>`;
};

export function renderServerAiEmpty() {
  const starters = [
    ["server", "Stato del VPS", "Verifica lo stato attuale e le anomalie.", "Controlla lo stato attuale del VPS e segnala solo problemi sostenuti da dati recenti."],
    ["cube", "Servizi e container", "Controlla disponibilità e log recenti.", "Controlla servizi e container infrastrutturali effettivamente presenti."],
    ["activity", "Backup e attività", "Verifica esiti e pianificazioni sul server.", "Controlla gli esiti dei backup e le pianificazioni server-side visibili dagli strumenti."],
  ];
  return `<section class="server-ai-empty" data-ai-empty><h2>Da dove iniziamo?</h2><p>Chiedimi di verificare il server o di intervenire sull’infrastruttura.</p><div class="server-ai-suggestions">${starters.map(([icon, label, detail, prompt]) => `<button type="button" data-ai-suggestion="${escapeHtml(prompt)}"><span class="server-ai-starter-icon">${aiIcon(icon)}</span><span class="server-ai-starter-copy"><strong>${escapeHtml(label)}</strong><small>${escapeHtml(detail)}</small></span><span class="server-ai-starter-arrow">${aiIcon("diagonal")}</span></button>`).join("")}</div></section>`;
}

export function renderServerAi({ manualRestore = "" } = {}) {
  return `<section class="server-ai" data-server-ai aria-labelledby="server-ai-title">
    <header class="server-ai-toolbar">
      <div class="server-ai-brand"><h1 id="server-ai-title">Server AI</h1></div>
      <div class="server-ai-machine" aria-label="Macchina Server AI">
        <div data-ai-machine-name><strong data-ai-machine-label>Caricamento…</strong></div>
        <label class="server-ai-machine-picker" data-ai-machine-picker hidden><span class="sr-only">Macchina</span><select data-ai-machine-select aria-label="Macchina"></select></label>
        <div class="server-ai-health" data-ai-health aria-live="polite"><span></span><strong>Verifica…</strong></div>
      </div>
      <div class="server-ai-toolbar-actions"><details class="server-ai-tools" data-ai-tools><summary aria-label="Strumenti Server AI"><span>Strumenti</span>${aiIcon("more")}</summary><div class="server-ai-tools-menu">${manualRestore ? '<button type="button" data-ai-open-restore>Ripristino manuale</button>' : ""}<details class="server-ai-admin-diagnostics" data-ai-admin-diagnostics hidden><summary>Diagnostica</summary><dl data-ai-admin-diagnostics-list></dl></details><div class="server-ai-gate-actions"><button type="button" data-ai-disable hidden>${aiIcon('power')}<span>Disattiva Server AI</span></button></div></div></details></div>
    </header>
    <section class="server-ai-workspace" data-ai-workspace>
      <button class="server-ai-drawer-backdrop" type="button" data-ai-close-conversations aria-label="Chiudi conversazioni" tabindex="-1"></button>
      <aside class="server-ai-conversations" id="server-ai-conversations" data-ai-conversation-drawer aria-label="Conversazioni">
        <div class="server-ai-conversations-head"><button type="button" data-ai-new-conversation>${aiIcon('plus')} Nuova chat</button><button type="button" class="server-ai-drawer-close" data-ai-close-conversations aria-label="Chiudi conversazioni">${aiIcon('close')}</button></div>
        <label class="server-ai-conversation-search">${aiIcon('search')}<input type="search" data-ai-conversation-search placeholder="Cerca nelle chat" aria-label="Cerca nelle chat" autocomplete="off"></label>
        <h2 class="server-ai-history-title">Conversazioni</h2>
        <ol data-ai-conversation-list></ol>
        <button type="button" class="server-ai-load-older" data-ai-more-conversations hidden>Conversazioni precedenti</button>
        <div class="server-ai-sidebar-footer">Le tue conversazioni, su questo server.</div>
      </aside>
      <div class="server-ai-main">
        <div class="server-ai-chat-head"><button type="button" class="server-ai-drawer-open" data-ai-open-conversations aria-label="Apri conversazioni" aria-controls="server-ai-conversations" aria-expanded="false">${aiIcon('sidebar')}</button><strong data-ai-conversation-title>Nuova chat</strong></div>
        <section class="server-ai-gate" data-ai-gate aria-live="polite"><span class="server-ai-gate-mark" aria-hidden="true">${aiIcon('power')}</span><div><h2 data-ai-gate-title>Verifica Server AI…</h2><p data-ai-gate-message>Recupero dello stato della macchina.</p><p class="server-ai-action-error" data-ai-action-error role="alert" hidden></p></div><ul data-ai-missing hidden></ul><div class="server-ai-gate-actions"><button type="button" data-ai-enable hidden>Attiva Server AI</button></div></section>
        <div class="server-ai-chat-area" data-ai-chat-area hidden>
            <button type="button" class="server-ai-load-older" data-ai-load-older hidden>Messaggi precedenti</button>
          <div class="server-ai-chat" data-ai-transcript role="log" aria-label="Conversazione" aria-live="polite" aria-relevant="additions text" tabindex="0">
            ${renderServerAiEmpty()}
          </div>
          <details class="server-ai-sources" data-ai-sources hidden><summary><span>Fonti della risposta</span><span data-ai-source-count></span></summary><ol data-ai-source-list></ol></details>
          <div class="server-ai-compose-dock">
            <button type="button" class="server-ai-jump-bottom" data-ai-jump-bottom hidden disabled aria-label="Vai in fondo alla conversazione" title="Vai in fondo alla conversazione">${aiIcon('arrow')}</button>
            <p class="server-ai-state" data-ai-state role="status" hidden></p>
            <form class="server-ai-composer" data-ai-form>
              <label class="sr-only" for="server-ai-prompt">Messaggio per Server AI</label><textarea id="server-ai-prompt" data-ai-prompt rows="1" maxlength="12000" placeholder="Scrivi una richiesta per il server…" autocomplete="off"></textarea>
                <div class="server-ai-attachments" data-ai-attachments hidden aria-live="polite"></div>
                <div class="server-ai-composer-actions">
                <button type="button" data-ai-attach aria-label="Allega file o immagine" title="Allega file o immagine">${aiIcon('attach')}</button><input data-ai-attachment-input type="file" hidden multiple>
                <button type="button" data-ai-stop hidden aria-label="Interrompi risposta" title="Interrompi risposta"><span class="server-ai-stop-icon" aria-hidden="true"></span></button><button type="submit" data-ai-send aria-label="Invia messaggio" title="Invia messaggio">${aiIcon('arrow')}</button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </section>
    <template data-ai-empty-template>${renderServerAiEmpty()}</template>
    ${manualRestore ? `<dialog class="server-ai-restore-dialog" data-ai-restore-dialog aria-label="Ripristino manuale"><div class="server-ai-dialog-head"><h2>Ripristino manuale</h2><button type="button" data-ai-close-restore aria-label="Chiudi ripristino">${aiIcon("close")}</button></div>${manualRestore}</dialog>` : ""}
  </section>`;
}
