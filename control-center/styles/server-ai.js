(function () {
  "use strict";

  var active = null;
  var observer = null;

  function csrfToken() {
    var prefix = "__Host-platform_cc_csrf=";
    return String(document.cookie || "").split(";").reduce(function (found, part) {
      var value = part.trim();
      return found || (value.indexOf(prefix) === 0 ? decodeURIComponent(value.slice(prefix.length)) : "");
    }, "");
  }

  function safeUrl(value) {
    try {
      var url = new URL(String(value || ""));
      return (url.protocol === "https:" || url.protocol === "http:") && !url.username && !url.password ? url : null;
    } catch {
      return null;
    }
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function inlineMarkdown(value, allowedHrefs) {
    var escaped = escapeHtml(value);
    escaped = escaped.replace(/!\[([^\]]*)\]\([^)\s]+\)/g, "$1");
    escaped = escaped.replace(/`([^`]+)`/g, "<code>$1</code>");
    escaped = escaped.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    escaped = escaped.replace(/(^|[^*])\*([^*]+)\*/g, "$1<em>$2</em>");
    return escaped.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, function (match, label, href) {
      var safe = safeUrl(href);
      return safe && allowedHrefs && allowedHrefs.has(safe.href) ? '<a href="' + escapeHtml(safe.href) + '" target="_blank" rel="noopener noreferrer">' + label + "</a>" : label;
    });
  }

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

  function markdown(value, allowedHrefs) {
    var lines = String(value == null ? "" : value).replace(/\r\n?/g, "\n").split("\n");
    var output = [];
    var index = 0;
    while (index < lines.length) {
      var line = lines[index];
      var fence = line.match(/^```([^`]*)$/);
      if (fence) {
        var code = [];
        index += 1;
        while (index < lines.length && !/^```\s*$/.test(lines[index])) code.push(lines[index++]);
        if (index < lines.length) index += 1;
        output.push('<pre class="server-ai-code"><span class="server-ai-code-head"><span>' + escapeHtml(fence[1].trim().slice(0, 32) || "code") + '</span><button type="button" data-ai-copy-code aria-label="Copia codice">Copia</button></span><code>' + escapeHtml(code.join("\n")) + "</code></pre>");
        continue;
      }
      var table = markdownTable(lines, index, allowedHrefs);
      if (table) { output.push(table.html); index = table.next; continue; }
      var heading = line.match(/^(#{1,3})\s+(.+)$/);
      if (heading) {
        var level = heading[1].length + 2;
        output.push("<h" + level + ">" + inlineMarkdown(heading[2], allowedHrefs) + "</h" + level + ">");
        index += 1;
        continue;
      }
      var list = /^\s*[-*]\s+/.test(line);
      var numbered = /^\s*\d+\.\s+/.test(line);
      if (list || numbered) {
        var entries = [];
        var expression = list ? /^\s*[-*]\s+/ : /^\s*\d+\.\s+/;
        while (index < lines.length && expression.test(lines[index])) entries.push("<li>" + inlineMarkdown(lines[index++].replace(expression, ""), allowedHrefs) + "</li>");
        output.push((list ? "<ul>" : "<ol>") + entries.join("") + (list ? "</ul>" : "</ol>"));
        continue;
      }
      if (!line.trim()) { index += 1; continue; }
      var paragraph = [line];
      index += 1;
      while (index < lines.length && lines[index].trim() && !/^```/.test(lines[index]) && !/^(#{1,3})\s+/.test(lines[index]) && !/^\s*(?:[-*]|\d+\.)\s+/.test(lines[index]) && !tableHeader(lines, index)) paragraph.push(lines[index++]);
      output.push("<p>" + inlineMarkdown(paragraph.join("\n"), allowedHrefs).replace(/\n/g, "<br>") + "</p>");
    }
    return output.join("") || "<p></p>";
  }

  function setState(instance, value, error) {
    instance.chatError = Boolean(error && value);
    instance.state.textContent = value || "";
    instance.state.classList.toggle("error", Boolean(error));
    instance.state.hidden = !error || !value;
  }

  function updateMachineStatusMessage(instance, status) {
    if (instance.actionError) {
      setState(instance, instance.actionError, true);
      return;
    }
    var ready = instance.machineState === "active" || instance.machineState === "degraded";
    if (ready) {
      if (!instance.busy && !instance.chatError) setState(instance, status.online === false ? "Connessione OpenAI da verificare; la cronologia resta disponibile." : "Disponibile tramite OpenAI.");
    } else setState(instance, String(status.label || stateTitle(instance.machineState)).slice(0, 320), instance.machineState === "unavailable");
  }

  function showMachineActionError(instance, message) {
    instance.actionError = message;
    setState(instance, message, true);
  }

  function quickReplyOption(value) {
    var option = String(value || "")
      .replace(/[`*_~]/g, "")
      .replace(/^\s*(?:[-–—•]|\d+[.)])\s*/, "")
      .replace(/[?.!,:;]+\s*$/, "")
      .replace(/\s+/g, " ")
      .trim();
    if (!option || option.length > 52 || /(?:https?:\/\/|www\.|[\\/]{2,}|\b(?:password|passwd|token|secret|cookie|api[_ -]?key)\b)/i.test(option)) return "";
    if (/\S{28,}/.test(option)) return "";
    return option;
  }

  function deriveQuickReplies(content) {
    var text = String(content || "").replace(/\r\n?/g, "\n").trim().slice(-4_000);
    if (!text) return [];
    var questionMatch = text.match(/(?:^|[\n.!])\s*([^?\n]{1,220}\?)\s*$/);
    var question = questionMatch ? questionMatch[1].trim() : "";
    if (question) {
      var alternatives = question.match(/\b(?:preferisci|scegli|vuoi)\s+(?:tra\s+)?(.{1,70}?)\s+(?:oppure|o)\s+(.{1,70}?)[?]\s*$/i);
      if (alternatives) {
        var options = [quickReplyOption(alternatives[1]), quickReplyOption(alternatives[2])].filter(Boolean);
        if (options.length === 2 && options[0].toLocaleLowerCase("it") !== options[1].toLocaleLowerCase("it")) {
          return options.map(function (option) { return { label: option, message: "Scelgo " + option + "." }; }).slice(0, 3);
        }
      }
      if (/\b(?:vuoi che|vuoi procedere|vuoi continuare|desideri che|posso|procedo|confermi|autorizzi|continuo|vado avanti|devo procedere)\b/i.test(question)) {
        return [
          { label: "Sì, procedi", message: "Sì, procedi" },
          { label: "No, fermati", message: "No, fermati" },
        ];
      }
    }
    return [
      // These exact commands are recognized by the backend continuation
      // selector, which attaches the preceding user/assistant pair.
      { label: "Approfondisci", message: "Approfondisci" },
      { label: "Riassumi", message: "Riassumi" },
    ];
  }

  function latestRenderedMessage(instance) {
    var messages = instance.transcript.querySelectorAll(".server-ai-message");
    return messages.length ? messages[messages.length - 1] : null;
  }

  function clearQuickReplies(instance) {
    instance.transcript.querySelectorAll("[data-ai-quick-replies]").forEach(function (element) { element.remove(); });
  }

  function quickRepliesAvailable(instance) {
    return Boolean(instance.generationAvailable && instance.conversationId && !instance.prompt.value.trim() && !instance.busy && !instance.scanBusy && !instance.actionBusy && (instance.machineState === "active" || instance.machineState === "degraded"));
  }

  function refreshQuickReplyAvailability(instance) {
    var available = quickRepliesAvailable(instance);
    instance.transcript.querySelectorAll("[data-ai-quick-replies]").forEach(function (group) {
      group.hidden = !available;
      group.querySelectorAll("button").forEach(function (button) { button.disabled = !available; });
    });
  }

  function renderLatestQuickReplies(instance, messages) {
    clearQuickReplies(instance);
    if (!Array.isArray(messages) || !messages.length) return;
    var stored = messages[messages.length - 1];
    if (!stored || stored.role !== "assistant" || stored.generationStatus !== "completed" || !String(stored.content || "").trim() || !stored.id) return;
    var node = renderedMessageNode(instance, stored.id);
    if (!node || node.item !== latestRenderedMessage(instance)) return;
    var replies = deriveQuickReplies(stored.content).slice(0, 3);
    if (!replies.length) return;
    var group = document.createElement("div");
    group.className = "server-ai-quick-replies";
    group.setAttribute("data-ai-quick-replies", "");
    group.setAttribute("role", "group");
    group.setAttribute("aria-label", "Risposte rapide");
    group._serverAiQuickReplyContext = { machineId: instance.selectedMachineId, conversationId: instance.conversationId, epoch: instance.contextEpoch, assistantId: String(stored.id) };
    replies.forEach(function (reply) {
      var button = document.createElement("button");
      button.type = "button";
      button.setAttribute("data-ai-quick-reply", "");
      button.textContent = reply.label;
      button._serverAiQuickReplyMessage = reply.message;
      group.appendChild(button);
    });
    node.item.appendChild(group);
    refreshQuickReplyAvailability(instance);
    if (!group.hidden) scrollTranscript(instance);
  }

  function activateQuickReply(instance, button) {
    var group = button && button.closest ? button.closest("[data-ai-quick-replies]") : null;
    var context = group && group._serverAiQuickReplyContext;
    var lastMessage = latestRenderedMessage(instance);
    var message = button && typeof button._serverAiQuickReplyMessage === "string" ? button._serverAiQuickReplyMessage.trim().slice(0, 120) : "";
    if (instance.prompt.value.trim()) { instance.prompt.focus(); return false; }
    if (!group || !context || !message || button.disabled || !quickRepliesAvailable(instance)) return false;
    if (!isCurrentConversationContext(instance, context) || context.conversationId !== instance.conversationId || group.closest(".server-ai-message") !== lastMessage || lastMessage.getAttribute("data-ai-message-id") !== context.assistantId) return false;
    instance.prompt.value = message;
    resizePrompt(instance);
    clearQuickReplies(instance);
    void send(instance);
    return true;
  }

  function setBusy(instance, busy) {
    instance.busy = busy;
    instance.root.setAttribute("aria-busy", busy ? "true" : "false");
    instance.stop.hidden = !busy;
    instance.send.hidden = false;
    refreshModeAvailability(instance);
    refreshQuickReplyAvailability(instance);
  }

  var MODE_OPTIONS = ["auto", "fast", "deep"];

  function modeStatus(mode) {
    if (mode === "deep") return "DEEP: analisi approfondita.";
    if (mode === "fast") return "FAST: risposta rapida.";
    return "AUTO: scelta adattiva.";
  }

  function selectMode(instance, value, announce, focus) {
    var mode = MODE_OPTIONS.includes(value) ? value : "auto";
    var selectedButton = null;
    instance.mode = mode;
    var group = instance.root.querySelector(".server-ai-mode");
    if (group) group.setAttribute("data-ai-selected-mode", mode);
    instance.root.querySelectorAll("[data-ai-mode]").forEach(function (button) {
      var selected = button.getAttribute("data-ai-mode") === mode;
      button.classList.toggle("active", selected);
      button.setAttribute("role", "radio");
      button.setAttribute("aria-checked", selected ? "true" : "false");
      button.removeAttribute("aria-pressed");
      button.tabIndex = selected ? 0 : -1;
      if (selected) selectedButton = button;
    });
    if (focus && selectedButton) selectedButton.focus();
    if (announce) setState(instance, modeStatus(mode));
  }

  function initializeModeControl(instance) {
    var group = instance.root.querySelector(".server-ai-mode");
    if (!group) return;
    group.setAttribute("role", "radiogroup");
    selectMode(instance, instance.mode, false, false);
  }


  function refreshModeAvailability(instance) {
    var chatEnabled = instance.generationAvailable && (instance.machineState === "active" || instance.machineState === "degraded");
    instance.root.querySelectorAll("[data-ai-mode]").forEach(function (button) {
      button.disabled = Boolean(!chatEnabled || instance.actionBusy);
    });
    // The composer remains editable while a turn is running so the user can
    // queue a follow-up without losing a draft. Attachments still wait for the
    // active upload/generation to finish and the stop action stays independent.
    instance.prompt.disabled = Boolean(!chatEnabled || instance.actionBusy);
    instance.send.disabled = Boolean(!chatEnabled || instance.actionBusy || instance.attachmentUploading);
    if (instance.send) {
      var queueLabel = instance.busy ? "Aggiungi alla coda" : "Invia messaggio";
      instance.send.setAttribute("aria-label", queueLabel);
      instance.send.title = queueLabel;
    }
    if (instance.sendImmediate) {
      instance.sendImmediate.hidden = !instance.busy;
      instance.sendImmediate.disabled = Boolean(!chatEnabled || instance.actionBusy || instance.attachmentUploading);
    }
    instance.stop.disabled = Boolean(instance.actionBusy);
    if (instance.attach) instance.attach.disabled = Boolean(!chatEnabled || instance.busy || instance.actionBusy || instance.attachmentUploading || !instance.attachmentCapabilities || (instance.pendingAttachments || []).length >= 5);
  }

  function machineState(status) {
    var state = String(status && status.state || "unavailable").toLowerCase();
    return ["active", "degraded", "disabled", "unavailable", "starting", "stopping"].includes(state) ? state : "unavailable";
  }

  function stateTitle(state) {
    if (state === "active") return "Server AI attivo";
    if (state === "degraded") return "Chat GPT-6 Luna attiva";
    if (state === "disabled") return "Server AI disattivato";
    if (state === "starting") return "Avvio di Server AI";
    if (state === "stopping") return "Arresto di Server AI";
    return "Server AI non disponibile";
  }

  function missingRequirements(status) {
    return Array.isArray(status && status.missing) ? status.missing.map(function (item) { return String(item || "").trim().slice(0, 240); }).filter(Boolean).slice(0, 12) : [];
  }

  function shortStateTitle(state) {
    if (state === "active" || state === "degraded") return "Attivo";
    if (state === "disabled") return "Disattivato";
    if (state === "starting") return "Avvio";
    if (state === "stopping") return "Arresto";
    return "Non disponibile";
  }

  function renderAdminDiagnostics(instance, status) {
    var diagnostics = status && status.adminDiagnostics;
    var allowed = diagnostics && diagnostics.allowed === true && Array.isArray(diagnostics.entries);
    if (!instance.adminDiagnostics || !instance.adminDiagnosticsList) return;
    instance.adminDiagnostics.hidden = !allowed;
    if (!allowed) return;
    instance.adminDiagnosticsList.replaceChildren();
    diagnostics.entries.slice(0, 12).forEach(function (entry) {
      if (!entry || typeof entry !== "object") return;
      var label = String(entry.label || "").trim().slice(0, 80);
      var value = String(entry.value || "").trim().slice(0, 160);
      if (!label || !value) return;
      var term = document.createElement("dt"); term.textContent = label;
      var description = document.createElement("dd"); description.textContent = value;
      instance.adminDiagnosticsList.append(term, description);
    });
    instance.adminDiagnostics.hidden = instance.adminDiagnosticsList.children.length === 0;
  }

  function renderMachine(instance, status) {
    instance.machineState = machineState(status);
    instance.enabled = status && status.enabled === true;
    instance.canConfigure = status && status.canConfigure === true;
    instance.generationAvailable = Boolean(status && (status.generationAvailable === true || status.ready === true));
    instance.historyAvailable = Boolean(status && status.historyAvailable === true);
    instance.root.setAttribute("data-ai-machine-state", instance.machineState);
    renderAdminDiagnostics(instance, status);
    instance.machineLabel.textContent = String(status && status.machineLabel || instance.selectedMachineLabel || "Macchina selezionata").slice(0, 160);
    var healthLabel = String(status && status.label || stateTitle(instance.machineState)).slice(0, 180);
    var healthStrong = instance.health.querySelector("strong");
    var ready = instance.machineState === "active" || instance.machineState === "degraded";
    instance.health.classList.toggle("good", instance.machineState === "active");
    instance.health.classList.toggle("degraded", instance.machineState === "degraded");
    instance.health.classList.toggle("bad", !ready);
    healthStrong.textContent = shortStateTitle(instance.machineState);
    healthStrong.title = healthLabel;
    instance.gateTitle.textContent = stateTitle(instance.machineState);
    var gateMessage = String(status && status.label || (instance.machineState === "disabled" ? "Attiva Server AI quando questa macchina è pronta." : "Verifica lo stato della macchina."));
    if (!instance.canConfigure) gateMessage += " L’attivazione è riservata ai ruoli owner o admin.";
    instance.gateMessage.textContent = gateMessage.slice(0, 320);
    var missing = missingRequirements(status);
    instance.missing.replaceChildren();
    missing.forEach(function (message) { var entry = document.createElement("li"); entry.textContent = message; instance.missing.appendChild(entry); });
    instance.missing.hidden = missing.length === 0;
    var transient = instance.machineState === "starting" || instance.machineState === "stopping";
    var canEnable = instance.machineState === "disabled" && missing.length === 0 && instance.canConfigure && !instance.actionBusy;
    var canDisable = instance.enabled && (instance.machineState === "active" || instance.machineState === "degraded" || instance.machineState === "unavailable") && instance.canConfigure && !instance.actionBusy;
    instance.enable.hidden = !canEnable;
    instance.enable.disabled = !canEnable;
    instance.disable.hidden = !canDisable;
    instance.disable.disabled = !canDisable;
    instance.chatArea.hidden = !instance.historyAvailable && instance.machineState !== "active" && instance.machineState !== "degraded";
    instance.gate.hidden = instance.machineState === "active";
    instance.root.classList.toggle("server-ai-transient", transient);
    refreshModeAvailability(instance);
    refreshQuickReplyAvailability(instance);
  }

  function resizePrompt(instance) {
    instance.prompt.style.height = "auto";
    instance.prompt.style.height = Math.min(instance.prompt.scrollHeight, 160) + "px";
  }

  function transcriptAtEnd(instance) {
    return instance.transcript.scrollHeight - instance.transcript.scrollTop - instance.transcript.clientHeight < 28;
  }

  function refreshJumpToBottom(instance) {
    if (!instance.jumpBottom) return;
    var overflow = instance.transcript.scrollHeight > instance.transcript.clientHeight + 28;
    var show = overflow && !instance.autoScroll && !transcriptAtEnd(instance);
    instance.jumpBottom.hidden = !show;
    instance.jumpBottom.disabled = !show;
  }

  function cancelTranscriptScrollFrames(instance) {
    if (instance.scrollFrame) window.cancelAnimationFrame(instance.scrollFrame);
    if (instance.scrollResetFrame) window.cancelAnimationFrame(instance.scrollResetFrame);
    instance.scrollFrame = null;
    instance.scrollResetFrame = null;
    instance.programmaticScroll = false;
  }

  function scrollTranscript(instance, force) {
    if (force) {
      instance.autoScroll = true;
      instance.userScrollUntil = 0;
      instance.pointerScrolling = false;
    }
    if (instance.pointerScrolling) { refreshJumpToBottom(instance); return; }
    if (!instance.autoScroll) { refreshJumpToBottom(instance); return; }
    cancelTranscriptScrollFrames(instance);
    instance.scrollFrame = window.requestAnimationFrame(function () {
      instance.scrollFrame = null;
      if (active !== instance || !instance.autoScroll || !instance.transcript.isConnected) { refreshJumpToBottom(instance); return; }
      instance.programmaticScroll = true;
      instance.transcript.scrollTop = instance.transcript.scrollHeight;
      refreshJumpToBottom(instance);
      if (instance.scrollResetFrame) window.cancelAnimationFrame(instance.scrollResetFrame);
      instance.scrollResetFrame = window.requestAnimationFrame(function () {
        instance.scrollResetFrame = null;
        if (active !== instance || !instance.transcript.isConnected) return;
        instance.programmaticScroll = false;
        refreshJumpToBottom(instance);
      });
    });
  }

  function noteTranscriptScrollIntent(instance) {
    instance.userScrollUntil = Date.now() + 600;
  }

  function pauseTranscriptFollow(instance) {
    instance.autoScroll = false;
    noteTranscriptScrollIntent(instance);
    cancelTranscriptScrollFrames(instance);
    refreshJumpToBottom(instance);
  }

  function handleTranscriptScroll(instance) {
    var atEnd = transcriptAtEnd(instance);
    var userScrolling = instance.pointerScrolling || Date.now() <= instance.userScrollUntil;
    if (atEnd) instance.autoScroll = true;
    else if (!atEnd && userScrolling) instance.autoScroll = false;
    refreshJumpToBottom(instance);
  }

  function addMessage(instance, role, text, streaming, allowedHrefs) {
    var empty = instance.transcript.querySelector("[data-ai-empty]");
    if (empty) empty.remove();
    var item = document.createElement("article");
    item.className = "server-ai-message " + role + (streaming ? " server-ai-streaming" : "");
    item.innerHTML = "<header>" + (role === "user" ? "Tu" : "Server AI") + "</header><div class=\"server-ai-message-content\"></div>";
    var content = item.querySelector(".server-ai-message-content");
    if (role === "user") content.textContent = text;
    else content.innerHTML = markdown(text, allowedHrefs || new Set());
    item._serverAiRawContent = String(text || "");
    instance.transcript.appendChild(item);
    scrollTranscript(instance);
    return { item: item, content: content };
  }

  function updateAssistant(instance, message, text, streaming) {
    message.node.content.innerHTML = markdown(text, message.sources || new Set());
    message.node.item._serverAiRawContent = String(text || "");
    message.node.item.classList.toggle("server-ai-streaming", Boolean(streaming));
    scrollTranscript(instance);
  }

  function sourceValues(sources) {
    var unique = new Map();
    (Array.isArray(sources) ? sources : []).forEach(function (source) {
      if (source && source.type === "project" && /^[A-Za-z0-9_-]{1,128}$/.test(String(source.id || "")) && /^[a-z0-9][a-z0-9-]{0,63}$/.test(String(source.projectId || ""))) {
        var projectKey = "project:" + source.projectId + ":" + source.id;
        unique.set(projectKey, { type: "project", id: String(source.id), projectId: String(source.projectId), kind: String(source.kind || ""), title: String(source.title || source.path || "Fonte progetto").slice(0, 240), path: String(source.path || "").slice(0, 512), startLine: Number(source.startLine) || 0, endLine: Number(source.endLine) || 0, sha256: String(source.sha256 || ""), databaseId: String(source.databaseId || ""), dialect: String(source.dialect || ""), operation: String(source.operation || "") });
        return;
      }
      var url = safeUrl(source && source.url);
      if (!url) return;
      var key = String(source.id || url.href);
      unique.set(key, { type: "web", url: url, title: String(source.title || url.hostname).slice(0, 240), domain: String(source.domain || url.hostname).slice(0, 160), fetchedAt: source.fetchedAt });
    });
    return Array.from(unique.values());
  }

  function sourceUrls(sources) {
    return new Set(sourceValues(sources).filter(function (source) { return source.type === "web"; }).map(function (source) { return source.url.href; }));
  }

  function sourceDate(value) {
    var date = new Date(value);
    return Number.isNaN(date.getTime()) ? "" : date.toLocaleString("it-IT", { dateStyle: "short", timeStyle: "short" });
  }

  function appendSourceList(target, values) {
    values.forEach(function (source) {
      var item = document.createElement("li");
      if (source.type === "project") {
        if (source.kind !== "file" && !(source.kind === "database" && source.operation === "schema")) {
          var label = document.createElement("span"); label.textContent = source.title + " · istantanea non riapribile"; item.appendChild(label);
        } else {
          var button = document.createElement("button");
          button.type = "button"; button.setAttribute("data-ai-project-source", source.id); button.setAttribute("data-ai-project-id", source.projectId); button.textContent = source.title;
          item.appendChild(button);
        }
        var projectMeta = document.createElement("small"); projectMeta.textContent = [source.path, source.startLine ? "righe " + source.startLine + (source.endLine ? "–" + source.endLine : "") : ""].filter(Boolean).join(" · "); if (projectMeta.textContent) item.appendChild(projectMeta);
      } else {
        var anchor = document.createElement("a"); anchor.href = source.url.href; anchor.target = "_blank"; anchor.rel = "noopener noreferrer"; anchor.textContent = source.title; item.appendChild(anchor);
        var meta = document.createElement("small"); meta.textContent = [source.domain, sourceDate(source.fetchedAt)].filter(Boolean).join(" · "); if (meta.textContent) item.appendChild(meta);
      }
      target.appendChild(item);
    });
  }

  function renderMessageSources(node, sources) {
    var values = sourceValues(sources);
    var signature = JSON.stringify(values.map(function (source) { return [source.id, source.type, source.projectId || "", source.sha256 || "", source.url && source.url.href || ""]; }));
    var previous = node.item.querySelector(".server-ai-message-sources");
    // Polling a durable turn must not close an already-open source viewer.
    if (previous && previous.getAttribute("data-ai-source-signature") === signature) return;
    if (previous) previous.remove();
    if (!values.length) return;
    var details = document.createElement("details"); details.className = "server-ai-sources server-ai-message-sources";
    details.setAttribute("data-ai-source-signature", signature);
    var summary = document.createElement("summary"); summary.textContent = values.length + (values.length === 1 ? " fonte" : " fonti");
    var list = document.createElement("ol"); appendSourceList(list, values);
    details.appendChild(summary); details.appendChild(list); node.item.appendChild(details);
  }

  function attachmentUrl(instance, attachmentId) {
    return conversationsEndpoint(instance, "/" + encodeURIComponent(instance.conversationId) + "/attachments/" + encodeURIComponent(attachmentId));
  }

  function renderMessageAttachments(instance, node, attachments) {
    var values = Array.isArray(attachments) ? attachments.filter(function (item) { return item && /^[0-9a-f-]{36}$/i.test(String(item.id || "")); }) : [];
    var signature = JSON.stringify(values.map(function (item) { return [item.id, item.name, item.kind, item.mediaType, item.size, item.document]; }));
    var previous = node.item.querySelector(".server-ai-message-attachments");
    if (previous && previous.getAttribute("data-ai-attachment-signature") === signature) return;
    if (previous) previous.remove();
    if (!values.length) return;
    var list = document.createElement("div"); list.className = "server-ai-message-attachments"; list.setAttribute("data-ai-attachment-signature", signature);
    values.forEach(function (item) {
      var href = attachmentUrl(instance, item.id);
      if (item.kind === "image") {
        var image = document.createElement("img"); image.src = href; image.alt = String(item.name || "Immagine allegata").slice(0, 255); image.loading = "lazy"; list.appendChild(image);
      }
      var link = document.createElement("a"); link.href = href; link.textContent = String(item.name || "Allegato").slice(0, 255); link.setAttribute("data-ai-attachment", item.id); list.appendChild(link);
      if (item.kind === "document" && item.document?.coverage) {
        var note = document.createElement("small"); note.className = "server-ai-document-note";
        note.textContent = item.document.extractedBytes > 0 ? (item.document.coverage.state === "partial" ? "Testo estratto in parte · " : "Testo estratto · ") + formatFileSize(item.document.extractedBytes) : "Nessun testo estraibile · serve OCR o una versione testuale";
        list.appendChild(note);
        var warnings = (item.document.coverage.warnings || []).filter(function (warning) { return typeof warning === "string"; }).slice(0, 16);
        if (warnings.length) {
          var details = document.createElement("details"); details.className = "server-ai-document-details";
          var summary = document.createElement("summary"); summary.textContent = "Limiti di lettura"; details.appendChild(summary);
          var description = document.createElement("p"); description.textContent = warnings.join(" "); details.appendChild(description); list.appendChild(details);
        }
      }
      if (item.kind === "text" || item.kind === "archive" || (item.kind === "document" && item.document?.extractedBytes > 0)) {
        var analyze = document.createElement("button"); analyze.type = "button"; analyze.className = "server-ai-analyze-attachment";
        analyze.setAttribute("data-ai-scan-attachment", item.id); analyze.setAttribute("aria-label", "Analizza tutto " + String(item.name || "l’allegato").slice(0, 180)); analyze.textContent = "Analizza tutto"; list.appendChild(analyze);
      }
    });
    node.item.appendChild(list);
  }

  function formatFileSize(value) {
    var bytes = Number(value);
    if (!Number.isSafeInteger(bytes) || bytes < 0) return "";
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toLocaleString("it-IT", { maximumFractionDigits: 1 }) + " KiB";
    return (bytes / (1024 * 1024)).toLocaleString("it-IT", { maximumFractionDigits: 1 }) + " MiB";
  }

  function renderMessageArtifacts(instance, node, artifacts) {
    var values = Array.isArray(artifacts) ? artifacts.filter(function (item) {
      return item && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(item.id || ""))
        && typeof item.name === "string" && item.name.length <= 180 && !/[\x00-\x1f\x7f/\\]/.test(item.name)
        && Number.isSafeInteger(item.size) && item.size >= 0;
    }).slice(0, 20) : [];
    var signature = JSON.stringify(values.map(function (item) { return [item.id, item.name, item.size]; }));
    var previous = node.item.querySelector(".server-ai-message-artifacts");
    if (previous && previous.getAttribute("data-ai-artifact-signature") === signature) return;
    if (previous) previous.remove();
    if (!values.length || !instance.conversationId || !instance.selectedMachineId) return;
    var list = document.createElement("div");
    list.className = "server-ai-message-artifacts";
    list.setAttribute("data-ai-artifact-signature", signature);
    values.forEach(function (item) {
      var link = document.createElement("a");
      // The download route comes only from the current authorized chat and a
      // validated server artifact ID. Model-provided URLs are never used here.
      link.href = conversationsEndpoint(instance, "/" + encodeURIComponent(instance.conversationId) + "/artifacts/" + encodeURIComponent(item.id));
      link.className = "server-ai-artifact";
      link.setAttribute("download", item.name);
      link.setAttribute("data-ai-artifact", item.id);
      link.setAttribute("aria-label", "Scarica " + item.name);
      var icon = document.createElement("span"); icon.className = "server-ai-artifact-icon"; icon.setAttribute("aria-hidden", "true"); icon.textContent = /\.zip$/i.test(item.name) ? "ZIP" : "FILE";
      var text = document.createElement("span"); text.className = "server-ai-artifact-info";
      var name = document.createElement("strong"); name.textContent = item.name;
      var size = document.createElement("small"); size.textContent = formatFileSize(item.size) + " · Scarica";
      var arrow = document.createElement("span"); arrow.className = "server-ai-artifact-download"; arrow.setAttribute("aria-hidden", "true"); arrow.textContent = "↓";
      text.appendChild(name); text.appendChild(size); link.appendChild(icon); link.appendChild(text); link.appendChild(arrow); list.appendChild(link);
    });
    node.item.appendChild(list);
  }

  function renderConversationScans(instance, scans, continuationPending) {
    var values = Array.isArray(scans) ? scans.filter(function (item) {
      return item && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(item.id || ""))
        && ["queued", "running", "paused", "completed", "aborted", "failed"].includes(item.status)
        && Number.isSafeInteger(item.processedBytes) && Number.isSafeInteger(item.totalBytes)
        && item.processedBytes >= 0 && item.totalBytes >= item.processedBytes;
    }).slice(0, 20) : [];
    instance.scanBusy = continuationPending === true || values.some(function (item) { return item.status === "queued" || item.status === "running"; });
    var previous = instance.transcript.querySelector(".server-ai-scans");
    var signature = JSON.stringify(values);
    if (previous && previous._serverAiScanSignature === signature) return;
    var openIds = previous ? Array.from(previous.querySelectorAll("details[open]")).map(function (item) { return item.getAttribute("data-ai-scan-id"); }) : [];
    if (previous) previous.remove();
    if (!values.length) return;
    var group = document.createElement("section"); group.className = "server-ai-scans"; group._serverAiScanSignature = signature; group.setAttribute("aria-label", "Analisi complete degli allegati");
    var labels = { queued: "In coda", running: "Analisi in corso", paused: "In pausa", completed: "Analisi completata", aborted: "Analisi interrotta", failed: "Analisi non completata" };
    values.forEach(function (item) {
      var card = document.createElement("details"); card.className = "server-ai-scan"; card.setAttribute("data-ai-scan-id", item.id); card.open = openIds.includes(item.id);
      var title = document.createElement("summary");
      var filename = document.createElement("strong"); filename.textContent = String(item.filename || "Allegato").slice(0, 180);
      var archive = item.kind === "archive" && Number.isSafeInteger(item.entryCount) && item.entryCount > 0;
      var visited = archive && Number.isSafeInteger(item.processedEntries) ? Math.min(item.entryCount, Math.max(0, item.processedEntries)) : 0;
      var excluded = archive && Number.isSafeInteger(item.unsupportedEntries) ? Math.max(0, item.unsupportedEntries) : 0;
      var analyzed = archive && Number.isSafeInteger(item.analyzedEntries) ? Math.max(0, item.analyzedEntries) : 0;
      var percent = archive ? Math.floor(visited * 100 / item.entryCount) : item.totalBytes ? Math.floor(item.processedBytes * 100 / item.totalBytes) : item.status === "completed" ? 100 : 0;
      var documentCoverage = item.coverage?.document?.coverage;
      var documentPartial = documentCoverage && documentCoverage.state !== "complete" || item.coverage?.partialDocumentEntries > 0;
      var stateLabel = item.status === "completed" && documentPartial ? "Testo analizzato con contenuti esclusi" : item.status === "completed" && excluded ? "Analisi conclusa con file esclusi" : labels[item.status];
      var state = document.createElement("span"); state.textContent = stateLabel + " · " + percent + "%"; title.appendChild(filename); title.appendChild(state); card.appendChild(title);
      var progress = document.createElement("progress"); progress.max = Math.max(1, archive ? item.entryCount : item.totalBytes); progress.value = archive ? visited : item.processedBytes; progress.setAttribute("aria-label", (archive ? "Voci esaminate di " : "Copertura verificata di ") + filename.textContent); card.appendChild(progress);
      var count = document.createElement("small");
      count.textContent = archive ? visited + " di " + item.entryCount + " voci esaminate · " + analyzed + " file analizzati" + (excluded ? " · " + excluded + " esclusi (formato o percorso non supportato)" : "") : percent + "% · " + formatFileSize(item.processedBytes) + " di " + formatFileSize(item.totalBytes) + " analizzati" + (item.kind === "document" ? " nel testo estratto" : ""); card.appendChild(count);
      var warnings = [].concat(documentCoverage?.warnings || [], item.coverage?.documentWarnings || []);
      warnings.slice(0, 12).forEach(function (value) { if (typeof value !== "string") return; var note = document.createElement("p"); note.className = "server-ai-scan-note"; note.textContent = value.slice(0, 500); card.appendChild(note); });
      if (typeof item.summary === "string" && item.summary.trim()) { var summary = document.createElement("p"); summary.textContent = item.summary.slice(0, 8192); card.appendChild(summary); }
      var automaticallyPreempted = item.status === "paused" && item.error?.code === "ATTACHMENT_SCAN_PREEMPTED";
      if (automaticallyPreempted) { var pauseNote = document.createElement("p"); pauseNote.className = "server-ai-scan-note"; pauseNote.textContent = "Riprende automaticamente al termine della risposta."; card.appendChild(pauseNote); }
      else if (item.error && typeof item.error.message === "string") { var error = document.createElement("p"); error.className = "server-ai-scan-error"; error.textContent = item.error.message.slice(0, 500); card.appendChild(error); }
      var action = item.status === "running" || item.status === "queued" ? "stop" : ["paused", "aborted", "failed"].includes(item.status) && !automaticallyPreempted ? "resume" : "";
      if (action) { var button = document.createElement("button"); button.type = "button"; button.setAttribute("data-ai-scan-action", action); button.setAttribute("data-ai-scan-id", item.id); button.textContent = action === "stop" ? "Interrompi" : "Riprendi analisi"; card.appendChild(button); }
      group.appendChild(card);
    });
    instance.transcript.appendChild(group);
    scrollTranscript(instance);
  }

  function queueValues(queue) {
    var values = Array.isArray(queue) ? queue : queue && Array.isArray(queue.items) ? queue.items : [];
    return values.filter(function (item) {
      return item && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(item.id || item.requestId || ""))
        && ["queued", "running", "cancelling", "failed"].includes(String(item.status || "queued"));
    }).slice(0, 12).map(function (item) {
      return { id: String(item.id || item.requestId), requestId: String(item.requestId || item.id), text: String(item.text || item.message || item.prompt || item.content || "").trim().slice(0, 160), status: String(item.status || "queued"), delivery: item.delivery === "immediate" ? "immediate" : "queue" };
    });
  }

  function queueStatusLabel(status) {
    return ({ queued: "In coda", running: "In elaborazione", cancelling: "Annullamento", failed: "Non riuscita", completed: "Completata", aborted: "Interrotta" })[status] || "In coda";
  }

  function queueActivityLabel(items) {
    var active = Array.isArray(items) ? items : [];
    var queued = active.filter(function (item) { return item.status === "queued"; }).length;
    var running = active.some(function (item) { return item.status === "running"; });
    var cancelling = active.some(function (item) { return item.status === "cancelling"; });
    var current = running ? "Elaborazione in corso" : cancelling ? "Annullamento in corso" : "";
    if (current) return current + (queued ? " · " + queued + " in coda" : "");
    return queued === 1 ? "Richiesta in coda" : queued ? queued + " richieste in coda" : "";
  }

  function queueDismissalKey(instance) {
    return "server-ai.queue-dismissed.v1:" + encodeURIComponent(String(instance.selectedMachineId || "")) + ":" + encodeURIComponent(String(instance.conversationId || ""));
  }

  function dismissedQueueIds(instance) {
    var key = queueDismissalKey(instance);
    if (instance.dismissedQueueErrorKey !== key) {
      var ids = [];
      try {
        var stored = JSON.parse(window.localStorage.getItem(key) || "[]");
        if (Array.isArray(stored)) ids = stored.filter(function (id) {
          return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(id));
        }).slice(-100);
      } catch (_) {}
      instance.dismissedQueueErrorKey = key;
      instance.dismissedQueueErrorIds = new Set(ids);
    }
    return instance.dismissedQueueErrorIds || new Set();
  }

  function saveDismissedQueueIds(instance) {
    try {
      var ids = Array.from(dismissedQueueIds(instance)).slice(-100);
      window.localStorage.setItem(queueDismissalKey(instance), JSON.stringify(ids));
    } catch (_) {}
  }

  function renderConversationQueue(instance, queue) {
    var target = instance.queue;
    if (!target) return;
    var values = queueValues(queue);
    var active = values.filter(function (item) { return item.status === "queued" || item.status === "running" || item.status === "cancelling"; });
    var dismissed = dismissedQueueIds(instance);
    var errors = values.filter(function (item) { return item.status === "failed" && !dismissed.has(item.requestId); });
    instance.queueItems = active;
    instance.queueErrors = errors;
    instance.queueBusy = active.length > 0;
    target.replaceChildren();
    target.hidden = !active.length && !errors.length;
    target.setAttribute("aria-label", "Stato richieste");
    if (active.length) {
      var title = document.createElement("div"); title.className = "server-ai-queue-title";
      var label = document.createElement("span"); label.textContent = queueActivityLabel(active);
      title.appendChild(label); target.appendChild(title);
      var list = document.createElement("ul"); list.className = "server-ai-queue-list";
      active.forEach(function (item) {
        var row = document.createElement("li"); row.className = "server-ai-queue-item"; row.setAttribute("data-ai-queue-item", item.requestId);
        var text = document.createElement("span"); text.textContent = [item.text || "Richiesta", queueStatusLabel(item.status), item.delivery === "immediate" ? "priorità" : ""].filter(Boolean).join(" · "); row.appendChild(text);
        if (item.status === "queued") {
          var cancel = document.createElement("button"); cancel.type = "button"; cancel.textContent = "Annulla"; cancel.title = "Annulla richiesta in coda"; cancel.setAttribute("data-ai-queue-cancel", item.id); row.appendChild(cancel);
        }
        list.appendChild(row);
      });
      target.appendChild(list);
    }
    if (errors.length) {
      var errorTitle = document.createElement("div"); errorTitle.className = "server-ai-queue-title server-ai-queue-title-error";
      var errorLabel = document.createElement("span"); errorLabel.textContent = errors.length === 1 ? "Richiesta non riuscita" : errors.length + " richieste non riuscite";
      errorTitle.appendChild(errorLabel); target.appendChild(errorTitle);
      var errorList = document.createElement("ul"); errorList.className = "server-ai-queue-list server-ai-queue-errors";
      errors.forEach(function (item) {
        var row = document.createElement("li"); row.className = "server-ai-queue-item server-ai-queue-item-error"; row.setAttribute("data-ai-queue-item", item.requestId);
        var text = document.createElement("span"); text.textContent = [item.text || "Richiesta", "Non riuscita"].join(" · "); row.appendChild(text);
        var dismiss = document.createElement("button"); dismiss.type = "button"; dismiss.textContent = "Nascondi"; dismiss.title = "Nascondi questo avviso senza cancellare la richiesta salvata"; dismiss.setAttribute("data-ai-queue-dismiss", item.requestId); row.appendChild(dismiss);
        errorList.appendChild(row);
      });
      target.appendChild(errorList);
    }
  }

  function dismissQueueError(instance, requestId) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(requestId || ""))) return;
    dismissedQueueIds(instance).add(String(requestId));
    saveDismissedQueueIds(instance);
    renderConversationQueue(instance, (instance.queueItems || []).concat(instance.queueErrors || []));
  }

  async function cancelQueuedRequest(instance, queueId) {
    var context = conversationContext(instance); var conversationId = instance.conversationId;
    if (!conversationId || !context.machineId || !/^[0-9a-f-]{36}$/i.test(String(queueId || ""))) return;
    var button = null;
    if (instance.queue) Array.from(instance.queue.querySelectorAll("[data-ai-queue-cancel]")).some(function (candidate) {
      if (candidate.getAttribute("data-ai-queue-cancel") !== String(queueId)) return false;
      button = candidate; return true;
    });
    if (button) button.disabled = true;
    try {
      var response = await fetch(conversationsEndpointFor(context.machineId, "/" + encodeURIComponent(conversationId) + "/queue/" + encodeURIComponent(queueId)), { method: "DELETE", credentials: "same-origin", headers: conversationHeaders() });
      if (!response.ok) throw new Error(await chatResponseError(response));
      if (isCurrentConversationContext(instance, context) && instance.conversationId === conversationId) scheduleConversationPoll(instance, context, true);
    } catch (error) {
      if (isCurrentConversationContext(instance, context) && instance.conversationId === conversationId) setState(instance, error && error.message ? error.message : "Annullamento non riuscito.", true);
      if (button) button.disabled = false;
    }
  }

  async function requestAttachmentScan(instance, button, action) {
    var context = conversationContext(instance); var conversationId = instance.conversationId;
    if (!conversationId || !context.machineId || button.disabled) return;
    var id = button.getAttribute(action === "start" ? "data-ai-scan-attachment" : "data-ai-scan-id");
    if (!/^[0-9a-f-]{36}$/i.test(String(id || "")) || !["start", "stop", "resume"].includes(action)) return;
    button.disabled = true;
    try {
      var suffix = "/" + encodeURIComponent(conversationId) + "/scans" + (action === "start" ? "" : "/" + encodeURIComponent(id) + "/" + action);
      var response = await fetch(conversationsEndpointFor(context.machineId, suffix), { method: "POST", credentials: "same-origin", headers: conversationHeaders(), body: JSON.stringify(action === "start" ? { attachmentId: id } : {}) });
      if (!response.ok) throw new Error(await chatResponseError(response));
      if (!isCurrentConversationContext(instance, context) || instance.conversationId !== conversationId) return;
      // Force one read even when a stop has just made the last job terminal.
      instance.scanBusy = true; scheduleConversationPoll(instance, context, true);
    } catch (error) { if (isCurrentConversationContext(instance, context) && instance.conversationId === conversationId) setState(instance, error.message || "Analisi non disponibile.", true); }
    finally { button.disabled = false; }
  }

  function renderPendingAttachments(instance) {
    var target = instance.attachments; if (!target) return;
    target.replaceChildren();
    var items = Array.isArray(instance.pendingAttachments) ? instance.pendingAttachments : [];
    var upload = instance.attachmentUpload;
    target.hidden = !items.length && !upload;
    if (upload) {
      var progress = document.createElement("span"); progress.className = "server-ai-attachment-chip server-ai-attachment-progress";
      var progressLabel = document.createElement("span"); progressLabel.textContent = String(upload.filename || "Allegato").slice(0, 180) + " · " + Math.min(100, Math.max(0, Number(upload.percent) || 0)) + "%"; progress.appendChild(progressLabel);
      var cancel = document.createElement("button"); cancel.type = "button"; cancel.setAttribute("data-ai-cancel-upload", ""); cancel.setAttribute("aria-label", "Annulla caricamento " + String(upload.filename || "allegato").slice(0, 180)); cancel.title = "Annulla caricamento"; cancel.textContent = "×"; progress.appendChild(cancel); target.appendChild(progress);
    }
    items.forEach(function (item) {
      var chip = document.createElement("span"); chip.className = "server-ai-attachment-chip";
      var name = String(item.name || "Allegato").slice(0, 255);
      if (item.kind === "image" && instance.conversationId) { var preview = document.createElement("img"); preview.src = attachmentUrl(instance, item.id); preview.alt = ""; preview.className = "server-ai-attachment-preview"; chip.appendChild(preview); }
      var label = document.createElement("span"); label.textContent = name + (item.kind === "document" && item.document?.extractedBytes === 0 ? " · nessun testo estraibile" : item.document?.coverage?.state === "partial" ? " · testo estratto in parte" : ""); chip.appendChild(label);
      var remove = document.createElement("button"); remove.type = "button"; remove.setAttribute("data-ai-remove-attachment", item.id); remove.setAttribute("aria-label", "Rimuovi " + chip.textContent); remove.textContent = "×"; chip.appendChild(remove); target.appendChild(chip);
    });
    refreshModeAvailability(instance);
  }

  async function loadPendingAttachments(instance, expectedContext, expectedConversationId) {
    var context = expectedContext || conversationContext(instance);
    var conversationId = expectedConversationId || instance.conversationId;
    if (!conversationId || !context.machineId) { instance.pendingAttachments = []; renderPendingAttachments(instance); return false; }
    var response = await fetchUploadWith429Retry(fetch, conversationsEndpointFor(context.machineId, "/" + encodeURIComponent(conversationId) + "/attachments"), { credentials: "same-origin", headers: { Accept: "application/json" } });
    var payload = await response.json().catch(function () { return {}; });
    if (!isCurrentConversationContext(instance, context) || instance.conversationId !== conversationId) return false;
    if (!response.ok || !Array.isArray(payload.attachments)) throw new Error(String(payload.message || "Allegati non disponibili."));
    instance.pendingAttachments = payload.attachments;
    if (payload.supported && typeof payload.supported === "object") instance.attachmentCapabilities = payload.supported;
    renderPendingAttachments(instance);
    return true;
  }

  async function loadAttachmentFormats(instance) {
    if (!instance.selectedMachineId) return;
    instance.attachmentCapabilities = null; refreshModeAvailability(instance);
    try {
      var response = await fetch(endpoint(instance, "/attachment-formats"), { credentials: "same-origin", headers: { Accept: "application/json" } });
      var payload = await response.json().catch(function () { return {}; });
      if (!response.ok || !payload.supported || typeof payload.supported !== "object") throw new Error("Allegati non disponibili.");
      instance.attachmentCapabilities = payload.supported;
      if (instance.attach) {
        var attachmentDescription = "Allega PDF, Word, Excel, PowerPoint, OpenDocument, EPUB, codice, testo, foto o ZIP, fino a 512 MiB per file. Massimo cinque allegati per messaggio.";
        instance.attach.title = attachmentDescription;
        instance.attach.setAttribute("aria-description", attachmentDescription);
      }
      if (instance.attachmentInput) {
        var accepted = typeof payload.supported.accept === "string" ? payload.supported.accept : [].concat(payload.supported.textExtensions || [], payload.supported.imageExtensions || [], payload.supported.archiveExtensions || [], payload.supported.documentExtensions || []).filter(function (extension) { return typeof extension === "string" && /^\.[a-z0-9]+$/i.test(extension); }).join(",");
        instance.attachmentInput.accept = accepted;
      }
    } catch { instance.attachmentCapabilities = null; }
    refreshModeAvailability(instance);
  }

  async function fetchUploadWith429Retry(fetchImpl, input, init, options) {
    var config = options && typeof options === "object" ? options : {};
    var signal = config.signal;
    var waitImpl = typeof config.wait === "function" ? config.wait : function (delayMs, waitSignal) {
      return new Promise(function (resolve, reject) {
        if (waitSignal?.aborted) { reject(new DOMException("Caricamento annullato.", "AbortError")); return; }
        var timer = setTimeout(done, delayMs);
        function done() { waitSignal?.removeEventListener("abort", aborted); resolve(); }
        function aborted() { clearTimeout(timer); waitSignal?.removeEventListener("abort", aborted); reject(new DOMException("Caricamento annullato.", "AbortError")); }
        waitSignal?.addEventListener("abort", aborted, { once: true });
      });
    };
    var fallbackDelays = [1_000, 2_000, 4_000, 8_000, 8_000];
    for (var attempt = 0; attempt < 6; attempt += 1) {
      if (signal?.aborted) throw new DOMException("Caricamento annullato.", "AbortError");
      var response = await fetchImpl(input, init);
      if (response.status !== 429 || attempt === 5) return response;
      var retryAfter = response.headers?.get?.("Retry-After");
      var delayMs = NaN;
      if (/^\d+(?:\.\d+)?$/.test(String(retryAfter || "").trim())) delayMs = Number(retryAfter) * 1_000;
      else if (retryAfter) delayMs = Date.parse(retryAfter) - Date.now();
      if (!Number.isFinite(delayMs) || delayMs < 0) delayMs = fallbackDelays[attempt];
      delayMs = Math.min(120_000, delayMs);
      try { await response.body?.cancel?.(); } catch {}
      await waitImpl(delayMs, signal);
    }
  }

  async function uploadAttachment(instance, file) {
    if (!file || instance.attachmentUploading || !instance.attachmentCapabilities || instance.busy) return;
    var existing = instance.pendingAttachments || [];
    if (existing.length >= 5) { setState(instance, "Puoi inviare al massimo cinque allegati per messaggio.", true); return; }
    var context = conversationContext(instance);
    if (!instance.conversationId) await createConversation(instance);
    if (!isCurrentConversationContext(instance, context) || !instance.conversationId) return;
    var targetConversationId = instance.conversationId;
    instance.attachmentUploading = true; refreshModeAvailability(instance);
    var controller = new AbortController(); instance.attachmentUploadController = controller;
    try {
      setState(instance, "");
      var maxFileBytes = Number(instance.attachmentCapabilities.maxFileBytes || 512 * 1024 * 1024);
      if (!Number.isFinite(file.size) || file.size < 1 || file.size > maxFileBytes) throw new Error("Il file supera il limite di 512 MiB.");
      // Every new browser upload follows the resumable protocol. A small
      // file simply completes in one bounded chunk, so progress, cancellation
      // and post-error pending refresh have one deterministic code path.
      await uploadResumableAttachment(instance, file, context, targetConversationId, controller);
    } catch (error) {
      if (!controller.signal.aborted && isCurrentConversationContext(instance, context) && instance.conversationId === targetConversationId) {
        // Completion can persist the attachment before a transient client or
        // acknowledgement error. Re-read the scoped pending list so a retry
        // never asks the user to submit an already-bound upload again.
        void loadPendingAttachments(instance, context, targetConversationId).catch(function () {});
        setState(instance, error && error.message ? error.message : "Allegato non accettato.", true);
      }
    }
    finally { if (instance.attachmentUploadController === controller) instance.attachmentUploadController = null; instance.attachmentUploading = false; if (instance.attachmentInput) instance.attachmentInput.value = ""; refreshModeAvailability(instance); }
  }

  async function abortResumableAttachment(context, conversationId, uploadId) {
    if (!context || !context.machineId || !conversationId || !uploadId) return;
    try {
      var response = await fetchUploadWith429Retry(fetch, conversationsEndpointFor(context.machineId, "/" + encodeURIComponent(conversationId) + "/attachment-uploads/" + encodeURIComponent(uploadId)), { method: "DELETE", credentials: "same-origin", headers: conversationHeaders(), body: "{}" });
      await response.body?.cancel?.();
    } catch {}
  }

  async function uploadResumableAttachment(instance, file, context, conversationId, controller) {
    var init = await fetchUploadWith429Retry(fetch, conversationsEndpointFor(context.machineId, "/" + encodeURIComponent(conversationId) + "/attachment-uploads"), {
      method: "POST", credentials: "same-origin", headers: conversationHeaders(), signal: controller.signal,
      body: JSON.stringify({ filename: file.name, byteSize: file.size }),
    }, { signal: controller.signal });
    var initialized = await init.json().catch(function () { return {}; });
    if (!init.ok || !initialized.upload || !/^[0-9a-f-]{36}$/i.test(String(initialized.upload.id || "")) || !Number.isSafeInteger(initialized.upload.chunkBytes) || initialized.upload.chunkBytes < 1) throw new Error(String(initialized.message || "Impossibile avviare il caricamento."));
    var uploadId = String(initialized.upload.id); var offset = Number(initialized.upload.offset) || 0; var chunkBytes = initialized.upload.chunkBytes;
    instance.attachmentUpload = { id: uploadId, filename: file.name, percent: Math.floor(offset * 100 / file.size) }; renderPendingAttachments(instance);
    try {
      while (offset < file.size) {
        if (controller.signal.aborted || !isCurrentConversationContext(instance, context) || instance.conversationId !== conversationId) throw new DOMException("Caricamento annullato.", "AbortError");
        var chunk = file.slice(offset, Math.min(file.size, offset + chunkBytes));
        // The original filename is fixed in the authenticated upload manifest.
        // Each multipart request transports an opaque block of those bytes.
        var form = new FormData(); form.append("file", chunk, "chunk.bin");
        var headers = new Headers({ Accept: "application/json", "X-Requested-With": "platform-control-center", "X-Upload-Offset": String(offset) }); var csrf = csrfToken(); if (csrf) headers.set("X-CSRF-Token", csrf);
        var response = await fetchUploadWith429Retry(fetch, conversationsEndpointFor(context.machineId, "/" + encodeURIComponent(conversationId) + "/attachment-uploads/" + encodeURIComponent(uploadId) + "/chunks"), { method: "POST", credentials: "same-origin", headers: headers, body: form, signal: controller.signal }, { signal: controller.signal });
        var payload = await response.json().catch(function () { return {}; });
        var nextOffset = Number(payload?.upload?.offset);
        if (!response.ok || !Number.isSafeInteger(nextOffset) || nextOffset <= offset || nextOffset > file.size) throw new Error(String(payload.message || "Caricamento interrotto."));
        offset = nextOffset;
        if (instance.attachmentUpload && instance.attachmentUpload.id === uploadId) { instance.attachmentUpload.percent = Math.floor(offset * 100 / file.size); renderPendingAttachments(instance); }
      }
      var completed = await fetchUploadWith429Retry(fetch, conversationsEndpointFor(context.machineId, "/" + encodeURIComponent(conversationId) + "/attachment-uploads/" + encodeURIComponent(uploadId) + "/complete"), { method: "POST", credentials: "same-origin", headers: conversationHeaders(), body: "{}", signal: controller.signal }, { signal: controller.signal });
      var completion = await completed.json().catch(function () { return {}; });
      if (!completed.ok || !completion.attachment) throw new Error(String(completion.message || "Allegato non accettato."));
      if (isCurrentConversationContext(instance, context) && instance.conversationId === conversationId) await loadPendingAttachments(instance, context, conversationId);
    } catch (error) {
      // The browser does not retain a resumable upload ID across a failed
      // attempt. Ask the scoped server to clean it up on every failure; its
      // durable-record check turns a post-commit acknowledgement failure into
      // a harmless acknowledgement instead of deleting the saved object.
      if (uploadId) void abortResumableAttachment(context, conversationId, uploadId);
      throw error;
    } finally {
      if (instance.attachmentUpload && instance.attachmentUpload.id === uploadId) { instance.attachmentUpload = null; renderPendingAttachments(instance); }
    }
  }

  async function uploadAttachments(instance, files) {
    var remaining = Math.max(0, 5 - (instance.pendingAttachments || []).length);
    if (files.length > remaining) setState(instance, "Puoi inviare al massimo cinque allegati per messaggio.", true);
    for (var index = 0; index < files.length; index += 1) {
      if ((instance.pendingAttachments || []).length >= 5 || instance.busy) break;
      await uploadAttachment(instance, files[index]);
    }
  }

  function cancelAttachmentUpload(instance) {
    if (instance.attachmentUploadController) instance.attachmentUploadController.abort();
  }

  async function removePendingAttachment(instance, attachmentId) {
    if (!instance.conversationId || instance.attachmentUploading) return;
    var context = conversationContext(instance);
    var conversationId = instance.conversationId;
    instance.attachmentUploading = true; refreshModeAvailability(instance);
    try {
      var response = await fetch(conversationsEndpointFor(context.machineId, "/" + encodeURIComponent(conversationId) + "/attachments/" + encodeURIComponent(attachmentId)), { method: "DELETE", credentials: "same-origin", headers: conversationHeaders(), body: "{}" });
      if (!isCurrentConversationContext(instance, context) || instance.conversationId !== conversationId) return;
      if (!response.ok) throw new Error(await chatResponseError(response));
      instance.pendingAttachments = (instance.pendingAttachments || []).filter(function (item) { return item.id !== attachmentId; }); renderPendingAttachments(instance);
      setState(instance, "");
    } catch (error) { if (isCurrentConversationContext(instance, context) && instance.conversationId === conversationId) setState(instance, error && error.message ? error.message : "Rimozione allegato non riuscita.", true); }
    finally { instance.attachmentUploading = false; refreshModeAvailability(instance); }
  }

  function renderSources(instance, sources) { return sourceUrls(sources); }

  function bindStreamMessageId(node, response) {
    var id = response.headers.get("X-Server-AI-Message-Id");
    if (typeof id === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      node.item.setAttribute("data-ai-message-id", id);
    }
  }

  function renderMessageMode(node, requestedMode, resolvedMode) {
    var requested = String(requestedMode || "").toLowerCase();
    var resolved = String(resolvedMode || requested).toLowerCase();
    if (!["auto", "fast", "deep"].includes(requested) || !["fast", "deep"].includes(resolved)) return;
    var badge = node.item.querySelector(".server-ai-message-mode");
    if (!badge) {
      badge = document.createElement("small");
      badge.className = "server-ai-message-mode";
      node.item.appendChild(badge);
    }
    badge.textContent = requested.toUpperCase() + " · " + resolved.toUpperCase();
  }

  function renderGenerationStatus(node, status) {
    var label = status === "aborted" ? "Risposta interrotta" : status === "failed" ? "Risposta non completata" : "";
    if (!label) return;
    var badge = node.item.querySelector(".server-ai-message-status");
    if (!badge) {
      badge = document.createElement("small");
      badge.className = "server-ai-message-status";
      node.item.appendChild(badge);
    }
    badge.textContent = label;
  }

  function activityLabel(state) {
    var labels = {
      queued: "In attesa della risposta",
      preparing: "Preparazione della risposta",
      loading: "Connessione a GPT-6 Luna",
      thinking: "Analisi della richiesta",
      tools: "Consultazione degli strumenti",
      summarizing: "Sintesi della risposta",
      responding: "Elaborazione della risposta",
    };
    return labels[String(state || "").toLowerCase()] || "";
  }

  function toolLabel(name) {
    var labels = {
      getServerOverview: "Stato del server",
      getCpuUsage: "Utilizzo della CPU",
      getMemoryUsage: "Memoria disponibile",
      getDiskUsage: "Spazio disco",
      getLoadAverage: "Carico del server",
      getSystemUptime: "Disponibilità del server",
      getGpuStatus: "Metriche hardware",
      getDockerContainers: "Elenco dei contenitori",
      getContainerStatus: "Stato del contenitore",
      getContainerHealth: "Salute del contenitore",
      getContainerStats: "Risorse del contenitore",
      getContainerLogs: "Log del contenitore",
      getNetworkOverview: "Rete del server",
      getListeningServices: "Servizi pubblicati",
      getRecentSystemErrors: "Errori recenti",
      getApplicationHealth: "Stato delle applicazioni",
      getBackupStatus: "Stato dei backup",
      webSearch: "Ricerca sul web",
      webFetch: "Lettura della pagina selezionata",
      listMachineProjects: "Catalogo progetti", getProjectContainers: "Container progetto", getProjectOverview: "Panoramica progetto",
      searchProjectKnowledge: "Conoscenza progetto", searchProjectFiles: "Ricerca nei file", readProjectFile: "Lettura file",
      getProjectFileTree: "Albero file", listProjectFiles: "Elenco file", getProjectGitStatus: "Stato Git", getProjectGitLog: "Cronologia Git",
      getProjectGitBranch: "Branch Git", getProjectGitFileHistory: "Cronologia file Git", getProjectGitDiff: "Diff Git", getProjectGitBlame: "Blame Git",
      getProjectDatabaseSchema: "Schema database", getProjectDatabaseStats: "Statistiche database", explainProjectDatabase: "Piano query", queryProjectDatabase: "Query in sola lettura",
      readChatAttachment: "Lettura allegato", listChatArchive: "Contenuto dello ZIP", readChatArchiveEntry: "Lettura file nello ZIP",
      analyzeChatAttachment: "Analisi completa del file",
      createChatFile: "Creazione file", createChatZip: "Creazione archivio ZIP",
    };
    return labels[String(name || "")] || "";
  }

  function toolActivity(name, outcome, started, descriptor) {
    var label = toolLabel(name);
    if (!label) return "";
    if (descriptor && typeof descriptor === "object") {
      var target = typeof descriptor.target === "string" ? descriptor.target.slice(0, 240) : "";
      // The activity list names a real tool and its safe target. Counts and
      // generic completion prose belong only in the concise path summary.
      return [label, target].filter(Boolean).join(" · ");
    }
    if (started) return "Avvio: " + label;
    if (outcome === "unavailable") return label + " · non disponibile";
    return label;
  }

  function conciseActivitySummary(tools) {
    // A started or unavailable tool is useful in the detailed list, but it is
    // not evidence for the completed-path summary.
    var completed = tools.filter(function (tool) { return tool && tool.outcome === "success"; });
    var names = completed.map(function (tool) { return String(tool.name || ""); });
    var parts = [];
    if (names.includes("listMachineProjects")) parts.push("Catalogo progetti consultato.");
    var fileReads = completed.filter(function (tool) { return tool.name === "readProjectFile"; });
    if (fileReads.length) parts.push(fileReads.length + (fileReads.length === 1 ? " lettura di file completata." : " letture di file completate."));
    var databases = completed.filter(function (tool) { return /(?:Database|ProjectDatabase|explainProjectDatabase|queryProjectDatabase)/.test(String(tool.name || "")); });
    if (databases.length) parts.push("Consultati dati o schema del database.");
    if (names.some(function (name) { return name === "webSearch" || name === "webFetch"; })) parts.push("Consultate fonti sul web.");
    if (names.some(function (name) { return /^getContainer/.test(name) || name === "getProjectContainers"; })) parts.push("Verificati container associati.");
    return parts.slice(0, 4).join(" ");
  }

  function reasoningActivities(metadata, generationStatus) {
    var tools = metadata && Array.isArray(metadata.tools) ? metadata.tools : [];
    var activities = tools.map(function (tool) { return toolActivity(tool && tool.name, tool && tool.outcome, false, tool); }).filter(Boolean).slice(0, 24);
    var analysisSummary = metadata && typeof metadata.analysisSummary === "string" ? Array.from(metadata.analysisSummary.trim()).slice(0, 1200).join("") : "";
    return { summary: analysisSummary || conciseActivitySummary(tools), publicSummary: Boolean(analysisSummary), activities: activities };
  }

  function reasoningView(value) {
    if (Array.isArray(value)) return { summary: "", activities: value.filter(Boolean).slice(0, 24) };
    if (!value || typeof value !== "object") return { summary: "", activities: [] };
    return {
      summary: typeof value.summary === "string" ? Array.from(value.summary).slice(0, 1200).join("") : "",
      publicSummary: Boolean(value.publicSummary),
      activities: Array.isArray(value.activities) ? value.activities.filter(Boolean).slice(0, 24) : [],
    };
  }

  function renderReasoning(node, activities, complete) {
    var view = reasoningView(activities);
    var signature = JSON.stringify([Boolean(complete), view.publicSummary, view.summary, view.activities]);
    var previous = node.item.querySelector(".server-ai-reasoning");
    if (previous && previous._serverAiReasoningSignature === signature) return;
    var wasOpen = previous && previous.open;
    if (previous) previous.remove();
    var details = document.createElement("details");
    details.className = "server-ai-reasoning";
    details._serverAiReasoningSignature = signature;
    details.open = Boolean(wasOpen);
    var summary = document.createElement("summary");
    summary.textContent = "Ragionamento · " + (complete ? "Completato" : "In corso");
    var caption = document.createElement("small");
    caption.textContent = view.publicSummary ? "Sintesi dell’analisi" : "Attività eseguite";
    details.appendChild(summary);
    if (view.summary || view.activities.length) details.appendChild(caption);
    if (view.summary) {
      var path = document.createElement("p");
      path.className = "server-ai-reasoning-summary";
      path.textContent = view.summary;
      details.appendChild(path);
    }
    var list = document.createElement("ol");
    view.activities.forEach(function (activity) {
      var entry = document.createElement("li");
      entry.textContent = String(activity).slice(0, 320);
      list.appendChild(entry);
    });
    if (list.children.length) {
      if (view.publicSummary) {
        var toolCaption = document.createElement("small");
        toolCaption.textContent = "Strumenti utilizzati";
        details.appendChild(toolCaption);
      }
      details.appendChild(list);
    }
    node.item.insertBefore(details, node.content);
  }

  function addActivity(instance, message, activity) {
    if (!activity) return;
    message.activities.push(activity);
    renderReasoning(message.node, { summary: message.analysisSummary || "", publicSummary: Boolean(message.analysisSummary), activities: message.activities }, false);
    scrollTranscript(instance);
  }

  function handleEvent(instance, type, payload, message) {
    if (type === "status") {
      var requested = String(payload.requestedMode || "").toLowerCase();
      var resolved = String(payload.resolvedMode || "").toLowerCase();
      if (requested && resolved) renderMessageMode(message.node, requested, resolved);
    setState(instance, "Risposta GPT-6 Luna in corso…");
    } else if (type === "analysis_summary") {
      message.analysisSummary = typeof payload.text === "string" ? Array.from(payload.text).slice(0, 1200).join("") : "";
      renderReasoning(message.node, { summary: message.analysisSummary, publicSummary: Boolean(message.analysisSummary), activities: message.activities }, false);
      scrollTranscript(instance);
    } else if (type === "activity") {
      var state = String(payload.state || "").toLowerCase();
      addActivity(instance, message, toolActivity(payload.tool, payload.outcome, state === "tool_started", payload.activity));
    } else if (type === "delta") {
      message.text += String(payload.text || "");
      updateAssistant(instance, message, message.text, true);
    } else if (type === "sources") {
      message.sources = renderSources(instance, payload.sources);
      renderMessageSources(message.node, payload.sources);
      updateAssistant(instance, message, message.text, true);
    } else if (type === "metrics") {
      return;
    } else if (type === "error") {
      throw new Error(String(payload.message || payload.code || "La risposta AI non è disponibile."));
    }
  }

  function parseSse(instance, response, message, context) {
    var reader = response.body && response.body.getReader ? response.body.getReader() : null;
    if (!reader) throw new Error("Il browser non supporta lo streaming della risposta.");
    var decoder = new TextDecoder();
    var pending = "";
    var eventName = "message";
    var data = [];
    function dispatch() {
      if (!data.length) return;
      if (!isCurrentConversationContext(instance, context)) throw new DOMException("Contesto macchina cambiato.", "AbortError");
      var payload;
      try { payload = JSON.parse(data.join("\n")); } catch { throw new Error("Stream AI non valido."); }
      handleEvent(instance, eventName, payload || {}, message);
      eventName = "message";
      data = [];
    }
    return (async function () {
      while (true) {
        var read = await reader.read();
        pending += decoder.decode(read.value || new Uint8Array(), { stream: !read.done });
        var lines = pending.split("\n");
        pending = lines.pop();
        lines.forEach(function (raw) {
          var line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
          if (!line) { dispatch(); return; }
          if (line.indexOf("event:") === 0) eventName = line.slice(6).trim() || "message";
          else if (line.indexOf("data:") === 0) data.push(line.slice(5).replace(/^ /, ""));
        });
        if (read.done) break;
      }
      if (pending) data.push(pending.replace(/^data:\s?/, ""));
      dispatch();
    })();
  }

  function newRequestId() {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") return crypto.randomUUID();
    if (typeof window !== "undefined" && window.crypto && typeof window.crypto.randomUUID === "function") return window.crypto.randomUUID();
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (char) { var random = Math.random() * 16 | 0; var value = char === "x" ? random : random & 3 | 8; return value.toString(16); });
  }

  function generationResponseIds(response, payload) {
    var uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    var queueItem = payload && payload.queueItem && typeof payload.queueItem === "object" ? payload.queueItem : null;
    var queueItemId = queueItem && uuid.test(String(queueItem.id || "")) ? String(queueItem.id) : "";
    var responseRequestId = queueItem && uuid.test(String(queueItem.requestId || "")) ? String(queueItem.requestId) : "";
    // Immediate generations may already have an assistant id. Queued
    // generations intentionally do not: their durable identity is the
    // nested queueItem envelope returned by the HTTP contract.
    var assistantId = queueItem && uuid.test(String(queueItem.assistantId || "")) ? String(queueItem.assistantId) : (payload && uuid.test(String(payload.assistantId || "")) ? String(payload.assistantId) : "");
    return { queueItem: queueItem, queueItemId: queueItemId, responseRequestId: responseRequestId, assistantId: assistantId, accepted: response.status === 202 && Boolean(assistantId || responseRequestId) };
  }

  async function send(instance) {
    var text = instance.prompt.value.trim();
    var attachmentIds = (instance.pendingAttachments || []).map(function (item) { return item.id; });
    var wasBusy = instance.busy;
    // Every ordinary send is durable queue work, including an idle chat. The
    // separate priority action is the only way to request interruption.
    var delivery = instance.nextDelivery === "immediate" ? "immediate" : "queue";
    instance.nextDelivery = null;
    if ((!text && !attachmentIds.length) || instance.attachmentUploading || !instance.generationAvailable || (instance.machineState !== "active" && instance.machineState !== "degraded") || !instance.selectedMachineId) return;
    clearQuickReplies(instance);
    instance.chatError = false;
    var context = conversationContext(instance);
    if (!instance.conversationId) {
      try { await createConversation(instance); }
      catch (error) {
        if (isCurrentConversationContext(instance, context) && (!error || error.name !== "AbortError")) setState(instance, error && error.message ? error.message : "Impossibile creare la conversazione.", true);
        return;
      }
    }
    if (!isCurrentConversationContext(instance, context) || !instance.conversationId) return;
    var targetConversationId = String(instance.conversationId);
    // The idempotency key belongs to this exact operation.  In particular,
    // changing mode, delivery, machine, or chat must never reuse a previous
    // key after a late network response.
    var requestFingerprint = JSON.stringify([text, attachmentIds, instance.mode, delivery, context.machineId, targetConversationId]);
    var requestId = instance.pendingRequest && instance.pendingRequest.fingerprint === requestFingerprint ? instance.pendingRequest.id : newRequestId();
    instance.pendingRequest = { id: requestId, fingerprint: requestFingerprint };
    var userNode = Array.from(instance.transcript.querySelectorAll(".server-ai-message.user[data-ai-request-id]")).map(function (item) {
      return { item: item, content: item.querySelector(".server-ai-message-content") };
    }).find(function (node) { return node.item.getAttribute("data-ai-request-id") === requestId; });
    if (!userNode) {
      userNode = addMessage(instance, "user", text || "Analizza gli allegati.", false);
      renderMessageAttachments(instance, userNode, instance.pendingAttachments);
    }
    userNode.item.setAttribute("data-ai-request-id", requestId);
    instance.prompt.value = "";
    resizePrompt(instance);
    var message = { text: "", sources: new Set(), activities: [], node: null };
    var controller = new AbortController();
    instance.controller = controller;
    setBusy(instance, true);
    setState(instance, instance.mode === "deep" ? "Ragionamento…" : "Risposta GPT-6 Luna…");
    try {
      var response = await fetch(conversationsEndpointFor(context.machineId, "/" + encodeURIComponent(instance.conversationId) + "/messages"), {
        method: "POST", credentials: "same-origin", headers: conversationHeaders(), signal: controller.signal,
        body: JSON.stringify({ message: text, requestedMode: instance.mode, delivery: delivery, requestId: requestId, ...(attachmentIds.length ? { attachmentIds: attachmentIds } : {}) }),
      });
      var payload = await response.json().catch(function () { return {}; });
      // A response may arrive after navigation or machine/chat selection. Do
      // this check before touching optimistic DOM, queue state, or pending
      // uploads with data from the old context.
      if (!isCurrentConversationContext(instance, context) || instance.conversationId !== targetConversationId) return;
      var parsed = generationResponseIds(response, payload);
      var queueItem = parsed.queueItem;
      var queueItemId = parsed.queueItemId;
      var responseRequestId = parsed.responseRequestId;
      var assistantId = parsed.assistantId;
      if (!parsed.accepted) throw new Error(await chatResponseError(response));
      if (assistantId) {
        message.node = addMessage(instance, "assistant", "", true);
        renderReasoning(message.node, message.activities, false);
        bindStreamMessageId(message.node, response);
        if (!message.node.item.getAttribute("data-ai-message-id")) message.node.item.setAttribute("data-ai-message-id", assistantId);
      }
      if (requestId) userNode.item.setAttribute("data-ai-request-id", requestId);
      if (message.node && requestId) message.node.item.setAttribute("data-ai-request-id", requestId);
      instance.pendingRequest = null;
      if (delivery === "immediate" || !instance.activeAssistantId) instance.activeAssistantId = assistantId || instance.activeAssistantId;
      instance.pendingAttachments = []; renderPendingAttachments(instance);
      if (!isCurrentConversationContext(instance, context)) return;
      if (payload.queued === true || payload.delivery === "queue" || delivery === "queue" || queueItem) {
        var queued = (instance.queueItems || []).filter(function (item) { return item.requestId !== requestId; });
        if (requestId) queued.push({ id: queueItemId || responseRequestId || requestId, requestId: responseRequestId || requestId, text: text, status: queueItem && queueItem.status || "queued", delivery: queueItem && queueItem.delivery || delivery, errorCode: queueItem && queueItem.errorCode || "" });
        renderConversationQueue(instance, queued);
        setState(instance, "Richiesta aggiunta alla coda.");
      } else setState(instance, "Elaborazione in corso…");
      scheduleConversationPoll(instance, context, true);
    } catch (error) {
      if (!isCurrentConversationContext(instance, context)) return;
      if (message.node) {
        message.node.item.classList.remove("server-ai-streaming");
        renderReasoning(message.node, message.activities, true);
        if (!message.text.trim()) message.node.item.remove();
      }
      // A follow-up may have been drafted while this request was in flight.
      // Restore the failed text only when the composer is still empty; never
      // overwrite newer user input from the same or another queued turn.
      if (text && !instance.prompt.value.trim()) { instance.prompt.value = text; resizePrompt(instance); }
      instance.chatError = true;
      setState(instance, error && error.message ? error.message : "La risposta AI non è disponibile.", true);
      // A failed queued/priority follow-up must not stop the already-running
      // turn. Restore the state captured before this request was attempted.
      setBusy(instance, wasBusy);
      // A rejected request can still have crossed the durable bind boundary.
      // Reload pending metadata only for this unchanged chat so stale IDs are
      // never retried after the assistant has been finalized as failed.
      void loadPendingAttachments(instance, context, instance.conversationId).catch(function () {});
    } finally {
      if (instance.controller === controller) instance.controller = null;
    }
  }

  async function chatResponseError(response) {
    var payload = await response.json().catch(function () { return null; });
    var value = payload && (payload.message || payload.error);
    if (typeof value === "string" && value.trim() && !/[<>]/.test(value)) return value.slice(0, 500);
    return "Richiesta AI non riuscita (HTTP " + response.status + "). Riprova tra poco.";
  }

  function conversationsEndpoint(instance, suffix) {
    return conversationsEndpointFor(instance.selectedMachineId, suffix);
  }

  function conversationsEndpointFor(machineId, suffix) {
    return "/control/v1/machines/" + encodeURIComponent(machineId) + "/server-ai/conversations" + (suffix || "");
  }

  function conversationContext(instance) {
    return { machineId: instance.selectedMachineId, epoch: instance.contextEpoch };
  }

  function isCurrentConversationContext(instance, context) {
    return Boolean(context) && active === instance && instance.root.isConnected && instance.selectedMachineId === context.machineId && instance.contextEpoch === context.epoch;
  }

  function abortConversationRequests(instance) {
    ["conversationListController", "conversationDetailController", "conversationCreateController", "generationPollController", "attachmentUploadController"].forEach(function (key) {
      if (instance[key]) instance[key].abort();
      instance[key] = null;
    });
    instance.attachmentUpload = null;
    renderPendingAttachments(instance);
  }

  function conversationHeaders() {
    var headers = new Headers({ Accept: "application/json", "Content-Type": "application/json", "X-Requested-With": "platform-control-center" });
    var csrf = csrfToken();
    if (csrf) headers.set("X-CSRF-Token", csrf);
    return headers;
  }

  async function createConversation(instance) {
    var context = conversationContext(instance);
    if (!context.machineId) return false;
    if (instance.conversationCreateController) instance.conversationCreateController.abort();
    var controller = new AbortController();
    instance.conversationCreateController = controller;
    var response = await fetch(conversationsEndpointFor(context.machineId), { method: "POST", credentials: "same-origin", headers: conversationHeaders(), body: "{}", signal: controller.signal });
    var payload = await response.json().catch(function () { return {}; });
    if (!isCurrentConversationContext(instance, context)) return false;
    if (!response.ok || !payload.conversation || !payload.conversation.id) throw new Error(String(payload.message || payload.error || "Impossibile creare la conversazione."));
    instance.conversationId = String(payload.conversation.id);
    instance.conversationTitle.textContent = String(payload.conversation.title || "Nuova chat");
    await loadConversations(instance);
    return true;
  }

  function conversationDate(value) {
    var date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function sameLocalDay(left, right) {
    return left.getFullYear() === right.getFullYear() && left.getMonth() === right.getMonth() && left.getDate() === right.getDate();
  }

  function conversationTime(value) {
    var date = conversationDate(value);
    if (!date) return "";
    return sameLocalDay(date, new Date())
      ? date.toLocaleTimeString("it-IT", { hour: "2-digit", minute: "2-digit" })
      : date.toLocaleDateString("it-IT", { day: "2-digit", month: "short" });
  }

  function appendConversationRow(instance, conversation) {
    var item = document.createElement("li");
    item.className = "server-ai-conversation-row";
    var open = document.createElement("button");
    open.type = "button";
    open.setAttribute("data-ai-open-conversation", conversation.id);
    open.className = String(conversation.id) === String(instance.conversationId) ? "active" : "";
    var title = document.createElement("span");
    title.className = "server-ai-conversation-title";
    title.textContent = String(conversation.title || "Nuova chat").slice(0, 160);
    var updated = document.createElement("time");
    updated.className = "server-ai-conversation-time";
    updated.textContent = conversationTime(conversation.updatedAt);
    if (updated.textContent) {
      var date = conversationDate(conversation.updatedAt);
      updated.dateTime = date.toISOString();
      updated.title = date.toLocaleString("it-IT", { dateStyle: "medium", timeStyle: "short" });
    }
    open.appendChild(title);
    open.appendChild(updated);
    item.appendChild(open);
    var actions = document.createElement("details");
    actions.className = "server-ai-conversation-actions";
    var summary = document.createElement("summary");
    summary.setAttribute("aria-label", "Azioni conversazione");
    summary.textContent = "⋯";
    actions.appendChild(summary);
    [ ["Rinomina", "rename"], ["Elimina", "delete"] ].forEach(function (action) {
      var button = document.createElement("button");
      button.type = "button";
      button.setAttribute("data-ai-conversation-action", action[1]);
      button.setAttribute("data-ai-conversation-id", conversation.id);
      button.textContent = action[0];
      actions.appendChild(button);
    });
    item.appendChild(actions);
    instance.conversationList.appendChild(item);
  }

  function renderConversationList(instance) {
    instance.conversationList.replaceChildren();
    var query = String(instance.conversationSearch && instance.conversationSearch.value || "").trim().toLocaleLowerCase("it-IT");
    var conversations = instance.conversations.filter(function (conversation) {
      return !query || String(conversation.title || "Nuova chat").toLocaleLowerCase("it-IT").includes(query);
    });
    if (!conversations.length && query) {
      var empty = document.createElement("li");
      empty.className = "server-ai-conversation-empty";
      empty.textContent = "Nessuna conversazione trovata.";
      instance.conversationList.appendChild(empty);
      return;
    }
    var today = [];
    var previous = [];
    var undated = [];
    conversations.forEach(function (conversation) {
      var updated = conversationDate(conversation.updatedAt);
      if (!updated) { undated.push(conversation); return; }
      (sameLocalDay(updated, new Date()) ? today : previous).push(conversation);
    });
    [ ["Oggi", today], ["Precedenti", previous] ].forEach(function (group) {
      if (!group[1].length) return;
      var heading = document.createElement("li");
      heading.className = "server-ai-conversation-group";
      heading.textContent = group[0];
      instance.conversationList.appendChild(heading);
      group[1].forEach(function (conversation) { appendConversationRow(instance, conversation); });
    });
    undated.forEach(function (conversation) { appendConversationRow(instance, conversation); });
  }

  async function loadConversations(instance, append) {
    var context = conversationContext(instance);
    if (!context.machineId) return;
    if (append && !instance.nextConversationCursor) return;
    if (instance.conversationListController) instance.conversationListController.abort();
    var controller = new AbortController();
    instance.conversationListController = controller;
    var cursor = append ? "?cursor=" + encodeURIComponent(instance.nextConversationCursor) : "";
    var response = await fetch(conversationsEndpointFor(context.machineId, cursor), { credentials: "same-origin", headers: { Accept: "application/json" }, signal: controller.signal });
    var payload = await response.json().catch(function () { return {}; });
    if (!isCurrentConversationContext(instance, context)) return;
    if (controller.signal.aborted || instance.conversationListController !== controller) return;
    if (!response.ok || !Array.isArray(payload.conversations)) throw new Error(String(payload.message || payload.error || "Conversazioni non disponibili."));
    var previous = append ? instance.conversations : [];
    instance.conversations = payload.conversations.filter(function (entry) { return entry && entry.id && !previous.some(function (old) { return old.id === entry.id; }); });
    instance.conversations = previous.concat(instance.conversations);
    instance.nextConversationCursor = typeof payload.nextCursor === "string" ? payload.nextCursor : null;
    if (instance.moreConversations) instance.moreConversations.hidden = !instance.nextConversationCursor;
    var current = instance.conversations.find(function (entry) { return String(entry.id) === instance.conversationId; });
    if (current) instance.conversationTitle.textContent = String(current.title || "Nuova chat").slice(0, 120);
    renderConversationList(instance);
  }

  function applyStoredAssistant(instance, node, stored) {
    var sources = sourceValues(stored.sources);
    var text = String(stored.content || "");
    var sourceSignature = JSON.stringify(sources.map(function (source) { return [source.id, source.type, source.projectId || "", source.sha256 || "", source.url && source.url.href || ""]; }));
    if (node.item._serverAiRawContent !== text || node.item.classList.contains("server-ai-streaming") !== (stored.generationStatus === "streaming") || node.item._serverAiSourceSignature !== sourceSignature) {
      updateAssistant(instance, { node: node, text: text, sources: sourceUrls(sources) }, text, stored.generationStatus === "streaming");
      node.item._serverAiSourceSignature = sourceSignature;
    }
    renderMessageMode(node, stored.requestedMode, stored.resolvedMode);
    renderGenerationStatus(node, stored.generationStatus);
    renderMessageSources(node, sources);
    renderMessageArtifacts(instance, node, stored.artifacts);
    renderReasoning(node, reasoningActivities(stored.toolMetadata, stored.generationStatus), stored.generationStatus !== "streaming");
    scrollTranscript(instance);
  }

  function renderedMessageNode(instance, id) {
    var entries = instance.transcript.querySelectorAll("[data-ai-message-id]");
    for (var index = 0; index < entries.length; index += 1) {
      if (entries[index].getAttribute("data-ai-message-id") === String(id)) {
        var content = entries[index].querySelector(".server-ai-message-content");
        if (content) return { item: entries[index], content: content };
      }
    }
    return null;
  }

  function renderStoredMessage(instance, stored) {
    if (stored.role !== "user" && stored.role !== "assistant") return null;
    var sources = stored.role === "assistant" ? sourceValues(stored.sources) : [];
    var node = addMessage(instance, stored.role, String(stored.content || ""), stored.generationStatus === "streaming", stored.role === "assistant" ? sourceUrls(sources) : null);
    if (stored && stored.id) node.item.setAttribute("data-ai-message-id", String(stored.id));
    if (stored.role === "user") renderMessageAttachments(instance, node, stored.attachments);
    if (stored.role === "assistant") applyStoredAssistant(instance, node, stored);
    return node;
  }

  function reorderReconciledMessages(instance, messages) {
    var transcript = instance.transcript;
    if (!transcript || !transcript.children || !Array.isArray(messages)) return;
    var ordered = messages.map(function (stored) { return stored && stored.id ? renderedMessageNode(instance, stored.id) : null; }).filter(Boolean).map(function (node) { return node.item; });
    var current = Array.from(transcript.children).filter(function (item) { return ordered.includes(item); });
    var needsMove = current.length !== ordered.length || current.some(function (item, index) { return item !== ordered[index]; });
    if (ordered.length > 1 && needsMove) {
      var marker = document.createComment("server-ai-message-order");
      transcript.insertBefore(marker, ordered[0]);
      ordered.forEach(function (item) { item.remove(); });
      ordered.forEach(function (item) { transcript.insertBefore(item, marker); });
      marker.remove();
    }
    // A user turn that has been optimistically displayed but is not in this
    // detail response yet is still pending. Keep it after all persisted
    // ordinal messages so a later assistant cannot appear beneath it.
    var pending = Array.from(transcript.children).filter(function (item) {
      return item.classList && item.classList.contains("user") && item.getAttribute("data-ai-request-id") && !item.getAttribute("data-ai-message-id");
    });
    pending.forEach(function (item) { item.remove(); });
    pending.forEach(function (item) { transcript.appendChild(item); });
  }

  function reconcileStoredMessages(instance, messages) {
    if (!Array.isArray(messages)) return;
    messages.forEach(function (stored, index) {
      if (!stored || (stored.role !== "user" && stored.role !== "assistant")) return;
      var node = stored.id ? renderedMessageNode(instance, stored.id) : null;
      if (!node && stored.role === "user") {
        var content = String(stored.content || "");
        var optimistic = Array.from(instance.transcript.querySelectorAll(".server-ai-message.user[data-ai-request-id]"));
        optimistic = optimistic.find(function (candidate) { return !candidate.getAttribute("data-ai-message-id") && candidate._serverAiRawContent === content; });
        if (optimistic) {
          if (stored.id) optimistic.setAttribute("data-ai-message-id", String(stored.id));
          node = { item: optimistic, content: optimistic.querySelector(".server-ai-message-content") };
        }
      }
      if (node) return;
      var created = renderStoredMessage(instance, stored);
      if (!created) return;
      for (var next = index + 1; next < messages.length; next += 1) {
        var nextNode = messages[next] && messages[next].id ? renderedMessageNode(instance, messages[next].id) : null;
        if (nextNode && nextNode.item.parentNode === instance.transcript) { instance.transcript.insertBefore(created.item, nextNode.item); return; }
      }
    });
    reorderReconciledMessages(instance, messages);
  }

  async function refreshActiveConversation(instance, context) {
    var id = instance.conversationId;
    if (!id || (!instance.busy && !instance.scanBusy && !instance.queueBusy) || !isCurrentConversationContext(instance, context)) return;
    if (instance.generationPollController) instance.generationPollController.abort();
    var controller = new AbortController();
    instance.generationPollController = controller;
    try {
      var response = await fetch(conversationsEndpointFor(context.machineId, "/" + encodeURIComponent(id)), { credentials: "same-origin", headers: { Accept: "application/json" }, signal: controller.signal });
      var payload = await response.json().catch(function () { return {}; });
      if (controller.signal.aborted || instance.generationPollController !== controller || !isCurrentConversationContext(instance, context) || id !== instance.conversationId) return;
      if (!response.ok || !payload.conversation || !Array.isArray(payload.messages)) throw new Error(String(payload.message || payload.error || "Conversazione non disponibile."));
      renderConversationScans(instance, payload.scans, payload.continuationPending);
      renderConversationQueue(instance, payload.queue || payload.conversation.queue);
      reconcileStoredMessages(instance, payload.messages);
      var activeMessage = null;
      payload.messages.forEach(function (stored) {
        if (!stored || stored.role !== "assistant") return;
        var node = renderedMessageNode(instance, stored.id);
        if (!node) return;
        applyStoredAssistant(instance, node, stored);
        if (["pending", "streaming"].includes(stored.generationStatus)) activeMessage = stored;
      });
      if (activeMessage) {
        instance.activeAssistantId = activeMessage.id || null;
        setBusy(instance, true);
        setState(instance, activeMessage.toolMetadata && activeMessage.toolMetadata.state === "tools" ? "Consultazione strumenti…" : "Elaborazione in corso…");
        scheduleConversationPoll(instance, context, false);
        return;
      }
      instance.activeAssistantId = null;
      setBusy(instance, false);
      var terminal = payload.messages.filter(function (stored) { return stored && stored.role === "assistant"; }).at(-1);
      if (instance.queueBusy) setState(instance, queueActivityLabel(instance.queueItems));
      else if (terminal && terminal.generationStatus === "aborted") setState(instance, "Risposta interrotta.");
      else if (terminal && terminal.generationStatus === "failed") setState(instance, "Risposta non completata.", true);
      else setState(instance, "Risposta completata.");
      renderLatestQuickReplies(instance, payload.messages);
      if (instance.scanBusy || instance.queueBusy) scheduleConversationPoll(instance, context, false);
      void loadConversations(instance).catch(function () {});
    } finally {
      if (instance.generationPollController === controller) instance.generationPollController = null;
    }
  }

  function scheduleConversationPoll(instance, context, immediate) {
    if (instance.generationPollTimer) window.clearTimeout(instance.generationPollTimer);
    if (!isCurrentConversationContext(instance, context) || !instance.conversationId || (!instance.busy && !instance.scanBusy && !instance.queueBusy)) return;
    instance.generationPollTimer = window.setTimeout(function () {
      if (!isCurrentConversationContext(instance, context) || !instance.conversationId || (!instance.busy && !instance.scanBusy && !instance.queueBusy)) return;
      refreshActiveConversation(instance, context).catch(function (error) {
        if (error && error.name !== "AbortError" && isCurrentConversationContext(instance, context)) {
          setState(instance, error.message || "Aggiornamento conversazione non disponibile.", true);
          scheduleConversationPoll(instance, context, false);
        }
      });
    }, immediate ? 0 : instance.busy ? 800 : 2000);
  }

  async function openConversation(instance, id, before) {
    var loadingOlder = before != null;
    if (!id || (instance.busy && loadingOlder)) return;
    var context = conversationContext(instance);
    if (!context.machineId) return;
    if (loadingOlder) pauseTranscriptFollow(instance);
    if (instance.conversationDetailController) instance.conversationDetailController.abort();
    var controller = new AbortController();
    instance.conversationDetailController = controller;
    var cursor = before == null ? "" : "?before=" + encodeURIComponent(String(before));
    var response = await fetch(conversationsEndpointFor(context.machineId, "/" + encodeURIComponent(id) + cursor), { credentials: "same-origin", headers: { Accept: "application/json" }, signal: controller.signal });
    var payload = await response.json().catch(function () { return {}; });
    if (controller.signal.aborted || instance.conversationDetailController !== controller || !isCurrentConversationContext(instance, context)) return;
    if (!response.ok || !payload.conversation || !Array.isArray(payload.messages)) throw new Error(String(payload.message || payload.error || "Conversazione non disponibile."));
    instance.conversationId = String(payload.conversation.id);
    instance.conversationTitle.textContent = String(payload.conversation.title || "Nuova chat");
    var scrollTop = instance.transcript.scrollTop;
    var scrollHeight = instance.transcript.scrollHeight;
    var anchor = loadingOlder ? (instance.loadOlder && instance.transcript.contains(instance.loadOlder) ? instance.loadOlder.nextSibling : instance.transcript.firstChild) : null;
    if (!loadingOlder) {
      var older = instance.loadOlder;
      if (older && instance.transcript.contains(older)) older.remove();
      instance.transcript.replaceChildren();
      if (older && !older.parentNode) instance.transcript.appendChild(older);
    }
    var rendered = [];
    payload.messages.forEach(function (stored) { var node = renderStoredMessage(instance, stored); if (node) rendered.push({ node: node, stored: stored }); });
    if (loadingOlder && anchor) rendered.forEach(function (entry) { instance.transcript.insertBefore(entry.node.item, anchor); });
    instance.nextBefore = typeof payload.nextBefore === "string" && /^\d+$/.test(payload.nextBefore) ? payload.nextBefore : null;
    instance.loadOlder.hidden = !instance.nextBefore;
    if (loadingOlder) {
      instance.transcript.scrollTop = scrollTop + instance.transcript.scrollHeight - scrollHeight;
      refreshJumpToBottom(instance);
    }
    else if (!rendered.length) clearConversation(instance);
    var inProgress = payload.messages.some(function (stored) { return stored && stored.role === "assistant" && (stored.generationStatus === "pending" || stored.generationStatus === "streaming"); });
    if (!loadingOlder && id === instance.conversationId) {
      setBusy(instance, inProgress);
      renderConversationScans(instance, payload.scans, payload.continuationPending);
      renderConversationQueue(instance, payload.queue || payload.conversation.queue);
      if (inProgress) {
        var activeMessage = payload.messages.filter(function (stored) { return stored && stored.role === "assistant" && (stored.generationStatus === "pending" || stored.generationStatus === "streaming"); }).at(-1);
        instance.activeAssistantId = activeMessage && activeMessage.id || null;
        setState(instance, activeMessage && activeMessage.toolMetadata && activeMessage.toolMetadata.state === "tools" ? "Consultazione strumenti…" : "Elaborazione in corso…");
        scheduleConversationPoll(instance, context, false);
      } else {
        instance.activeAssistantId = null;
        if (instance.queueBusy) setState(instance, queueActivityLabel(instance.queueItems));
        renderLatestQuickReplies(instance, payload.messages);
      if (instance.scanBusy || instance.queueBusy) scheduleConversationPoll(instance, context, false);
      }
      void loadPendingAttachments(instance, context, id).catch(function (error) { if (isCurrentConversationContext(instance, context) && instance.conversationId === id) setState(instance, error.message || "Allegati non disponibili.", true); });
    }
    renderConversationList(instance); setDrawerOpen(instance, false);
    return payload;
  }

  function editConversation(instance, action, id, row) {
    var conversation = instance.conversations.find(function (entry) { return entry.id === id; });
    if (!conversation || !row) return;
    instance.conversationList.querySelectorAll("[data-ai-conversation-edit]").forEach(function (editor) { editor.remove(); });
    var form = document.createElement("form");
    form.className = "server-ai-conversation-edit";
    form.setAttribute("data-ai-conversation-edit", "");
    var input = null;
    if (action === "rename") {
      input = document.createElement("input");
      input.type = "text"; input.value = String(conversation.title || ""); input.maxLength = 160; input.required = true;
      input.setAttribute("aria-label", "Titolo della conversazione");
      form.appendChild(input);
    } else {
      var label = document.createElement("p"); label.textContent = "Eliminare questa conversazione?"; form.appendChild(label);
    }
    var save = document.createElement("button"); save.type = "submit"; save.textContent = action === "rename" ? "Salva titolo" : "Conferma eliminazione";
    var cancel = document.createElement("button"); cancel.type = "button"; cancel.textContent = "Annulla";
    cancel.addEventListener("click", function () { form.remove(); });
    form.appendChild(save); form.appendChild(cancel);
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      if (save.disabled || (input && !input.value.trim())) return;
      save.disabled = true; cancel.disabled = true;
      changeConversation(instance, action, id, input ? input.value.trim() : undefined).catch(function (error) {
        setState(instance, error.message || "Operazione non riuscita.", true);
        save.disabled = false; cancel.disabled = false;
      });
    });
    row.appendChild(form);
    if (input) { input.focus(); input.select(); } else save.focus();
  }

  async function changeConversation(instance, action, id, title) {
    var context = conversationContext(instance);
    var conversation = instance.conversations.find(function (entry) { return entry.id === id; });
    if (!conversation) return;
    if (action === "delete") {
      if (instance.busy) {
        if (id !== instance.conversationId) {
          setState(instance, "Questa conversazione ha una risposta in corso in un'altra sessione.", true);
          return;
        }
        await requestGenerationCancel(instance);
        var deadline = Date.now() + 1500;
        while (instance.busy && Date.now() < deadline) await new Promise(function (resolve) { window.setTimeout(resolve, 50); });
        if (!isCurrentConversationContext(instance, context)) return;
        if (instance.busy) {
          setState(instance, "Attendi la conferma dell'interruzione prima di eliminare la conversazione.", true);
          return;
        }
      }
      var deleted = await fetch(conversationsEndpointFor(context.machineId, "/" + encodeURIComponent(id)), { method: "DELETE", credentials: "same-origin", headers: conversationHeaders() });
      if (!isCurrentConversationContext(instance, context)) return;
      if (!deleted.ok) {
        if (deleted.status === 409) throw new Error("Questa conversazione ha una risposta in corso in un'altra sessione.");
        throw new Error("Impossibile eliminare la conversazione.");
      }
      if (id === instance.conversationId) { instance.conversationId = ""; instance.conversationTitle.textContent = "Nuova chat"; clearConversation(instance); }
    } else {
      if (typeof title !== "string" || !title.trim()) return;
      var renamed = await fetch(conversationsEndpointFor(context.machineId, "/" + encodeURIComponent(id)), { method: "PATCH", credentials: "same-origin", headers: conversationHeaders(), body: JSON.stringify({ title: title.trim() }) });
      if (!isCurrentConversationContext(instance, context)) return;
      if (!renamed.ok) throw new Error("Impossibile rinominare la conversazione.");
      if (id === instance.conversationId) instance.conversationTitle.textContent = title.trim() || "Nuova chat";
    }
    await loadConversations(instance);
  }

  function isMobileDrawer() {
    return typeof window.matchMedia === "function" && window.matchMedia("(max-width: 980px)").matches;
  }

  function setDrawerOpen(instance, open, returnFocus) {
    var mobile = isMobileDrawer();
    instance.root.classList.toggle("server-ai-drawer-open", Boolean(open));
    if (instance.drawer) {
      if (mobile && "inert" in instance.drawer) instance.drawer.inert = !open;
      else if (!mobile && "inert" in instance.drawer) instance.drawer.inert = false;
      instance.drawer.setAttribute("aria-hidden", mobile && !open ? "true" : "false");
    }
    if (instance.openConversations) instance.openConversations.setAttribute("aria-expanded", open ? "true" : "false");
    if (!open && returnFocus && instance.drawerOpener && instance.drawerOpener.isConnected) instance.drawerOpener.focus();
  }

  function closeOpenDetails(instance) {
    instance.root.querySelectorAll("details[open]").forEach(function (details) { details.open = false; });
  }

  function renderEmptyConversation(instance) {
    var empty = document.createElement("section");
    empty.className = "server-ai-empty";
    empty.setAttribute("data-ai-empty", "");
    var mark = document.createElement("span");
    mark.className = "server-ai-empty-mark";
    mark.textContent = "AI";
    var title = document.createElement("h2");
    title.textContent = "Come posso aiutarti?";
    var copy = document.createElement("p");
    copy.textContent = "Controlla il server, approfondisci un problema o cerca nella documentazione.";
    var suggestions = document.createElement("div");
    suggestions.className = "server-ai-suggestions";
    [
      ["Stato del server", "Controlla lo stato attuale del server."],
      ["Analizza un problema", "Aiutami ad analizzare questo problema: "],
      ["Cerca sul web", "Cerca nella documentazione ufficiale: "],
    ].forEach(function (suggestion) {
      var button = document.createElement("button");
      button.type = "button";
      button.setAttribute("data-ai-suggestion", suggestion[1]);
      button.textContent = suggestion[0];
      suggestions.appendChild(button);
    });
    empty.appendChild(mark);
    empty.appendChild(title);
    empty.appendChild(copy);
    empty.appendChild(suggestions);
    instance.transcript.appendChild(empty);
  }

  function clearConversation(instance) {
    instance.scanBusy = false;
    instance.queueBusy = false;
    instance.queueItems = [];
    instance.queueErrors = [];
    instance.pendingRequest = null;
    renderConversationQueue(instance, []);
    instance.chatError = false;
    cancelTranscriptScrollFrames(instance);
    if (instance.generationPollTimer) window.clearTimeout(instance.generationPollTimer);
    instance.generationPollTimer = null;
    instance.controller = null;
    instance.activeAssistantId = null;
    instance.prompt.value = "";
    resizePrompt(instance);
    var older = instance.loadOlder;
    if (older && instance.transcript.contains(older)) older.remove();
    instance.transcript.replaceChildren();
    if (older && !older.parentNode) instance.transcript.appendChild(older);
    renderEmptyConversation(instance);
    instance.nextBefore = null;
    instance.loadOlder.hidden = true;
    instance.autoScroll = true;
    instance.pointerScrolling = false;
    instance.userScrollUntil = 0;
    refreshJumpToBottom(instance);
    setBusy(instance, false);
  }

  function scheduleStatusPoll(instance) {
    if (instance.pollTimer) window.clearTimeout(instance.pollTimer);
    if (active !== instance || !instance.root.isConnected || !instance.selectedMachineId) return;
    var transient = (instance.machineState === "starting" || instance.machineState === "stopping") && Date.now() < instance.transientUntil;
    instance.pollTimer = window.setTimeout(function () { refreshStatus(instance); }, transient ? 1000 : 15000);
  }

  function endpoint(instance, suffix) {
    return "/control/v1/machines/" + encodeURIComponent(instance.selectedMachineId) + "/server-ai" + suffix;
  }

  async function refreshStatus(instance) {
    if (!instance.selectedMachineId || active !== instance) return null;
    var machineId = instance.selectedMachineId;
    if (instance.statusController) instance.statusController.abort();
    var controller = new AbortController();
    instance.statusController = controller;
    try {
      var response = await fetchUploadWith429Retry(fetch, endpoint(instance, "/status"), { credentials: "same-origin", headers: { Accept: "application/json" }, signal: controller.signal }, { signal: controller.signal });
      var status = await response.json().catch(function () { return {}; });
      if (!response.ok) throw new Error(String(status.message || status.error || "Stato non disponibile."));
      if (active !== instance || machineId !== instance.selectedMachineId) return null;
      instance.lastMachineStatus = status;
      renderMachine(instance, status || {});
      instance.models = Array.isArray(status.models) ? status.models : null;
      updateMachineStatusMessage(instance, status);
      return status;
    } catch (error) {
      if (error && error.name === "AbortError") return null;
      if (active === instance && machineId === instance.selectedMachineId) {
        if (instance.historyAvailable || instance.lastMachineStatus) {
          // A dropped status poll does not invalidate a successful session,
          // erase its transcript, or discard model authorization already
          // established by an actual API response.
          instance.machineState = "degraded";
          instance.root.setAttribute("data-ai-machine-state", "degraded");
          instance.health.classList.remove("bad", "good");
          instance.health.classList.add("degraded");
          var staleHealth = instance.health.querySelector("strong");
          staleHealth.textContent = "Verifica";
          staleHealth.title = "Ultimo controllo non raggiungibile; la cronologia è conservata.";
          instance.gateTitle.textContent = "Connessione da verificare";
          instance.gateMessage.textContent = "La cronologia resta disponibile. Riprova l’invio o attendi il prossimo controllo.";
          instance.gate.hidden = false;
          instance.chatArea.hidden = false;
          refreshModeAvailability(instance);
          refreshQuickReplyAvailability(instance);
          setState(instance, instance.actionError || "Controllo temporaneamente non raggiungibile; cronologia conservata.", Boolean(instance.actionError));
        } else {
          renderMachine(instance, { machineLabel: instance.selectedMachineLabel, state: "unavailable", enabled: instance.enabled, canConfigure: instance.canConfigure, label: "Stato della macchina non disponibile." });
          instance.health.classList.add("bad");
          var unavailableHealth = instance.health.querySelector("strong");
          unavailableHealth.textContent = "Non disponibile";
          unavailableHealth.title = "Stato AI non disponibile";
          setState(instance, instance.actionError || (error && error.message ? error.message : "Stato AI non disponibile."), true);
        }
      }
      return null;
    } finally {
      if (instance.statusController === controller) instance.statusController = null;
      scheduleStatusPoll(instance);
    }
  }

  function preferredMachineId() {
    try { return window.localStorage.getItem("platform-server-ai-machine") || ""; } catch { return ""; }
  }

  function persistMachineId(machineId) {
    try { window.localStorage.setItem("platform-server-ai-machine", machineId); } catch {}
  }

  async function selectMachine(instance, machineId) {
    var machine = instance.machines.find(function (entry) { return entry.id === machineId; });
    if (!machine || (instance.selectedMachineId === machine.id && instance.statusController)) return;
    if (instance.statusController) instance.statusController.abort();
    if (instance.controller) instance.controller.abort();
    instance.contextEpoch += 1;
    abortConversationRequests(instance);
    instance.conversationId = "";
    instance.actionError = "";
    instance.queueBusy = false;
    instance.queueItems = [];
    instance.queueErrors = [];
    instance.pendingRequest = null;
    instance.nextBefore = null;
    instance.nextConversationCursor = null;
    instance.conversations = [];
    instance.pendingAttachments = [];
    instance.attachmentCapabilities = null;
    renderPendingAttachments(instance);
    if (instance.moreConversations) instance.moreConversations.hidden = true;
    renderConversationList(instance);
    clearConversation(instance);
    instance.selectedMachineId = machine.id;
    instance.selectedMachineLabel = machine.label;
    instance.machineLabel.textContent = machine.label;
    instance.machineSelect.value = machine.id;
    persistMachineId(machine.id);
    var context = conversationContext(instance);
    setState(instance, "Caricamento stato macchina…");
    await refreshStatus(instance);
    if (!isCurrentConversationContext(instance, context)) return;
    void loadAttachmentFormats(instance);
    await loadConversations(instance).catch(function (error) {
      if (isCurrentConversationContext(instance, context) && (!error || error.name !== "AbortError")) setState(instance, error.message || "Conversazioni non disponibili.", true);
    });
  }

  async function loadMachines(instance) {
    try {
      var response = await fetch("/control/v1/server-ai/machines", { credentials: "same-origin", headers: { Accept: "application/json" }, signal: instance.machineController.signal });
      var payload = await response.json().catch(function () { return {}; });
      if (!response.ok || !Array.isArray(payload.machines)) throw new Error("Elenco macchine non disponibile.");
      var ids = new Set();
      instance.machines = payload.machines.map(function (entry) {
        var id = String(entry && entry.id || "").trim().slice(0, 160);
        var label = String(entry && entry.label || id).trim().slice(0, 160);
        return { id: id, label: label };
      }).filter(function (entry) { if (!entry.id || ids.has(entry.id)) return false; ids.add(entry.id); return true; });
      if (!instance.machines.length) throw new Error("Nessuna macchina Server AI disponibile.");
      instance.machineSelect.replaceChildren();
      instance.machines.forEach(function (machine) { var option = document.createElement("option"); option.value = machine.id; option.textContent = machine.label; instance.machineSelect.appendChild(option); });
      var multiple = instance.machines.length > 1;
      instance.machinePicker.hidden = !multiple;
      instance.machineName.hidden = multiple;
      var preferred = preferredMachineId();
      var selected = instance.machines.find(function (machine) { return machine.id === preferred; }) || instance.machines[0];
      await selectMachine(instance, selected.id);
    } catch (error) {
      if (error && error.name === "AbortError") return;
      instance.machineLabel.textContent = "Macchina non disponibile";
      instance.gateTitle.textContent = "Server AI non disponibile";
      instance.gateMessage.textContent = error && error.message ? error.message : "Elenco macchine non disponibile.";
      instance.gate.hidden = false;
      instance.chatArea.hidden = true;
      instance.health.classList.add("bad");
      var unavailableHealth = instance.health.querySelector("strong");
      unavailableHealth.textContent = "Non disponibile";
      unavailableHealth.title = "Stato AI non disponibile";
    }
  }

  async function requestGenerationCancel(instance) {
    if (!instance.conversationId || !instance.selectedMachineId || !instance.busy || instance.cancelBusy) return;
    instance.cancelBusy = true;
    setState(instance, "Interruzione richiesta…");
    try {
      var response = await fetch(conversationsEndpointFor(instance.selectedMachineId, "/" + encodeURIComponent(instance.conversationId) + "/cancel"), { method: "POST", credentials: "same-origin", headers: conversationHeaders(), body: "{}" });
      if (response.status !== 202) throw new Error(await chatResponseError(response));
      scheduleConversationPoll(instance, conversationContext(instance), true);
    } catch (error) { setState(instance, error && error.message ? error.message : "Interruzione non riuscita.", true); }
    finally { instance.cancelBusy = false; }
  }

  async function requestMachineAction(instance, action) {
    if (!instance.selectedMachineId) { showMachineActionError(instance, "Seleziona una macchina prima di continuare."); return; }
    if (instance.actionBusy) return;
    if (!instance.canConfigure) { showMachineActionError(instance, "L’attivazione è riservata ai ruoli owner o admin."); return; }
    if (action === "enable" && instance.machineState !== "disabled") { showMachineActionError(instance, "La macchina deve essere nello stato disattivato prima di poterla attivare."); return; }
    if (action === "enable" && !instance.missing.hidden) { showMachineActionError(instance, "Completa i prerequisiti elencati prima di attivare Server AI."); return; }
    if (action === "disable" && !instance.enabled) { showMachineActionError(instance, "La macchina risulta già disattivata."); return; }
    instance.actionError = "";
    setState(instance, "");
    instance.actionBusy = true;
    if (action === "disable") {
      if (instance.controller) instance.controller.abort();
      instance.controller = null;
      setBusy(instance, false);
    }
    renderMachine(instance, { machineLabel: instance.selectedMachineLabel, state: action === "enable" ? "starting" : "stopping", enabled: instance.enabled, canConfigure: instance.canConfigure, label: action === "enable" ? "Avvio richiesto per questa macchina." : "Arresto richiesto per questa macchina." });
    instance.transientUntil = Date.now() + 60_000;
    var actionError = "";
    try {
      var headers = new Headers({ Accept: "application/json", "Content-Type": "application/json", "X-Requested-With": "platform-control-center" });
      var csrf = csrfToken();
      if (csrf) headers.set("X-CSRF-Token", csrf);
      var response = await fetch(endpoint(instance, "/" + action), { method: "POST", credentials: "same-origin", headers: headers, body: "{}" });
      var payload = await response.json().catch(function () { return {}; });
      if (response.status !== 202) {
        actionError = String(payload.message || payload.error || "Operazione non avviata.");
        if (payload.reauthUrl) actionError += " Effettua di nuovo l’accesso con passkey.";
        instance.actionError = actionError;
      }
      if (!actionError) setState(instance, action === "enable" ? "Avvio richiesto per questa macchina." : "Arresto richiesto per questa macchina.");
    } catch (error) {
      actionError = error && error.message ? error.message : "Operazione non avviata.";
      instance.actionError = actionError;
    } finally {
      instance.actionBusy = false;
      if (instance.root.isConnected) await refreshStatus(instance);
      // The status refresh clears its own transient state. Restore a failed
      // action afterwards so auth, CSRF, and server-side rejection details
      // remain visible instead of making the button appear to do nothing.
      if (actionError && instance.root.isConnected) setState(instance, actionError, true);
    }
  }

  async function viewProjectSource(instance, button) {
    var message = button.closest("[data-ai-message-id]"); var sourceId = button.getAttribute("data-ai-project-source"); var projectId = button.getAttribute("data-ai-project-id");
    if (!message || !instance.conversationId || !sourceId || !projectId) return;
    button.disabled = true;
    try {
      var suffix = "/" + encodeURIComponent(instance.conversationId) + "/messages/" + encodeURIComponent(message.getAttribute("data-ai-message-id")) + "/sources/" + encodeURIComponent(sourceId);
      var response = await fetch(conversationsEndpointFor(instance.selectedMachineId, suffix), { credentials: "same-origin", headers: { Accept: "application/json" } });
      var payload = await response.json().catch(function () { return {}; });
      if (!response.ok || !payload.source || typeof payload.content !== "string") throw new Error("Fonte progetto non più disponibile.");
      var previous = message.querySelector(".server-ai-project-source-content"); if (previous) previous.remove();
      var details = document.createElement("details"); details.className = "server-ai-project-source-content"; details.open = true;
      var summary = document.createElement("summary"); summary.textContent = String(payload.source.title || "Fonte progetto").slice(0, 240);
      var pre = document.createElement("pre"); pre.textContent = payload.content;
      details.appendChild(summary); details.appendChild(pre); message.appendChild(details);
    } catch (error) { setState(instance, error && error.message ? error.message : "Fonte progetto non disponibile.", true); }
    finally { button.disabled = false; }
  }

  function cleanup() {
    if (!active) return;
    if (active.controller) active.controller.abort();
    if (active.statusController) active.statusController.abort();
    if (active.machineController) active.machineController.abort();
    abortConversationRequests(active);
    if (active.pollTimer) window.clearTimeout(active.pollTimer);
    if (active.generationPollTimer) window.clearTimeout(active.generationPollTimer);
    cancelTranscriptScrollFrames(active);
    if (active.pointerEndHandler) {
      window.removeEventListener("pointerup", active.pointerEndHandler);
      window.removeEventListener("pointercancel", active.pointerEndHandler);
    }
    if (active.pointerMoveHandler) window.removeEventListener("pointermove", active.pointerMoveHandler);
    if (active.resizeHandler) window.removeEventListener("resize", active.resizeHandler);
    active = null;
  }

  function mount() {
    cleanup();
    var root = document.querySelector("[data-server-ai]");
    if (!root) return;
    active = {
      root: root, mode: "auto", models: null, machines: [], conversations: [], queueItems: [], queueBusy: false, conversationId: "", nextBefore: null, nextConversationCursor: null, contextEpoch: 0, selectedMachineId: "", selectedMachineLabel: "", machineState: "unavailable", generationAvailable: false, historyAvailable: false, lastMachineStatus: null, transientUntil: 0, busy: false, actionBusy: false, enabled: false, canConfigure: false, controller: null, statusController: null, machineController: new AbortController(), conversationListController: null, conversationDetailController: null, conversationCreateController: null, generationPollController: null, attachmentUploadController: null, attachmentUpload: null, pollTimer: null, generationPollTimer: null, activeAssistantId: null, cancelBusy: false, nextDelivery: null, attachmentCapabilities: null, pendingAttachments: [], attachmentUploading: false, autoScroll: true, programmaticScroll: false, pointerScrolling: false, userScrollUntil: 0, scrollFrame: null, scrollResetFrame: null, pointerEndHandler: null, pointerMoveHandler: null, drawerOpener: null, resizeHandler: null,
      transcript: root.querySelector("[data-ai-transcript]"), prompt: root.querySelector("[data-ai-prompt]"), send: root.querySelector("[data-ai-send]"), sendImmediate: root.querySelector("[data-ai-send-immediate]"), stop: root.querySelector("[data-ai-stop]"), jumpBottom: root.querySelector("[data-ai-jump-bottom]"), queue: root.querySelector("[data-ai-queue]"),
      state: root.querySelector("[data-ai-state]"), health: root.querySelector("[data-ai-health]"), attachments: root.querySelector("[data-ai-attachments]"), attach: root.querySelector("[data-ai-attach]"), attachmentInput: root.querySelector("[data-ai-attachment-input]"),
      machineLabel: root.querySelector("[data-ai-machine-label]"), machineName: root.querySelector("[data-ai-machine-name]"), machinePicker: root.querySelector("[data-ai-machine-picker]"), machineSelect: root.querySelector("[data-ai-machine-select]"),
      gate: root.querySelector("[data-ai-gate]"), gateTitle: root.querySelector("[data-ai-gate-title]"), gateMessage: root.querySelector("[data-ai-gate-message]"), missing: root.querySelector("[data-ai-missing]"), enable: root.querySelector("[data-ai-enable]"), disable: root.querySelector("[data-ai-disable]"), chatArea: root.querySelector("[data-ai-chat-area]"), conversationList: root.querySelector("[data-ai-conversation-list]"), conversationSearch: root.querySelector("[data-ai-conversation-search]"), conversationTitle: root.querySelector("[data-ai-conversation-title]"), drawer: root.querySelector("[data-ai-conversation-drawer]"), openConversations: root.querySelector("[data-ai-open-conversations]"), loadOlder: root.querySelector("[data-ai-load-older]"), moreConversations: root.querySelector("[data-ai-more-conversations]"), adminDiagnostics: root.querySelector("[data-ai-admin-diagnostics]"), adminDiagnosticsList: root.querySelector("[data-ai-admin-diagnostics-list]"),
    };
    var instance = active;
    initializeModeControl(instance);
    root.addEventListener("click", function (event) {
      var quickReply = event.target.closest("[data-ai-quick-reply]");
      if (quickReply) { activateQuickReply(instance, quickReply); return; }
      var sendImmediate = event.target.closest("[data-ai-send-immediate]");
      if (sendImmediate) { if (!sendImmediate.disabled) { instance.nextDelivery = "immediate"; send(instance); } return; }
      var queueDismiss = event.target.closest("[data-ai-queue-dismiss]");
      if (queueDismiss) { dismissQueueError(instance, queueDismiss.getAttribute("data-ai-queue-dismiss")); return; }
      var queueCancel = event.target.closest("[data-ai-queue-cancel]");
      if (queueCancel) { void cancelQueuedRequest(instance, queueCancel.getAttribute("data-ai-queue-cancel")); return; }
      var mode = event.target.closest("[data-ai-mode]");
      if (mode) {
        if (mode.disabled || instance.actionBusy) return;
        selectMode(instance, mode.getAttribute("data-ai-mode"), true, false);
        return;
      }
      var jumpBottom = event.target.closest("[data-ai-jump-bottom]");
      if (jumpBottom) {
        instance.userScrollUntil = 0;
        instance.pointerScrolling = false;
        scrollTranscript(instance, true);
        instance.transcript.focus({ preventScroll: true });
        return;
      }
      var copy = event.target.closest("[data-ai-copy-code]");
      if (copy) {
        var code = copy.closest("pre").querySelector("code");
        navigator.clipboard.writeText(code ? code.textContent : "").then(function () { copy.textContent = "Copiato"; }, function () { setState(instance, "Copia non riuscita.", true); });
        return;
      }
      var projectSource = event.target.closest("[data-ai-project-source]");
      if (projectSource) { viewProjectSource(instance, projectSource); return; }
      var scanAttachment = event.target.closest("[data-ai-scan-attachment]");
      if (scanAttachment) { void requestAttachmentScan(instance, scanAttachment, "start"); return; }
      var scanAction = event.target.closest("[data-ai-scan-action]");
      if (scanAction) { void requestAttachmentScan(instance, scanAction, scanAction.getAttribute("data-ai-scan-action")); return; }
      var removeAttachment = event.target.closest("[data-ai-remove-attachment]");
      if (removeAttachment) { removePendingAttachment(instance, removeAttachment.getAttribute("data-ai-remove-attachment")); return; }
      if (event.target.closest("[data-ai-cancel-upload]")) { cancelAttachmentUpload(instance); return; }
      if (event.target.closest("[data-ai-attach]") && instance.attachmentInput && !instance.attach.disabled) { instance.attachmentInput.click(); return; }
      if (event.target.closest("[data-ai-stop]")) requestGenerationCancel(instance);
      if (event.target.closest("[data-ai-enable]")) requestMachineAction(instance, "enable");
      if (event.target.closest("[data-ai-disable]")) requestMachineAction(instance, "disable");
      if (event.target.closest("[data-ai-new-conversation]")) {
        if (instance.busy) return;
        createConversation(instance).then(function () { clearConversation(instance); setDrawerOpen(instance, false, true); }).catch(function (error) { setState(instance, error.message || "Impossibile creare la conversazione.", true); });
        return;
      }
      if (event.target.closest("[data-ai-more-conversations]")) {
        loadConversations(instance, true).catch(function (error) { if (error.name !== "AbortError") setState(instance, error.message, true); });
        return;
      }
      var openConversationButton = event.target.closest("[data-ai-open-conversation]");
      if (openConversationButton) openConversation(instance, openConversationButton.getAttribute("data-ai-open-conversation")).catch(function (error) { setState(instance, error.message, true); });
      var conversationAction = event.target.closest("[data-ai-conversation-action]");
      if (conversationAction) editConversation(instance, conversationAction.getAttribute("data-ai-conversation-action"), conversationAction.getAttribute("data-ai-conversation-id"), conversationAction.closest("li"));
      if (event.target.closest("[data-ai-load-older]")) {
        if (instance.nextBefore) openConversation(instance, instance.conversationId, instance.nextBefore).catch(function (error) { setState(instance, error.message, true); });
        return;
      }
      var suggestion = event.target.closest("[data-ai-suggestion]");
      if (suggestion) {
        instance.prompt.value = String(suggestion.getAttribute("data-ai-suggestion") || "");
        resizePrompt(instance);
        instance.prompt.focus();
        return;
      }
      if (event.target.closest("[data-ai-open-conversations]")) {
        instance.drawerOpener = event.target.closest("[data-ai-open-conversations]");
        setDrawerOpen(instance, true);
      }
      if (event.target.closest("[data-ai-close-conversations]")) setDrawerOpen(instance, false, true);
    });
    root.addEventListener("keydown", function (event) {
      var modeButton = event.target.closest("[data-ai-mode]");
      var key = event.key;
      if (modeButton && ["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End"].includes(key)) {
        if (modeButton.disabled || instance.actionBusy) return;
        var index = MODE_OPTIONS.indexOf(instance.mode);
        if (key === "Home") index = 0;
        else if (key === "End") index = MODE_OPTIONS.length - 1;
        else index = (index + (key === "ArrowRight" || key === "ArrowDown" ? 1 : -1) + MODE_OPTIONS.length) % MODE_OPTIONS.length;
        event.preventDefault();
        selectMode(instance, MODE_OPTIONS[index], true, true);
        return;
      }
      if (event.key !== "Escape") return;
      var openDetails = root.querySelector("details[open]");
      if (openDetails) { closeOpenDetails(instance); event.preventDefault(); return; }
      if (root.classList.contains("server-ai-drawer-open")) { setDrawerOpen(instance, false, true); event.preventDefault(); }
    });
    root.querySelector("[data-ai-form]").addEventListener("submit", function (event) { event.preventDefault(); send(instance); });
    instance.machineSelect.addEventListener("change", function () { selectMachine(instance, instance.machineSelect.value); });
    if (instance.conversationSearch) instance.conversationSearch.addEventListener("input", function () { renderConversationList(instance); });
    instance.transcript.addEventListener("wheel", function (event) {
      if (event.deltaY < 0 || !transcriptAtEnd(instance)) pauseTranscriptFollow(instance);
      else noteTranscriptScrollIntent(instance);
    }, { passive: true });
    instance.transcript.addEventListener("pointerdown", function () {
      instance.pointerScrolling = true;
      cancelTranscriptScrollFrames(instance);
    });
    instance.pointerMoveHandler = function () { if (instance.pointerScrolling) pauseTranscriptFollow(instance); };
    instance.pointerEndHandler = function () {
      if (!instance.pointerScrolling) return;
      instance.pointerScrolling = false;
      noteTranscriptScrollIntent(instance);
      handleTranscriptScroll(instance);
    };
    window.addEventListener("pointermove", instance.pointerMoveHandler);
    window.addEventListener("pointerup", instance.pointerEndHandler);
    window.addEventListener("pointercancel", instance.pointerEndHandler);
    instance.transcript.addEventListener("keydown", function (event) {
      if (["ArrowUp", "PageUp", "Home"].includes(event.key) || (event.key === " " && event.shiftKey)) pauseTranscriptFollow(instance);
      else if (["ArrowDown", "PageDown", "End", " "].includes(event.key)) noteTranscriptScrollIntent(instance);
    });
    instance.transcript.addEventListener("scroll", function () { handleTranscriptScroll(instance); }, { passive: true });
    instance.prompt.addEventListener("input", function () { resizePrompt(instance); refreshQuickReplyAvailability(instance); });
    if (instance.attachmentInput) instance.attachmentInput.addEventListener("change", function () { void uploadAttachments(instance, Array.from(instance.attachmentInput.files || []).slice(0, 5)); });
    instance.root.addEventListener("dragover", function (event) { if (instance.attachmentCapabilities && !instance.busy) event.preventDefault(); });
    instance.root.addEventListener("drop", function (event) { var files = event.dataTransfer && event.dataTransfer.files; if (files && files.length && instance.attachmentCapabilities && !instance.busy) { event.preventDefault(); void uploadAttachments(instance, Array.from(files).slice(0, 5)); } });
    instance.root.addEventListener("paste", function (event) { var items = event.clipboardData && event.clipboardData.items; if (!items || !instance.attachmentCapabilities || instance.busy) return; var files = []; for (var index = 0; index < items.length && files.length < 5; index += 1) if (items[index].kind === "file") { var file = items[index].getAsFile(); if (file) files.push(file); } if (files.length) { event.preventDefault(); void uploadAttachments(instance, files); } });
    instance.prompt.addEventListener("keydown", function (event) {
      if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); send(instance); }
    });
    instance.resizeHandler = function () { setDrawerOpen(instance, root.classList.contains("server-ai-drawer-open")); };
    window.addEventListener("resize", instance.resizeHandler);
    setDrawerOpen(instance, false);
    resizePrompt(instance);
    loadMachines(instance);
  }

  function start() {
    mount();
    document.addEventListener("cc:navigation-complete", mount);
    observer = new MutationObserver(function () {
      if (active && !active.root.isConnected) cleanup();
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start, { once: true });
  else start();
})();
