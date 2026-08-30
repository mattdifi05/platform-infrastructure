(function () {
  "use strict";

  var appSelector = ".cc-app-shell, .login-shell";
  var cacheLimit = 64;
  var cacheTtlMs = 300000;
  var prefetchTimeoutMs = 15000;
  var preloadWorkerCount = 4;
  var sidebarStateKey = "platform-control-center-sidebar";
  var htmlCache = new Map();
  var activeRequest = null;
  var initialized = false;
  var bootId = "cc-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2);
  var fileManagerRefreshInFlight = false;
  var prefetchInFlight = new Set();
  var formSubmissions = new WeakSet();
  var navigationSequence = 0;
  var opsNavLastPillRect = null;
  var opsNavPillFrame = 0;
  var opsNavLayoutFrame = 0;
  var pendingSidebarScrollTop = null;
  var pendingSidebarScrollAt = 0;
  var selectedFileEntry = null;
  var passkeyActionInFlight = false;

  function sameOriginUrl(value) {
    try {
      var url = new URL(value, window.location.href);
      return url.origin === window.location.origin ? url : null;
    } catch {
      return null;
    }
  }

  function canRenderPath(url) {
    return url.pathname === "/" || url.pathname === "/index.html" || url.pathname === "/login" || url.pathname === "/logout";
  }

  function isSensitivePortalUrl(url) {
    return Boolean(url && (
      url.pathname === "/auth/login"
      || ((url.pathname === "/" || url.pathname === "/index.html") && url.searchParams.get("section") === "secrets")
    ));
  }

  function redirectForReauthentication(response, payload) {
    var candidate = payload && payload.error === "admin_reauthentication_required"
      ? payload.reauthUrl
      : response && response.redirected
        ? response.url
        : "";
    var target = sameOriginUrl(candidate || "");
    if (!target || target.pathname !== "/auth/login") return false;
    clearCache();
    window.location.assign(target.href);
    return true;
  }

  function reauthenticationRedirectError() {
    var error = new Error("Reauthentication redirect started.");
    error.name = "ReauthenticationRedirect";
    return error;
  }

  function isPlainClick(event) {
    return event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey;
  }

  function setBusy(value) {
    document.body.dataset.ccNavigation = value ? "loading" : "idle";
    var root = document.querySelector(appSelector);
    if (root) root.setAttribute("aria-busy", value ? "true" : "false");
  }

  function showError(message) {
    var existing = document.querySelector(".cc-async-error");
    if (existing) existing.remove();
    var box = document.createElement("div");
    box.className = "cc-async-error";
    box.setAttribute("role", "alert");
    box.textContent = message || "Action failed.";
    document.body.appendChild(box);
    window.setTimeout(function () {
      if (box.isConnected) box.remove();
    }, 5200);
  }

  function storeCache(url, html, etag) {
    htmlCache.delete(url);
    htmlCache.set(url, { etag: etag || "", html: String(html || ""), storedAt: Date.now() });
    while (htmlCache.size > cacheLimit) {
      htmlCache.delete(htmlCache.keys().next().value);
    }
  }

  function clearCache() {
    htmlCache.clear();
  }

  function cachedPage(url, allowStale) {
    var entry = htmlCache.get(url);
    if (!entry) return null;
    if (!allowStale && Date.now() - entry.storedAt > cacheTtlMs) return null;
    htmlCache.delete(url);
    htmlCache.set(url, entry);
    return entry;
  }

  function payloadFromForm(form, submitter) {
    var data = new FormData(form);
    if (submitter && submitter.name && !data.has(submitter.name)) {
      data.append(submitter.name, submitter.value || "");
    }
    var csrf = csrfToken();
    if (csrf) data.set("_csrf", csrf);
    return new URLSearchParams(data);
  }

  function csrfToken() {
    var prefix = "__Host-platform_cc_csrf=";
    var parts = String(document.cookie || "").split(";");
    for (var index = 0; index < parts.length; index += 1) {
      var part = parts[index].trim();
      if (part.indexOf(prefix) === 0) return decodeURIComponent(part.slice(prefix.length));
    }
    return "";
  }

  function addMutationHeaders(headers, method) {
    if (String(method || "GET").toUpperCase() === "GET") return;
    var csrf = csrfToken();
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }

  function base64UrlToBuffer(value) {
    var normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
    while (normalized.length % 4) normalized += "=";
    var raw = atob(normalized);
    return Uint8Array.from(raw, function (character) { return character.charCodeAt(0); }).buffer;
  }

  function bufferToBase64Url(value) {
    var bytes = new Uint8Array(value);
    var raw = "";
    for (var index = 0; index < bytes.length; index += 1) raw += String.fromCharCode(bytes[index]);
    return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function serializePasskeyAssertion(credential) {
    if (typeof credential.toJSON === "function") return credential.toJSON();
    var response = credential.response;
    return {
      id: credential.id,
      rawId: bufferToBase64Url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment || undefined,
      clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
      response: {
        clientDataJSON: bufferToBase64Url(response.clientDataJSON),
        authenticatorData: bufferToBase64Url(response.authenticatorData),
        signature: bufferToBase64Url(response.signature),
        userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : undefined,
      },
    };
  }

  async function passkeyJsonRequest(url, body) {
    var response = await fetch(url, {
      body: JSON.stringify(body || {}),
      credentials: "same-origin",
      headers: { "content-type": "application/json", accept: "application/json" },
      method: "POST",
    });
    var payload = await response.json();
    if (!response.ok) throw new Error(payload.message || payload.error || "Autenticazione passkey non disponibile.");
    return payload;
  }

  async function authenticateWithSystemPasskey() {
    if (!window.PublicKeyCredential || !navigator.credentials) throw new Error("Questo browser non supporta le passkey.");
    var optionsPayload = await passkeyJsonRequest("/auth/passkey/login/options", {});
    var options = optionsPayload.options;
    var publicKey = Object.assign({}, options, {
      challenge: base64UrlToBuffer(options.challenge),
      allowCredentials: (options.allowCredentials || []).map(function (item) {
        return Object.assign({}, item, { id: base64UrlToBuffer(item.id) });
      }),
    });
    var credential = await navigator.credentials.get({ publicKey: publicKey });
    if (!credential) throw new Error("Autenticazione annullata.");
    var result = await passkeyJsonRequest("/auth/passkey/login/verify", {
      challenge: options.challenge,
      credential: serializePasskeyAssertion(credential),
    });
    if (result.ok !== true) throw new Error(result.message || "Autenticazione passkey non riuscita.");
  }

  async function runPasskeyNavigation(link) {
    if (passkeyActionInFlight) return;
    var target = sameOriginUrl(link.getAttribute("data-passkey-return-to") || "");
    if (!target || !canRenderPath(target)) return;
    passkeyActionInFlight = true;
    link.setAttribute("aria-busy", "true");
    try {
      await authenticateWithSystemPasskey();
      clearCache();
      await navigate(target, { history: "push" });
    } catch (error) {
      showError(error && error.message ? error.message : "Autenticazione passkey non riuscita.");
    } finally {
      passkeyActionInFlight = false;
      if (link.isConnected) link.removeAttribute("aria-busy");
    }
  }

  async function submitPasskeyForm(form, submitter) {
    if (passkeyActionInFlight || formSubmissions.has(form)) return true;
    var action = sameOriginUrl(form.getAttribute("action") || "");
    var allowedActions = new Set(["/actions/backup-delete-command", "/actions/database-delete-command", "/actions/vault-command", "/actions/redis-restore-command", "/actions/redis-backup-delete-command"]);
    if (!action || !allowedActions.has(action.pathname)) return false;
    passkeyActionInFlight = true;
    formSubmissions.add(form);
    var pageScrollTop = currentPageScrollTop();
    if (submitter) {
      submitter.disabled = true;
      submitter.setAttribute("aria-busy", "true");
    }
    try {
      await authenticateWithSystemPasskey();
      var headers = new Headers();
      headers.set("Accept", "application/json");
      headers.set("Content-Type", "application/x-www-form-urlencoded");
      headers.set("X-Requested-With", "platform-control-center");
      addMutationHeaders(headers, "POST");
      var response = await fetch(action.href, {
        body: payloadFromForm(form, submitter),
        credentials: "same-origin",
        headers: headers,
        method: "POST",
      });
      var payload = await response.json();
      if (!response.ok) throw new Error(payload.message || payload.error || "Azione non riuscita.");
      clearCache();
      var successUrl = sameOriginUrl(form.getAttribute("data-passkey-success-url") || window.location.href);
      if (successUrl && canRenderPath(successUrl)) await navigate(successUrl, { history: "replace", pageScrollTop: pageScrollTop });
      return true;
    } catch (error) {
      showError(error && error.message ? error.message : "Azione non riuscita.");
      return false;
    } finally {
      passkeyActionInFlight = false;
      formSubmissions.delete(form);
      if (submitter && submitter.isConnected) {
        submitter.disabled = false;
        submitter.removeAttribute("aria-busy");
      }
    }
  }

  async function requestHtml(url, options) {
    var method = (options && options.method ? options.method : "GET").toUpperCase();
    var useCache = method === "GET";
    var cacheKey = url.href;
    var freshCache = useCache ? cachedPage(cacheKey, false) : null;
    var staleCache = useCache ? cachedPage(cacheKey, true) : null;
    if (freshCache) {
      return { html: freshCache.html, url: cacheKey, fromCache: true };
    }

    if (activeRequest) activeRequest.abort();
    var controller = new AbortController();
    activeRequest = controller;

    var headers = new Headers(options && options.headers ? options.headers : {});
    headers.set("Accept", "text/html,*/*;q=0.8");
    headers.set("X-Requested-With", "platform-control-center");
    if (staleCache && staleCache.etag) headers.set("If-None-Match", staleCache.etag);
    addMutationHeaders(headers, method);

    try {
      var response = await fetch(url.href, {
        body: options ? options.body : undefined,
        credentials: "same-origin",
        headers: headers,
        method: method,
        redirect: "follow",
        signal: controller.signal,
      });

      if (redirectForReauthentication(response)) throw reauthenticationRedirectError();

      if (response.status === 304 && staleCache) {
        staleCache.storedAt = Date.now();
        return { html: staleCache.html, url: cacheKey, fromCache: true, revalidated: true };
      }

      var contentType = response.headers.get("content-type") || "";
      if (contentType.indexOf("application/json") !== -1) {
        var payload = await response.json();
        if (redirectForReauthentication(response, payload)) throw reauthenticationRedirectError();
        if (!response.ok) throw new Error(payload.message || payload.error || "Request failed.");
        throw new Error(payload.message || "The server returned JSON instead of a page update.");
      }

      var html = await response.text();
      if (!response.ok) {
        throw new Error(extractError(html) || "Request failed.");
      }

      var finalUrl = response.url || url.href;
      if (useCache) {
        var etag = response.headers.get("etag") || "";
        storeCache(cacheKey, html, etag);
        storeCache(finalUrl, html, etag);
      }
      return { html: html, url: finalUrl, fromCache: false };
    } finally {
      if (activeRequest === controller) activeRequest = null;
    }
  }

  async function prefetchHtml(url) {
    if (!url || !canRenderPath(url) || isSensitivePortalUrl(url) || prefetchInFlight.has(url.href)) return null;
    var cached = cachedPage(url.href, false);
    if (cached) return { html: cached.html, url: url.href, fromCache: true };
    prefetchInFlight.add(url.href);
    try {
      var controller = new AbortController();
      var timeout = window.setTimeout(function () {
        controller.abort();
      }, prefetchTimeoutMs);
      var headers = new Headers();
      headers.set("Accept", "text/html,*/*;q=0.8");
      headers.set("X-Requested-With", "platform-control-center-prefetch");
      var response;
      try {
        response = await fetch(url.href, {
          cache: "no-cache",
          credentials: "same-origin",
          headers: headers,
          method: "GET",
          redirect: "follow",
          signal: controller.signal,
        });
      } finally {
        window.clearTimeout(timeout);
      }
      if (!response.ok) return null;
      var responseUrl = sameOriginUrl(response.url || "");
      if (response.redirected && responseUrl && responseUrl.pathname === "/auth/login") return null;
      var contentType = response.headers.get("content-type") || "";
      if (contentType.indexOf("application/json") !== -1) return null;
      var html = await response.text();
      var finalUrl = response.url || url.href;
      var etag = response.headers.get("etag") || "";
      storeCache(url.href, html, etag);
      storeCache(finalUrl, html, etag);
      return { html: html, url: finalUrl, fromCache: false };
    } catch {
      // Preload is opportunistic; normal navigation still fetches on demand.
      return null;
    } finally {
      prefetchInFlight.delete(url.href);
    }
  }


  function extractError(html) {
    try {
      var parsed = new DOMParser().parseFromString(html, "text/html");
      return parsed.querySelector("h1, .login-copy, .cc-async-error")?.textContent?.trim() || "";
    } catch {
      return "";
    }
  }

  function syncBodyAttributes(nextBody) {
    Array.from(document.body.attributes).forEach(function (attribute) {
      if (attribute.name.indexOf("data-cc-") === 0 && attribute.name !== "data-cc-navigation" && attribute.name !== "data-cc-enhanced" && attribute.name !== "data-cc-boot-id" && attribute.name !== "data-cc-preloading" && attribute.name !== "data-cc-preload-complete") {
        document.body.removeAttribute(attribute.name);
      }
    });
    Array.from(nextBody.attributes).forEach(function (attribute) {
      if (attribute.name.indexOf("data-cc-") === 0 && attribute.name !== "data-cc-preloading" && attribute.name !== "data-cc-preload-complete") {
        document.body.setAttribute(attribute.name, attribute.value);
      }
    });
    document.body.dataset.ccEnhanced = "true";
    document.body.dataset.ccBootId = bootId;
  }

  function syncElementAttributes(current, next) {
    Array.from(current.attributes).forEach(function (attribute) {
      current.removeAttribute(attribute.name);
    });
    Array.from(next.attributes).forEach(function (attribute) {
      current.setAttribute(attribute.name, attribute.value);
    });
  }

  function updateStableElement(current, next, options) {
    var imported = document.importNode(next, true);
    if (options && options.preserveNavPill) {
      var currentPill = current.querySelector(".ops-nav-pill");
      var nextPill = imported.querySelector(".ops-nav-pill");
      if (currentPill && nextPill) nextPill.replaceWith(currentPill);
    }
    syncElementAttributes(current, imported);
    current.replaceChildren.apply(current, Array.from(imported.childNodes));
  }

  function applyHtml(html, finalUrl, mode, options) {
    var previousSidebarScrollTop = options && typeof options.sidebarScrollTop === "number" ? options.sidebarScrollTop : currentSidebarScrollTop();
    var previousPageScrollTop = options && typeof options.pageScrollTop === "number" ? options.pageScrollTop : null;
    var previousOpsNavExpandedState = captureOpsNavExpandedState();
    var previousPillRect = captureOpsNavPillRect() || opsNavLastPillRect;
    var parsed = new DOMParser().parseFromString(html, "text/html");
    var nextBody = parsed.body;
    var currentShell = document.querySelector(".cc-app-shell");
    var nextShell = parsed.querySelector(".cc-app-shell");
    if (!nextBody || !parsed.querySelector(appSelector)) {
      window.location.assign(finalUrl);
      return;
    }

    document.title = parsed.title || document.title;
    syncBodyAttributes(nextBody);
    if (currentShell && nextShell) {
      var currentSidebar = currentShell.querySelector(".ops-sidebar");
      var currentPage = currentShell.querySelector(".ops-page");
      var nextSidebar = nextShell.querySelector(".ops-sidebar");
      var nextPage = nextShell.querySelector(".ops-page");
      if (!currentSidebar || !currentPage || !nextSidebar || !nextPage) {
        window.location.assign(finalUrl);
        return;
      }
      updateStableElement(currentSidebar, nextSidebar, { preserveNavPill: true });
      updateStableElement(currentPage, nextPage);
      currentShell.className = nextShell.className;
    } else {
      document.body.replaceChildren.apply(
        document.body,
        Array.from(nextBody.childNodes).map(function (node) {
          return document.importNode(node, true);
        })
      );
    }

    var target = new URL(finalUrl, window.location.href);
    var historyUrl = target.pathname + target.search + target.hash;
    if (mode === "replace") {
      window.history.replaceState({ ccDynamic: true }, "", historyUrl);
    } else if (mode === "push" && historyUrl !== window.location.pathname + window.location.search + window.location.hash) {
      window.history.pushState({ ccDynamic: true }, "", historyUrl);
    }

    setBusy(false);
    restoreSidebarState({ instantOpsNav: true, opsNavExpandedState: previousOpsNavExpandedState });
    restoreSidebarScrollTop(previousSidebarScrollTop);
    startStatusTabs();
    startFileManagers();
    fitSingleLineText();
    scrollAfterRender(target);
    restorePageScrollTop(previousPageScrollTop);
    restoreSidebarScrollTop(previousSidebarScrollTop);
    positionOpsNavPill({ fromViewportRect: previousPillRect });
    restoreNavigationFocus();
    opsNavLastPillRect = null;
    document.dispatchEvent(new CustomEvent("cc:navigation-complete", { detail: { url: target.href } }));
    scheduleControlCenterPreload();
  }

  function currentPageScrollTop() {
    return Math.max(0, Number(window.scrollY || document.documentElement.scrollTop || 0));
  }

  function restorePageScrollTop(value) {
    if (typeof value !== "number" || !Number.isFinite(value)) return;
    var apply = function () {
      var maxScrollTop = Math.max(0, document.documentElement.scrollHeight - window.innerHeight);
      window.scrollTo({ left: window.scrollX, top: Math.min(Math.max(0, value), maxScrollTop), behavior: "instant" });
    };
    apply();
    window.requestAnimationFrame(apply);
  }

  function restoreNavigationFocus() {
    var active = document.querySelector(".ops-nav-subitem[aria-current='page']");
    if (!active || typeof active.focus !== "function") return;
    active.focus({ preventScroll: true });
  }

  function setText(node, value) {
    if (!node) return;
    var next = value == null ? "" : String(value);
    if (node.textContent !== next) node.textContent = next;
  }

  function activateStatusTab(tabId, updateHash) {
    var root = document.querySelector("[data-status-tabs]");
    if (!root) return;
    var requested = String(tabId || "all").replace(/[^a-z0-9-]/gi, "");
    var targetPanel = root.querySelector('[data-status-panel="' + requested + '"]');
    if (!targetPanel) {
      requested = "all";
      targetPanel = root.querySelector('[data-status-panel="all"]');
    }
    root.querySelectorAll("[data-status-tab]").forEach(function (tab) {
      var selected = tab.getAttribute("data-status-tab") === requested;
      tab.classList.toggle("active", selected);
      tab.setAttribute("aria-selected", selected ? "true" : "false");
    });
    root.querySelectorAll("[data-status-panel]").forEach(function (panel) {
      var selected = panel.getAttribute("data-status-panel") === requested;
      panel.classList.toggle("active", selected);
      panel.hidden = !selected;
    });
    if (updateHash) {
      var nextUrl = new URL(window.location.href);
      nextUrl.hash = "status-tab-" + requested;
      window.history.replaceState({ ccDynamic: true }, "", nextUrl.pathname + nextUrl.search + nextUrl.hash);
    }
  }

  function startStatusTabs() {
    if (!document.querySelector("[data-status-tabs]")) return;
    var hash = String(window.location.hash || "").replace(/^#status-tab-/, "");
    activateStatusTab(hash || "all", false);
  }

  function fitSingleLineText() {
    document.querySelectorAll("[data-fit-single-line]").forEach(function (node) {
      node.style.removeProperty("--fit-font-size");
      node.style.fontSize = "";
      var maxSize = Number(node.getAttribute("data-fit-max-size") || 15);
      var minSize = Number(node.getAttribute("data-fit-min-size") || 8);
      if (!Number.isFinite(maxSize)) maxSize = 15;
      if (!Number.isFinite(minSize)) minSize = 8;
      var available = node.clientWidth;
      var required = node.scrollWidth;
      if (!available || !required || required <= available) return;
      var nextSize = Math.max(minSize, Math.floor((maxSize * available / required) * 100) / 100);
      node.style.setProperty("--fit-font-size", nextSize + "px");
      while (node.scrollWidth > node.clientWidth && nextSize > minSize) {
        nextSize = Math.max(minSize, Math.floor((nextSize - 0.25) * 100) / 100);
        node.style.setProperty("--fit-font-size", nextSize + "px");
      }
    });
  }

  function statusRunnerRoot() {
    return document.querySelector("[data-status-runner]");
  }

  function setStatusProgress(percent, label) {
    var bar = document.querySelector("[data-status-progress-bar]");
    var text = document.querySelector("[data-status-progress-label]");
    var value = Math.max(0, Math.min(100, Number(percent) || 0));
    if (bar) bar.style.width = value + "%";
    if (label) setText(text, label);
  }

  function setStatusRunState(value) {
    setText(document.querySelector("[data-status-run-state]"), value);
  }

  function setStatusStep(step, state, detail) {
    if (!step) return;
    ["idle", "loading", "passed", "failed"].forEach(function (name) {
      step.classList.remove(name);
    });
    step.classList.add(state);
    var mark = step.querySelector("[data-status-run-step-mark]");
    var detailNode = step.querySelector("[data-status-run-step-detail]");
    var markers = { idle: "-", loading: "...", passed: "V", failed: "X" };
    setText(mark, markers[state] || "-");
    if (detail) setText(detailNode, detail);
  }

  function setStatusSection(card, state, progress, summary) {
    if (!card) return;
    ["passed", "blocked", "loading"].forEach(function (name) {
      card.classList.remove(name);
    });
    card.classList.add(state);
    card.setAttribute("data-status-category-state", state);
    var mark = card.querySelector("[data-status-section-mark]");
    var bar = card.querySelector("[data-status-section-progress]");
    var summaryNode = card.querySelector("[data-status-section-summary]");
    var markers = { passed: "V", blocked: "X", loading: "..." };
    setText(mark, markers[state] || "-");
    if (bar) bar.style.width = Math.max(0, Math.min(100, Number(progress) || 0)) + "%";
    if (summary) setText(summaryNode, summary);
  }

  function sectionCardById(id) {
    if (!id) return null;
    return document.querySelector('[data-status-category-card="' + String(id).replace(/"/g, "") + '"]');
  }

  function statusRunId() {
    return "status-ui-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 10);
  }

  function statusStepById(checkId) {
    return Array.from(document.querySelectorAll("[data-status-run-step]")).find(function (step) {
      return step.getAttribute("data-status-run-step") === checkId;
    }) || null;
  }

  function applyStatusEvent(event, state) {
    if (!event || !state) return;
    if (event.type === "run-started") {
      state.total = Math.max(1, Number(event.total || 0));
      setStatusRunState("In corso");
      setStatusProgress(0, "Avvio controlli...");
      document.querySelectorAll("[data-status-run-step]").forEach(function (step) {
        setStatusStep(step, "idle", "In coda.");
      });
      return;
    }
    var step = statusStepById(event.checkId || "");
    if (event.type === "check-started") {
      if (step) setStatusStep(step, "loading", "Esecuzione in corso...");
      setStatusSection(sectionCardById(event.category), "loading", 50, "Controllo in corso...");
      var label = step?.querySelector("strong")?.textContent?.trim() || event.checkId || "Controllo";
      setStatusProgress(Math.round((state.completed / state.total) * 100), "Eseguo: " + label);
      return;
    }
    if (event.type === "check-completed") {
      state.completed += 1;
      var passed = event.status === "passed" || event.status === "success";
      if (step) setStatusStep(step, passed ? "passed" : "failed", friendlyStatusLabel(event.status));
      setStatusSection(sectionCardById(event.category), passed ? "passed" : "blocked", passed ? 100 : 0, passed ? "Controllo superato." : "Controllo aperto.");
      setStatusProgress(Math.round((state.completed / state.total) * 100), state.completed + " di " + state.total + " completati");
      return;
    }
    if (event.type === "run-completed") {
      setStatusProgress(100, "Controlli completati.");
    }
  }

  function watchStatusRun(runId) {
    var source = new EventSource("/control/v1/status/events/stream?runId=" + encodeURIComponent(runId), { withCredentials: true });
    var settled = false;
    var state = { completed: 0, total: 1 };
    var resolvePromise;
    var rejectPromise;
    var completed = new Promise(function (resolve, reject) {
      resolvePromise = resolve;
      rejectPromise = reject;
    });
    var timeout = window.setTimeout(function () {
      if (settled) return;
      settled = true;
      source.close();
      rejectPromise(new Error("Timeout stream Stato."));
    }, 6 * 60 * 1000);
    source.addEventListener("status", function (message) {
      var event;
      try {
        event = JSON.parse(message.data);
      } catch {
        return;
      }
      applyStatusEvent(event, state);
      if (event.type === "run-completed" && !settled) {
        settled = true;
        window.clearTimeout(timeout);
        source.close();
        resolvePromise(event);
      }
    });
    source.onerror = function () {
      if (settled || source.readyState !== EventSource.CLOSED) return;
      settled = true;
      window.clearTimeout(timeout);
      rejectPromise(new Error("Stream Stato interrotto."));
    };
    return {
      completed: completed,
      close: function () {
        if (settled) return;
        settled = true;
        window.clearTimeout(timeout);
        source.close();
      },
    };
  }

  function applyStatusRunResult(payload) {
    var checks = Array.isArray(payload && payload.checks) ? payload.checks : [];
    var byId = new Map();
    checks.forEach(function (check) {
      byId.set(check.id, check);
    });
    document.querySelectorAll("[data-status-run-step]").forEach(function (step) {
      var check = byId.get(step.getAttribute("data-status-run-step"));
      if (!check) {
        setStatusStep(step, "idle", "Non eseguito in questo run.");
        return;
      }
      var passed = check.status === "passed" || check.status === "success";
      setStatusStep(step, passed ? "passed" : "failed", check.detail || check.status);
      var category = step.getAttribute("data-status-run-step-category") || "";
      setStatusSection(sectionCardById(category), passed ? "passed" : "blocked", passed ? 100 : 0, passed ? "Test appena superato." : "Test non superato.");
    });
    setStatusRunState(payload && payload.status ? friendlyStatusLabel(payload.status) : "Completato");
    setStatusProgress(100, "Test completati.");
  }

  function friendlyStatusLabel(status) {
    switch (String(status || "")) {
      case "passed":
      case "success":
        return "Superato";
      case "warning":
        return "Con avvisi";
      case "failed":
        return "Non superato";
      default:
        return status || "Completato";
    }
  }

  async function submitStatusRun(form, submitter, action) {
    var button = submitter || form.querySelector("[data-status-run-button]");
    var consolePanel = document.querySelector("[data-status-run-console]");
    var selectedCategory = form.querySelector('[name="category"]');
    var selectedCategoryId = selectedCategory ? selectedCategory.value || "" : "";
    var runId = statusRunId();
    var stream = null;
    clearCache();
    setBusy(true);
    if (consolePanel && consolePanel.tagName === "DETAILS") {
      consolePanel.setAttribute("open", "");
    }
    if (button) {
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
    }
    try {
      var headers = new Headers();
      headers.set("Accept", "application/json");
      headers.set("X-Requested-With", "platform-control-center");
      addMutationHeaders(headers, "POST");
      var body = payloadFromForm(form, submitter);
      body.set("runId", runId);
      stream = watchStatusRun(runId);
      var fetchRun = fetch(action.href, {
        body: body,
        credentials: "same-origin",
        headers: headers,
        method: "POST",
        redirect: "follow",
      }).then(async function (response) {
        var payload = await response.json();
        if (!response.ok) throw new Error(payload.message || payload.error || "Status run failed.");
        return payload;
      });
      var result = await fetchRun;
      await stream.completed;
      applyStatusRunResult(result);
      var page = sameOriginUrl(window.location.href);
      page.searchParams.set("section", "status");
      if (selectedCategoryId) page.searchParams.set("statusCategory", selectedCategoryId);
      page.hash = "status-run";
      var html = await requestHtml(page, { method: "GET" });
      applyHtml(html.html, html.url || page.href, "replace");
      return true;
    } catch (error) {
      if (stream) stream.close();
      setBusy(false);
      setStatusRunState("Errore");
      setStatusProgress(100, "Run non completato.");
      showError(error && error.message ? error.message : "Status run failed.");
      return false;
    } finally {
      if (button) {
        button.disabled = false;
        button.removeAttribute("aria-busy");
      }
    }
  }

  function scrollAfterRender(url) {
    if (url.hash) {
      var target = document.getElementById(decodeURIComponent(url.hash.slice(1)));
      if (target) {
        target.scrollIntoView({ block: "start" });
        return;
      }
    }
    window.scrollTo({ left: 0, top: 0, behavior: "auto" });
  }

  function currentSidebarScrollTop() {
    var sidebar = document.querySelector(".ops-sidebar");
    return sidebar ? sidebar.scrollTop : 0;
  }

  function restoreSidebarScrollTop(value) {
    var sidebar = document.querySelector(".ops-sidebar");
    if (!sidebar || typeof value !== "number") return;
    sidebar.scrollTop = Math.max(0, value);
  }

  function rememberSidebarScrollBeforePointer(event) {
    if (!event || !event.target || !event.target.closest) return;
    if (!event.target.closest(".ops-nav-subitem[href], .ops-nav-direct[href]")) return;
    pendingSidebarScrollTop = currentSidebarScrollTop();
    pendingSidebarScrollAt = Date.now();
  }

  function consumePendingSidebarScrollTop() {
    var value = pendingSidebarScrollTop;
    var age = Date.now() - pendingSidebarScrollAt;
    pendingSidebarScrollTop = null;
    pendingSidebarScrollAt = 0;
    return typeof value === "number" && age < 1500 ? value : null;
  }

  function captureOpsNavExpandedState() {
    var expandedState = {};
    document.querySelectorAll("[data-ops-nav-collapsible]").forEach(function (group) {
      var key = group.getAttribute("data-ops-nav-group") || "";
      if (!key) return;
      expandedState[key] = group.dataset.opsNavExpanded === "true";
    });
    return expandedState;
  }

  function readSidebarState() {
    try {
      return JSON.parse(window.localStorage.getItem(sidebarStateKey) || "{}") || {};
    } catch {
      return {};
    }
  }

  function writeSidebarState(state) {
    try {
      window.localStorage.setItem(sidebarStateKey, JSON.stringify(state));
    } catch {
      // Local storage can be unavailable in hardened browser contexts.
    }
  }

  function opsNavPixel(value) {
    return Math.round(Number(value || 0) * 1000) / 1000 + "px";
  }

  function usableOpsNavPillTarget(target) {
    return target && Number.isFinite(target.top) && Number.isFinite(target.left) && Number.isFinite(target.width) && Number.isFinite(target.height);
  }

  function opsNavActiveItem(nav) {
    if (!nav) return null;
    var items = Array.from(nav.querySelectorAll(".ops-nav-subitem[aria-current='page'], .ops-nav-subitem.active, .ops-nav-direct[aria-current='page'], .ops-nav-direct.active"));
    return items.find(function (item) {
      var group = item.closest("[data-ops-nav-group]");
      if (!group || group.dataset.opsNavExpanded !== "true") return false;
      var rect = item.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0;
    }) || null;
  }

  function opsNavPillTarget(nav, item) {
    if (!nav || !item) return null;
    var navRect = nav.getBoundingClientRect();
    var itemRect = item.getBoundingClientRect();
    if (!itemRect.width || !itemRect.height) return null;
    return {
      height: itemRect.height,
      left: itemRect.left - navRect.left + nav.scrollLeft,
      top: itemRect.top - navRect.top + nav.scrollTop,
      width: itemRect.width,
    };
  }

  function opsNavPillRectToTarget(nav, rect) {
    if (!nav || !rect || !Number.isFinite(rect.top) || !Number.isFinite(rect.left) || !Number.isFinite(rect.width) || !Number.isFinite(rect.height)) return null;
    var navRect = nav.getBoundingClientRect();
    return {
      height: rect.height,
      left: rect.left - navRect.left + nav.scrollLeft,
      top: rect.top - navRect.top + nav.scrollTop,
      width: rect.width,
    };
  }

  function writeOpsNavPill(pill, target) {
    pill.style.height = opsNavPixel(target.height);
    pill.style.transform = "translate3d(" + opsNavPixel(target.left) + ", " + opsNavPixel(target.top) + ", 0)";
    pill.style.width = opsNavPixel(target.width);
  }

  function applyOpsNavPill(nav, target, options) {
    var pill = nav ? nav.querySelector(".ops-nav-pill") : null;
    if (!nav || !pill || !usableOpsNavPillTarget(target)) {
      if (nav) nav.removeAttribute("data-nav-pill-ready");
      return false;
    }
    var instant = Boolean(options && options.instant);
    var from = instant ? null : opsNavPillRectToTarget(nav, options && options.fromViewportRect);
    if (opsNavPillFrame) {
      window.cancelAnimationFrame(opsNavPillFrame);
      opsNavPillFrame = 0;
    }
    if (instant) {
      nav.dataset.navPillInstant = "true";
      writeOpsNavPill(pill, target);
      nav.dataset.navPillReady = "true";
      window.requestAnimationFrame(function () {
        if (nav.isConnected) delete nav.dataset.navPillInstant;
      });
      return true;
    }
    if (from && usableOpsNavPillTarget(from)) {
      nav.dataset.navPillInstant = "true";
      writeOpsNavPill(pill, from);
      nav.dataset.navPillReady = "true";
      pill.getBoundingClientRect();
      opsNavPillFrame = window.requestAnimationFrame(function () {
        opsNavPillFrame = 0;
        if (!nav.isConnected) return;
        delete nav.dataset.navPillInstant;
        writeOpsNavPill(pill, target);
      });
      return true;
    }
    delete nav.dataset.navPillInstant;
    writeOpsNavPill(pill, target);
    nav.dataset.navPillReady = "true";
    return true;
  }

  function positionOpsNavPill(options) {
    var nav = document.querySelector(".ops-nav");
    if (!nav) return false;
    var active = options && options.item ? options.item : opsNavActiveItem(nav);
    var target = opsNavPillTarget(nav, active);
    if (!usableOpsNavPillTarget(target)) {
      nav.removeAttribute("data-nav-pill-ready");
      return false;
    }
    return applyOpsNavPill(nav, target, options || {});
  }

  function captureOpsNavPillRect() {
    var nav = document.querySelector(".ops-nav");
    if (!nav) return null;
    var pill = nav.querySelector(".ops-nav-pill");
    var rect = null;
    if (pill && nav.dataset.navPillReady === "true") {
      rect = pill.getBoundingClientRect();
    }
    if (!rect || !rect.width || !rect.height) {
      var active = opsNavActiveItem(nav);
      rect = active ? active.getBoundingClientRect() : null;
    }
    if (!rect || !rect.width || !rect.height) return null;
    opsNavLastPillRect = {
      height: rect.height,
      left: rect.left,
      top: rect.top,
      width: rect.width,
    };
    return opsNavLastPillRect;
  }

  function moveOpsNavPillTowardLink(link) {
    if (!link || !link.matches || !link.matches(".ops-nav-subitem[href], .ops-nav-direct[href]")) return false;
    var nav = link.closest(".ops-nav");
    var group = link.closest("[data-ops-nav-group]");
    if (!nav || !group || group.dataset.opsNavExpanded !== "true") return false;
    var target = opsNavPillTarget(nav, link);
    if (!usableOpsNavPillTarget(target)) return false;
    var from = captureOpsNavPillRect();
    return applyOpsNavPill(nav, target, { fromViewportRect: from });
  }

  function trackOpsNavPillDuringLayout(activeItem, duration) {
    var nav = document.querySelector(".ops-nav");
    var active = activeItem && activeItem.isConnected ? activeItem : opsNavActiveItem(nav);
    if (!nav || !active) return;
    var startedAt = window.performance && window.performance.now ? window.performance.now() : Date.now();
    if (opsNavLayoutFrame) {
      window.cancelAnimationFrame(opsNavLayoutFrame);
      opsNavLayoutFrame = 0;
    }
    var step = function (timestamp) {
      var now = timestamp || Date.now();
      if (!active.isConnected) {
        opsNavLayoutFrame = 0;
        positionOpsNavPill();
        return;
      }
      positionOpsNavPill({ item: active });
      if (now - startedAt < duration) {
        opsNavLayoutFrame = window.requestAnimationFrame(step);
      } else {
        opsNavLayoutFrame = 0;
        positionOpsNavPill({ item: active });
      }
    };
    opsNavLayoutFrame = window.requestAnimationFrame(step);
  }

  function activeNavItemInGroup(group) {
    return group ? group.querySelector(".ops-nav-subitem[aria-current='page'], .ops-nav-subitem.active") : null;
  }

  function groupContainsActiveNavItem(group) {
    return Boolean(activeNavItemInGroup(group));
  }

  function syncOpsNavPanelHeight(group) {
    if (!group) return;
    var panel = group.querySelector(":scope > .ops-nav-sublist");
    if (!panel) return;
    group.style.setProperty("--ops-nav-panel-height", panel.scrollHeight + "px");
  }

  function setOpsNavGroupExpanded(group, expanded) {
    if (!group) return;
    var panel = group.querySelector(":scope > .ops-nav-sublist");
    var toggle = group.querySelector("[data-ops-nav-toggle]");
    var locked = expanded && groupContainsActiveNavItem(group);
    syncOpsNavPanelHeight(group);
    group.classList.toggle("expanded", expanded);
    group.dataset.opsNavExpanded = expanded ? "true" : "false";
    group.dataset.opsNavLocked = locked ? "true" : "false";
    if (toggle) {
      toggle.setAttribute("aria-expanded", expanded ? "true" : "false");
      if (locked) {
        toggle.setAttribute("aria-disabled", "true");
      } else {
        toggle.removeAttribute("aria-disabled");
      }
      var label = group.querySelector(".ops-nav-main-label")?.textContent?.trim() || "sezione";
      toggle.setAttribute("aria-label", locked ? "Sezione attuale: " + label : (expanded ? "Chiudi " : "Apri ") + label);
    }
    if (panel) {
      panel.setAttribute("aria-hidden", expanded ? "false" : "true");
      if ("inert" in panel) panel.inert = !expanded;
    }
  }

  function restoreOpsNavState(options) {
    var nav = document.querySelector(".ops-nav");
    var instant = Boolean(options && options.instant);
    var compactNavigation = Boolean(window.matchMedia && window.matchMedia("(max-width: 860px)").matches);
    var preserved = options && options.expandedState && typeof options.expandedState === "object" ? options.expandedState : {};
    var state = readSidebarState();
    var opsState = state.opsNav && typeof state.opsNav === "object" ? state.opsNav : {};
    var opsStateChanged = false;
    if (instant && nav) nav.dataset.opsNavRestoring = "true";
    document.querySelectorAll("[data-ops-nav-collapsible]").forEach(function (group) {
      var key = group.getAttribute("data-ops-nav-group") || "";
      var current = group.dataset.opsNavExpanded === "true";
      var hasActiveItem = groupContainsActiveNavItem(group);
      if (hasActiveItem && key && opsState[key] !== true) {
        opsState[key] = true;
        opsStateChanged = true;
      }
      var expanded = hasActiveItem ? true : compactNavigation ? false : typeof preserved[key] === "boolean" ? preserved[key] : typeof opsState[key] === "boolean" ? opsState[key] : current;
      setOpsNavGroupExpanded(group, expanded);
    });
    if (opsStateChanged) {
      state.opsNav = opsState;
      writeSidebarState(state);
    }
    if (instant && nav) {
      nav.getBoundingClientRect();
      window.requestAnimationFrame(function () {
        delete nav.dataset.opsNavRestoring;
      });
    }
  }

  function toggleOpsNavGroup(toggle) {
    var group = toggle.closest("[data-ops-nav-collapsible]");
    if (!group) return;
    var key = group.getAttribute("data-ops-nav-group") || "";
    var hasActiveItem = groupContainsActiveNavItem(group);
    var currentExpanded = group.dataset.opsNavExpanded === "true";
    var state = readSidebarState();
    var opsState = state.opsNav && typeof state.opsNav === "object" ? state.opsNav : {};
    if (hasActiveItem && currentExpanded) {
      opsState[key] = true;
      state.opsNav = opsState;
      writeSidebarState(state);
      setOpsNavGroupExpanded(group, true);
      positionOpsNavPill();
      return;
    }
    var expanded = !currentExpanded;
    opsState[key] = expanded;
    state.opsNav = opsState;
    writeSidebarState(state);
    var activeItem = opsNavActiveItem(document.querySelector(".ops-nav"));
    captureOpsNavPillRect();
    setOpsNavGroupExpanded(group, expanded);
    trackOpsNavPillDuringLayout(activeItem, 320);
  }

  function setSidebarGroupCollapsed(group, collapsed) {
    if (!group) return;
    group.dataset.ccCollapsed = collapsed ? "true" : "false";
    var toggle = group.querySelector("[data-cc-sidebar-toggle]");
    var panel = group.querySelector(":scope > .cc-nav-panel");
    if (toggle) toggle.setAttribute("aria-expanded", collapsed ? "false" : "true");
    if (panel) {
      panel.setAttribute("aria-hidden", collapsed ? "true" : "false");
      if ("inert" in panel) panel.inert = collapsed;
    }
  }

  function restoreSidebarState(options) {
    restoreOpsNavState({
      expandedState: options && options.opsNavExpandedState,
      instant: Boolean(options && options.instantOpsNav),
    });
    var state = readSidebarState();
    document.querySelectorAll("[data-cc-collapsible][data-cc-nav-group][data-cc-collapsed]").forEach(function (group) {
      var key = group.getAttribute("data-cc-nav-group");
      var hasActivePage = group.querySelector('[aria-current="page"]') !== null;
      setSidebarGroupCollapsed(group, hasActivePage ? false : state[key] === true);
    });
  }

  function toggleSidebarGroup(toggle) {
    var group = toggle.closest("[data-cc-collapsible][data-cc-nav-group]");
    if (!group) return;
    var key = group.getAttribute("data-cc-nav-group");
    var collapsed = group.dataset.ccCollapsed !== "true";
    var state = readSidebarState();
    state[key] = collapsed;
    writeSidebarState(state);
    setSidebarGroupCollapsed(group, collapsed);
  }

  async function copyCommand(button) {
    var value = button.getAttribute("data-copy-command") || "";
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      var previous = button.textContent;
      button.dataset.copied = "true";
      button.textContent = "Copied";
      window.setTimeout(function () {
        button.dataset.copied = "false";
        button.textContent = previous;
      }, 1600);
    } catch {
      showError("Copy failed.");
    }
  }

  function hideVaultSecret(box, button) {
    var input = box ? box.querySelector("[data-vault-reveal-value]") : null;
    var copyButton = box ? box.querySelector("[data-vault-copy-action]") : null;
    if (input) {
      input.value = "";
      input.type = "password";
      input.dataset.vaultVisible = "false";
    }
    if (copyButton) copyButton.disabled = true;
    if (button) button.textContent = "Mostra";
  }

  async function revealVaultSecret(button) {
    var id = button.getAttribute("data-vault-id") || "";
    var confirm = button.getAttribute("data-vault-confirm") || "";
    var box = button.closest("[data-vault-reveal-box]");
    var input = box ? box.querySelector("[data-vault-reveal-value]") : null;
    var copyButton = box ? box.querySelector("[data-vault-copy-action]") : null;
    if (!id || !confirm || !box || !input) return;
    if (input.dataset.vaultVisible === "true") {
      hideVaultSecret(box, button);
      return;
    }
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    try {
      var response;
      var payload;
      for (var attempt = 0; attempt < 2; attempt += 1) {
        var headers = new Headers();
        headers.set("Accept", "application/json");
        headers.set("Content-Type", "application/x-www-form-urlencoded");
        headers.set("X-Requested-With", "platform-control-center");
        addMutationHeaders(headers, "POST");
        response = await fetch("/control/vault/secrets/" + encodeURIComponent(id) + "/reveal", {
          body: new URLSearchParams({ confirm: confirm }),
          credentials: "same-origin",
          headers: headers,
          method: "POST",
        });
        payload = await response.json();
        if (payload.error !== "admin_reauthentication_required" || attempt > 0) break;
        await authenticateWithSystemPasskey();
      }
      if (!response.ok) throw new Error(payload.message || payload.error || "Reveal failed.");
      input.type = "text";
      input.value = payload.value || "";
      input.dataset.vaultVisible = "true";
      button.textContent = "Nascondi";
      if (copyButton) copyButton.disabled = false;
      window.setTimeout(function () {
        if (input.dataset.vaultVisible === "true") hideVaultSecret(box, button);
      }, Math.max(10000, Number(payload.ttlMs || 120000)));
    } catch (error) {
      showError(error && error.message ? error.message : "Reveal failed.");
    } finally {
      button.disabled = false;
      button.removeAttribute("aria-busy");
    }
  }

  async function copyVaultSecret(button) {
    var box = button.closest("[data-vault-reveal-box]");
    var input = box ? box.querySelector("[data-vault-reveal-value]") : null;
    if (!input || !input.value) return;
    try {
      await navigator.clipboard.writeText(input.value);
      var previous = button.textContent;
      button.textContent = "Copiato";
      window.setTimeout(function () {
        button.textContent = previous || "Copia";
      }, 1400);
    } catch {
      showError("Copy failed.");
    }
  }

  async function navigate(url, options) {
    if (!url || !canRenderPath(url)) return false;
    var sequence = ++navigationSequence;
    var historyMode = options && options.history ? options.history : "push";
    var sidebarScrollTop = options && typeof options.sidebarScrollTop === "number" ? options.sidebarScrollTop : null;
    var pageScrollTop = options && typeof options.pageScrollTop === "number" ? options.pageScrollTop : null;
    captureOpsNavPillRect();
    setBusy(true);
    try {
      var result = await requestHtml(url, { method: "GET" });
      if (sequence !== navigationSequence) return true;
      applyHtml(result.html, result.url || url.href, historyMode, { sidebarScrollTop: sidebarScrollTop, pageScrollTop: pageScrollTop });
      return true;
    } catch (error) {
      setBusy(false);
      if (error && (error.name === "AbortError" || error.name === "ReauthenticationRedirect")) return true;
      showError(error && error.message ? error.message : "Navigation failed.");
      return false;
    }
  }

  async function submitForm(form, submitter) {
    var method = String(form.method || "GET").toUpperCase();
    var action = sameOriginUrl(form.getAttribute("action") || window.location.href);
    if (!action || !canRenderPath(action) && action.pathname.indexOf("/actions/") !== 0) return false;
    if (method === "POST" && action.pathname === "/actions/status-check") {
      return submitStatusRun(form, submitter, action);
    }
    if (formSubmissions.has(form)) return true;
    formSubmissions.add(form);
    var pageScrollTop = currentPageScrollTop();
    if (submitter) {
      submitter.disabled = true;
      submitter.setAttribute("aria-busy", "true");
    }

    setBusy(true);
    try {
      if (method === "GET") {
        var query = payloadFromForm(form, submitter);
        action.search = query.toString();
        await navigate(action, { history: "push" });
        return true;
      }

      clearCache();
      var result = await requestHtml(action, {
        body: payloadFromForm(form, submitter),
        method: method,
      });
      applyHtml(result.html, result.url || window.location.href, "push", { pageScrollTop: pageScrollTop });
      return true;
    } catch (error) {
      setBusy(false);
      if (error && (error.name === "AbortError" || error.name === "ReauthenticationRedirect")) return true;
      showError(error && error.message ? error.message : "Action failed.");
      return false;
    } finally {
      formSubmissions.delete(form);
      if (submitter && submitter.isConnected) {
        submitter.disabled = false;
        submitter.removeAttribute("aria-busy");
      }
    }
  }

  function prefetch(url) {
    if (!url || !canRenderPath(url) || isSensitivePortalUrl(url) || cachedPage(url.href, false)) return;
    prefetchHtml(url);
  }

  function portalPageUrlsForPreload() {
    var seen = new Set();
    return Array.from(document.querySelectorAll("a[href]")).map(function (link) {
      if (link.target || link.hasAttribute("download")) return null;
      var url = sameOriginUrl(link.getAttribute("href") || "");
      if (!url || !canRenderPath(url) || isSensitivePortalUrl(url) || seen.has(url.href)) return null;
      seen.add(url.href);
      return url;
    }).filter(Boolean);
  }

  async function preloadControlCenterPages(urls, onProgress) {
    var queue = Array.isArray(urls) ? urls.slice() : portalPageUrlsForPreload();
    var total = queue.length;
    var completed = 0;
    var failed = [];
    if (!total) return { total: 0, completed: 0, failed: [] };
    var workers = Array.from({ length: Math.min(preloadWorkerCount, queue.length) }, async function () {
      while (queue.length) {
        var url = queue.shift();
        if (!url) continue;
        var result = await prefetchHtml(url);
        completed += 1;
        if (!result) failed.push(url);
        if (typeof onProgress === "function") onProgress(completed, total, url, Boolean(result));
      }
    });
    await Promise.all(workers);
    return { total: total, completed: completed, failed: failed };
  }

  function scheduleControlCenterPreload() {
    Promise.resolve().then(preloadControlCenterPages);
  }

  function updateInitialPreloadProgress(completed, total, message) {
    var safeTotal = Math.max(1, Number(total) || 1);
    var percent = Math.max(0, Math.min(100, Math.round((Number(completed) || 0) / safeTotal * 100)));
    var bar = document.querySelector("[data-cc-preload-bar]");
    var value = document.querySelector("[data-cc-preload-percent]");
    var detail = document.querySelector("[data-cc-preload-message]");
    if (bar) bar.style.width = percent + "%";
    setText(value, percent + "%");
    if (message) setText(detail, message);
  }

  function revealFullyPreloadedControlCenter(total) {
    updateInitialPreloadProgress(total, total, "Control Center pronto.");
    document.body.dataset.ccPreloadComplete = "true";
    delete document.body.dataset.ccPreloading;
    var screen = document.querySelector("[data-cc-preload-screen]");
    if (screen) screen.hidden = true;
  }

  async function runInitialControlCenterPreload() {
    var screen = document.querySelector("[data-cc-preload-screen]");
    if (!screen || document.body.dataset.ccPreloading !== "true") return;
    var retry = screen.querySelector("[data-cc-preload-retry]");
    if (retry) retry.hidden = true;
    var urls = portalPageUrlsForPreload();
    updateInitialPreloadProgress(0, urls.length, "Carico tutte le pagine applicative...");
    var result = await preloadControlCenterPages(urls, function (completed, total) {
      updateInitialPreloadProgress(completed, total, "Caricate " + completed + " di " + total + " pagine.");
    });
    if (result.failed.length) {
      updateInitialPreloadProgress(result.completed - result.failed.length, result.total, "Riprovo le pagine non ancora disponibili...");
      result = await preloadControlCenterPages(result.failed, function (completed, total) {
        updateInitialPreloadProgress(completed, total, "Verifica finale " + completed + " di " + total + ".");
      });
    }
    if (!result.failed.length) {
      revealFullyPreloadedControlCenter(urls.length);
      return;
    }
    updateInitialPreloadProgress(0, result.failed.length, "Non posso mostrare un portale caricato solo in parte.");
    if (retry) {
      retry.hidden = false;
      retry.onclick = function () {
        retry.hidden = true;
        runInitialControlCenterPreload();
      };
    }
  }

  function linkFromEvent(event) {
    var link = event.target.closest ? event.target.closest("a[href]") : null;
    if (!link || link.target || link.hasAttribute("download")) return null;
    var href = link.getAttribute("href") || "";
    if (!href || href === "#" || href.indexOf("javascript:") === 0) return null;
    var url = sameOriginUrl(href);
    if (!url || !canRenderPath(url)) return null;
    return url;
  }

  function interactiveTarget(event) {
    return event.target.closest && event.target.closest("a[href], button, input, select, textarea, label, summary, form");
  }

  function projectRowUrlFromEvent(event) {
    if (interactiveTarget(event)) return null;
    var row = event.target.closest ? event.target.closest("[data-project-row-link]") : null;
    if (!row) return null;
    return sameOriginUrl(row.getAttribute("data-project-row-link") || "");
  }

  function startFileManagers() {
    var manager = document.querySelector("[data-file-manager]");
    if (manager) {
      manager.dataset.fileManagerReady = "true";
      applyFileSearch(manager);
    }
    if (!selectedFileEntry || !selectedFileEntry.isConnected) selectedFileEntry = null;
  }

  function stopFileManagers() {
    fileManagerRefreshInFlight = false;
    if (!selectedFileEntry || !selectedFileEntry.isConnected) selectedFileEntry = null;
  }

  function fileContextMenuOpen() {
    return Array.from(document.querySelectorAll("[data-file-context-menu]")).some(function (menu) {
      return !menu.hidden;
    });
  }

  function applyFileSearch(root) {
    if (!root) return;
    var search = root.querySelector("[data-file-search]");
    var query = search ? String(search.value || "").trim().toLowerCase() : "";
    var entries = Array.from(root.querySelectorAll("[data-file-entry]"));
    var visible = 0;
    entries.forEach(function (entry) {
      var payload = fileEntryPayload(entry);
      var haystack = payload.name.toLowerCase();
      var matched = !query || haystack.indexOf(query) !== -1;
      entry.hidden = !matched;
      if (matched) visible += 1;
    });
    if (selectedFileEntry && selectedFileEntry.hidden) {
      selectedFileEntry.classList.remove("selected");
      selectedFileEntry.setAttribute("aria-selected", "false");
      selectedFileEntry = null;
    }
    var total = Number(root.getAttribute("data-file-total-count") || entries.length);
    if (!Number.isFinite(total)) total = entries.length;
    var count = root.querySelector("[data-file-count]");
    if (count) count.textContent = query ? visible + " di " + total + " elementi" : total + " elementi";
    var empty = root.querySelector("[data-file-search-empty]");
    if (empty) empty.hidden = !query || visible > 0 || total === 0;
  }

  async function refreshFileManager() {
    var current = document.querySelector("[data-file-manager]");
    if (!current) {
      stopFileManagers();
      return;
    }
    if (fileManagerRefreshInFlight || fileContextMenuOpen()) return;
    var url = sameOriginUrl(current.getAttribute("data-file-manager-refresh-url") || window.location.href);
    if (!url) return;
    var selectedPath = selectedFileEntry && selectedFileEntry.isConnected ? selectedFileEntry.getAttribute("data-file-path") : "";
    var currentGrid = current.querySelector(".ops-file-grid");
    var currentSearch = current.querySelector("[data-file-search]");
    var searchQuery = currentSearch ? currentSearch.value : "";
    var previousScrollTop = currentGrid ? currentGrid.scrollTop : 0;
    var previousScrollLeft = currentGrid ? currentGrid.scrollLeft : 0;
    fileManagerRefreshInFlight = true;
    try {
      var response = await fetch(url.href, {
        cache: "no-store",
        credentials: "same-origin",
        headers: {
          Accept: "text/html,*/*;q=0.8",
          "X-Requested-With": "platform-control-center",
        },
      });
      if (!response.ok) return;
      var html = await response.text();
      var parsed = new DOMParser().parseFromString(html, "text/html");
      var next = parsed.querySelector("[data-file-manager]");
      if (!next || !document.querySelector("[data-file-manager]")) return;
      var imported = document.importNode(next, true);
      imported.dataset.fileManagerReady = "true";
      current.replaceWith(imported);
      var nextSearch = imported.querySelector("[data-file-search]");
      if (nextSearch && searchQuery) nextSearch.value = searchQuery;
      var nextGrid = imported.querySelector(".ops-file-grid");
      if (nextGrid) {
        nextGrid.scrollTop = previousScrollTop;
        nextGrid.scrollLeft = previousScrollLeft;
      }
      applyFileSearch(imported);
      selectedFileEntry = null;
      if (selectedPath) {
        var restored = Array.from(imported.querySelectorAll("[data-file-entry]")).find(function (entry) {
          return entry.getAttribute("data-file-path") === selectedPath;
        });
        if (restored) selectFileEntry(restored);
      }
    } catch {
      // File manager live refresh is best-effort; manual navigation remains available.
    } finally {
      fileManagerRefreshInFlight = false;
    }
  }

  function fileEntryPayload(entry) {
    if (!entry) return null;
    return {
      modified: entry.getAttribute("data-file-modified") || "-",
      name: entry.getAttribute("data-file-name") || "",
      openUrl: entry.getAttribute("data-file-open-url") || "",
      path: entry.getAttribute("data-file-path") || "",
      size: entry.getAttribute("data-file-size") || "-",
      type: entry.getAttribute("data-file-type") || "file",
    };
  }

  function selectFileEntry(entry) {
    if (!entry) return;
    var root = entry.closest("[data-file-manager]");
    if (!root) return;
    root.querySelectorAll("[data-file-entry]").forEach(function (item) {
      var selected = item === entry;
      item.classList.toggle("selected", selected);
      item.setAttribute("aria-selected", selected ? "true" : "false");
    });
    selectedFileEntry = entry;
  }

  function closeFileContextMenu() {
    document.querySelectorAll("[data-file-context-menu]").forEach(function (menu) {
      menu.hidden = true;
      menu.removeAttribute("style");
    });
  }

  function positionFileContextMenu(menu, event) {
    var padding = 12;
    menu.hidden = false;
    menu.style.left = "0px";
    menu.style.top = "0px";
    var rect = menu.getBoundingClientRect();
    var x = Math.min(event.clientX, window.innerWidth - rect.width - padding);
    var y = Math.min(event.clientY, window.innerHeight - rect.height - padding);
    menu.style.left = Math.max(padding, x) + "px";
    menu.style.top = Math.max(padding, y) + "px";
  }

  function openFileContextMenu(entry, event) {
    var root = entry.closest("[data-file-manager]");
    var menu = root ? root.querySelector("[data-file-context-menu]") : null;
    if (!menu) return;
    selectFileEntry(entry);
    var payload = fileEntryPayload(entry);
    var openButton = menu.querySelector('[data-file-menu-action="open"]');
    if (openButton) openButton.disabled = !(payload && payload.openUrl);
    positionFileContextMenu(menu, event);
  }

  async function copyFileText(value) {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      showError("Copia non riuscita.");
    }
  }

  async function openFileEntry(entry) {
    var payload = fileEntryPayload(entry);
    var url = payload && payload.openUrl ? sameOriginUrl(payload.openUrl) : null;
    if (!url) return false;
    return navigate(url, { history: "push" });
  }

  async function runFileMenuAction(action) {
    var entry = selectedFileEntry && selectedFileEntry.isConnected ? selectedFileEntry : null;
    var payload = fileEntryPayload(entry);
    if (!entry || !payload) return;
    if (action === "open") {
      await openFileEntry(entry);
    } else if (action === "copy-path") {
      await copyFileText(payload.path);
    } else if (action === "copy-name") {
      await copyFileText(payload.name);
    }
    closeFileContextMenu();
  }

  function moveFileSelection(entry, direction) {
    var root = entry ? entry.closest("[data-file-manager]") : null;
    if (!root) return;
    var entries = Array.from(root.querySelectorAll("[data-file-entry]"));
    var index = entries.indexOf(entry);
    if (index === -1) return;
    var nextIndex = Math.max(0, Math.min(entries.length - 1, index + direction));
    var next = entries[nextIndex];
    if (!next) return;
    selectFileEntry(next);
    next.focus({ preventScroll: true });
  }

  function init() {
    if (initialized) return;
    initialized = true;
    document.body.dataset.ccEnhanced = "true";
    document.body.dataset.ccBootId = bootId;
    window.history.replaceState({ ccDynamic: true }, "", window.location.pathname + window.location.search + window.location.hash);
    restoreSidebarState({ instantOpsNav: true });
    positionOpsNavPill({ instant: true });
    startStatusTabs();
    startFileManagers();
    fitSingleLineText();
    storeCache(window.location.href, document.documentElement.outerHTML, "");
    runInitialControlCenterPreload();

    document.addEventListener("click", function (event) {
      var inlineStatusRun = event.target.closest ? event.target.closest("[data-status-run-inline]") : null;
      if (inlineStatusRun) {
        event.stopPropagation();
        return;
      }
      var fileRefreshButton = event.target.closest ? event.target.closest("[data-file-refresh-action]") : null;
      if (fileRefreshButton) {
        event.preventDefault();
        closeFileContextMenu();
        refreshFileManager();
        return;
      }
      var fileMenuButton = event.target.closest ? event.target.closest("[data-file-menu-action]") : null;
      if (fileMenuButton) {
        event.preventDefault();
        runFileMenuAction(fileMenuButton.getAttribute("data-file-menu-action") || "");
        return;
      }
      var fileEntry = event.target.closest ? event.target.closest("[data-file-entry]") : null;
      if (fileEntry) {
        event.preventDefault();
        closeFileContextMenu();
        selectFileEntry(fileEntry);
        return;
      }
      closeFileContextMenu();
      var statusTab = event.target.closest ? event.target.closest("[data-status-tab]") : null;
      if (statusTab) {
        event.preventDefault();
        activateStatusTab(statusTab.getAttribute("data-status-tab"), true);
        return;
      }
      var copyButton = event.target.closest ? event.target.closest("[data-copy-command]") : null;
      if (copyButton) {
        event.preventDefault();
        copyCommand(copyButton);
        return;
      }
      var vaultRevealButton = event.target.closest ? event.target.closest("[data-vault-reveal-action]") : null;
      if (vaultRevealButton) {
        event.preventDefault();
        revealVaultSecret(vaultRevealButton);
        return;
      }
      var vaultCopyButton = event.target.closest ? event.target.closest("[data-vault-copy-action]") : null;
      if (vaultCopyButton) {
        event.preventDefault();
        copyVaultSecret(vaultCopyButton);
        return;
      }
      var opsNavToggle = event.target.closest ? event.target.closest("[data-ops-nav-toggle]") : null;
      if (opsNavToggle) {
        event.preventDefault();
        toggleOpsNavGroup(opsNavToggle);
        return;
      }
      var toggle = event.target.closest ? event.target.closest("[data-cc-sidebar-toggle]") : null;
      if (toggle) {
        event.preventDefault();
        toggleSidebarGroup(toggle);
        return;
      }
      var passkeyLink = event.target.closest ? event.target.closest("[data-passkey-return-to]") : null;
      if (passkeyLink && isPlainClick(event)) {
        event.preventDefault();
        runPasskeyNavigation(passkeyLink);
        return;
      }
      if (!isPlainClick(event)) return;
      var projectRowUrl = projectRowUrlFromEvent(event);
      if (projectRowUrl) {
        event.preventDefault();
        navigate(projectRowUrl, { history: "push" });
        return;
      }
      var url = linkFromEvent(event);
      if (!url) return;
      event.preventDefault();
      var clickedLink = event.target.closest("a[href]");
      var sidebarScrollTop = consumePendingSidebarScrollTop();
      moveOpsNavPillTowardLink(clickedLink);
      navigate(url, { history: "push", sidebarScrollTop: sidebarScrollTop });
    });

    document.addEventListener("pointerdown", rememberSidebarScrollBeforePointer, { capture: true });

    document.addEventListener("dblclick", function (event) {
      var fileEntry = event.target.closest ? event.target.closest("[data-file-entry]") : null;
      if (!fileEntry) return;
      event.preventDefault();
      selectFileEntry(fileEntry);
      openFileEntry(fileEntry);
    });

    document.addEventListener("contextmenu", function (event) {
      var fileEntry = event.target.closest ? event.target.closest("[data-file-entry]") : null;
      if (!fileEntry) {
        closeFileContextMenu();
        return;
      }
      event.preventDefault();
      openFileContextMenu(fileEntry, event);
    });

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") {
        closeFileContextMenu();
        return;
      }
      var fileEntry = event.target.closest ? event.target.closest("[data-file-entry]") : null;
      if (fileEntry) {
        if (event.key === "Enter") {
          event.preventDefault();
          selectFileEntry(fileEntry);
          openFileEntry(fileEntry);
          return;
        }
        if (event.key === " ") {
          event.preventDefault();
          selectFileEntry(fileEntry);
          return;
        }
        if (event.key === "ArrowDown" || event.key === "ArrowRight") {
          event.preventDefault();
          moveFileSelection(fileEntry, 1);
          return;
        }
        if (event.key === "ArrowUp" || event.key === "ArrowLeft") {
          event.preventDefault();
          moveFileSelection(fileEntry, -1);
          return;
        }
        if (event.key === "ContextMenu" || event.shiftKey && event.key === "F10") {
          event.preventDefault();
          var rect = fileEntry.getBoundingClientRect();
          openFileContextMenu(fileEntry, { clientX: rect.left + 24, clientY: rect.top + 24 });
          return;
        }
      }
      if (event.key !== "Enter" && event.key !== " ") return;
      var projectRowUrl = projectRowUrlFromEvent(event);
      if (!projectRowUrl) return;
      event.preventDefault();
      navigate(projectRowUrl, { history: "push" });
    });

    document.addEventListener("submit", function (event) {
      var form = event.target;
      if (!(form instanceof HTMLFormElement)) return;
      if (form.hasAttribute("data-passkey-submit")) {
        event.preventDefault();
        submitPasskeyForm(form, event.submitter || null);
        return;
      }
      if (form.hasAttribute("data-cc-native-submit") || form.target) return;
      var action = sameOriginUrl(form.getAttribute("action") || window.location.href);
      if (!action) return;
      event.preventDefault();
      submitForm(form, event.submitter || null);
    });

    document.addEventListener("change", function (event) {
      var select = event.target;
      if (!(select instanceof HTMLSelectElement)) return;
      var form = select.closest("form.switcher");
      if (!form) return;
      submitForm(form, null);
    });

    document.addEventListener("input", function (event) {
      var search = event.target.closest ? event.target.closest("[data-file-search]") : null;
      if (!search) return;
      var manager = search.closest("[data-file-manager]");
      closeFileContextMenu();
      applyFileSearch(manager);
    });

    document.addEventListener("mouseover", function (event) {
      var url = linkFromEvent(event);
      if (url) prefetch(url);
    });

    document.addEventListener("focusin", function (event) {
      var url = linkFromEvent(event);
      if (url) prefetch(url);
    });

    window.addEventListener("resize", function () {
      document.querySelectorAll("[data-ops-nav-collapsible]").forEach(syncOpsNavPanelHeight);
      fitSingleLineText();
      positionOpsNavPill({ instant: true });
      closeFileContextMenu();
    });

    window.addEventListener("scroll", function () {
      closeFileContextMenu();
    }, true);

    window.addEventListener("popstate", function () {
      var url = sameOriginUrl(window.location.href);
      if (url) navigate(url, { history: "replace" });
    });

  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
