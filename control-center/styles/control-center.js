(function () {
  "use strict";

  var appSelector = ".cc-app-shell, .login-shell";
  var cacheLimit = 64;
  var cacheTtlMs = 300000;
  var prefetchTimeoutMs = 15000;
  var preloadWorkerCount = 4;
  var backgroundPreloadWorkerCount = 1;
  var backgroundPreloadQuietMs = 200;
  var sidebarStateKey = "platform-control-center-sidebar";
  var htmlCache = new Map();
  var activeRequest = null;
  var initialized = false;
  var bootId = "cc-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2);
  var fileManagerRefreshInFlight = false;
  var prefetchInFlight = new Set();
  var prefetchControllers = new Map();
  var backgroundPreloadHandle = null;
  var backgroundPreloadRunning = false;
  var backgroundPreloadPending = false;
  var backgroundPreloadGeneration = 0;
  var formSubmissions = new WeakSet();
  var navigationSequence = 0;
  var opsNavLastPillRect = null;
  var opsNavPillFrame = 0;
  var opsNavLayoutFrame = 0;
  var pendingSidebarScrollTop = null;
  var pendingSidebarScrollAt = 0;
  var selectedFileEntry = null;
  var passkeyActionInFlight = false;
  var projectHostingLoads = new WeakMap();
  var projectHostingPolls = new WeakMap();
  var projectHostingStates = new WeakMap();

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
    if (isSensitivePortalUrl(sameOriginUrl(url))) return;
    htmlCache.set(url, { etag: etag || "", html: String(html || ""), storedAt: Date.now() });
    while (htmlCache.size > cacheLimit) {
      htmlCache.delete(htmlCache.keys().next().value);
    }
  }

  function clearCache() {
    htmlCache.clear();
  }

  function cancelBackgroundPreload() {
    backgroundPreloadGeneration += 1;
    backgroundPreloadPending = false;
    if (backgroundPreloadHandle !== null) {
      window.clearTimeout(backgroundPreloadHandle);
      backgroundPreloadHandle = null;
    }
    prefetchControllers.forEach(function (controller) {
      controller.abort();
    });
  }

  function isCurrentBackgroundPreload(generation) {
    return generation === undefined || generation === backgroundPreloadGeneration;
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
    var allowedActions = new Set(["/actions/backup-delete-command", "/actions/database-delete-command", "/actions/vault-command", "/actions/redis-restore-command", "/actions/redis-backup-delete-command", "/actions/project-remove-from-list"]);
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
    cancelBackgroundPreload();
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
      if (activeRequest === controller) {
        activeRequest = null;
        scheduleControlCenterPreload();
      }
    }
  }

  async function prefetchHtml(url) {
    if (!url || !canRenderPath(url) || isSensitivePortalUrl(url) || prefetchInFlight.has(url.href)) return null;
    var cached = cachedPage(url.href, false);
    if (cached) return { html: cached.html, url: url.href, fromCache: true };
    prefetchInFlight.add(url.href);
    var controller = new AbortController();
    prefetchControllers.set(url.href, controller);
    try {
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
      if (prefetchControllers.get(url.href) === controller) {
        prefetchControllers.delete(url.href);
      }
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
    animatePortalPage();
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
    var active = document.querySelector(".ops-page h1") || document.querySelector(".ops-nav-main[aria-current='page']");
    if (!active || typeof active.focus !== "function") return;
    if (active.tagName === "H1") active.tabIndex = -1;
    active.focus({ preventScroll: true });
  }

  var portalMotions = new WeakMap();
  function animatePortalElement(element, frames) {
    if (!element) return;
    var previous = portalMotions.get(element);
    if (previous) { previous.cancel(); portalMotions.delete(element); }
    if (typeof element.animate !== "function" || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    var animation = element.animate(frames, { duration: 220, easing: "cubic-bezier(.22,1,.36,1)" });
    portalMotions.set(element, animation);
    var finish = function () { if (portalMotions.get(element) === animation) portalMotions.delete(element); };
    animation.finished.then(finish, finish);
    return animation;
  }

  function animatePortalPage() {
    var entrance = animatePortalElement(document.querySelector(".ops-shell .ops-page"), [{ opacity: .88, transform: "translateY(4px)" }, { opacity: 1, transform: "translateY(0)" }]);
    if (entrance) entrance.id = "cc-route-enter";
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
    var instant = Boolean(options && options.instant) || window.matchMedia("(prefers-reduced-motion: reduce)").matches;
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

  async function submitVaultManagement(form) {
    if (formSubmissions.has(form)) return;
    formSubmissions.add(form);
    var button = form.querySelector("button[type=submit]");
    var secretRoot = form.closest("[data-secrets-page]");
    if (secretRoot && secretRoot.dataset.managementBusy === "true") { formSubmissions.delete(form); return; }
    var pendingControls = [];
    if (secretRoot) {
      secretRoot.dataset.managementBusy = "true"; form.setAttribute("aria-busy", "true");
      secretRoot.querySelectorAll("[data-secret-create],[data-secret-edit],[data-secret-delete],[data-secret-close]").forEach(function (control) { if (!control.disabled) { pendingControls.push(control); control.disabled = true; } });
      var pendingStatus = form.querySelector("[data-secret-form-status]");
      if (pendingStatus) { pendingStatus.removeAttribute("data-error"); pendingStatus.textContent = form.elements.action.value === "delete" ? "Eliminazione in corso…" : "Salvataggio in corso…"; }
    }
    if (button) button.disabled = true;
    try {
      var payload = Object.fromEntries(new FormData(form).entries());
      await hostingRequest(form.getAttribute("action"), payload);
      if (!form.isConnected || (secretRoot && !secretRoot.isConnected)) return;
      form.querySelectorAll('textarea,input[type="password"]').forEach(function (field) { field.value = ""; });
      clearCache();
      await navigate(new URL(window.location.href), { history: "replace", pageScrollTop: currentPageScrollTop() });
      document.dispatchEvent(new CustomEvent("cc-vault-management-complete", { detail: { action: payload.action } }));
    } catch (error) {
      if (error.name !== "ReauthenticationRedirect") {
        if (!form.isConnected) return;
        var inlineStatus = form.querySelector("[data-secret-form-status]");
        if (inlineStatus) { inlineStatus.textContent = error.message || "Modifica Vault non riuscita."; inlineStatus.dataset.error = "true"; }
        else showError(error.message || "Modifica Vault non riuscita.");
      }
    }
    finally { if (secretRoot) delete secretRoot.dataset.managementBusy; form.removeAttribute("aria-busy"); pendingControls.forEach(function (control) { if (control.isConnected) control.disabled = false; }); formSubmissions.delete(form); if (button && button.isConnected) button.disabled = false; }
  }

  async function submitVaultRuntime(form) {
    var box = form.closest("[data-vault-binding]");
    var resultBox = box ? box.querySelector("[data-vault-runtime-result]") : null;
    var button = form.querySelector("button[type=submit]");
    if (button) button.disabled = true;
    try {
      var result = await hostingRequest(form.getAttribute("action"), Object.fromEntries(new FormData(form).entries()));
      if (resultBox) resultBox.replaceChildren();
      if (result.planId) {
        var explanation = document.createElement("p");
        explanation.textContent = "Piano verificato per " + (result.consumers || []).map(function (consumer) { return consumer.name; }).join(", ") + (result.requiresRestart ? ". Richiede riavvio controllato." : ".") + " Il provider " + (result.providerVerification === "available" ? "sarà verificato." : "non dispone di verifica automatica.");
        var apply = document.createElement("button"); apply.type = "button"; apply.className = "ops-button primary"; apply.textContent = "Applica piano verificato";
        apply.addEventListener("click", async function () {
          apply.disabled = true;
          try {
            var queued = await hostingRequest("/control/vault/runtime/apply", { bindingId: result.bindingId, planId: result.planId, confirmation: result.confirmation, expectedVaultRevision: result.expectedVaultRevision, expectedBindingRevision: result.expectedBindingRevision });
            resultBox.replaceChildren();
            addVaultStatusButton(resultBox, queued.operationId);
          } catch (error) { explanation.textContent = error.message || "Piano non più valido: ripeti la verifica."; apply.disabled = false; }
        });
        if (resultBox) resultBox.append(explanation, apply);
      } else if (result.operationId && result.phase === "queued") {
        if (resultBox) addVaultStatusButton(resultBox, result.operationId);
      } else if (/\/adopt$/.test(form.getAttribute("action"))) {
        refreshVaultPanel(box);
      } else if (resultBox) {
        var operation = result.operation || result;
        if (["verified", "rolled-back"].includes(operation.phase)) refreshVaultPanel(box);
        else if (["queued", "applying", "verifying", "rolling-back"].includes(operation.phase)) addVaultStatusButton(resultBox, operation.operationId);
        else resultBox.textContent = vaultPhaseLabel(operation.phase);
      }
    } catch (error) { if (resultBox) resultBox.textContent = error.message || "Operazione Vault non disponibile."; }
    finally { if (button && button.isConnected) button.disabled = false; }
  }

  function vaultPhaseLabel(phase) {
    return { queued: "Operazione in attesa", applying: "Consegna in corso", verifying: "Verifica in corso", "rolling-back": "Ripristino in corso", verified: "Completato: consegna verificata", "rolled-back": "Ripristino completato", failed: "Operazione non riuscita", "requires-reconciliation": "È necessario verificare lo stato del servizio" }[phase] || "Stato non disponibile";
  }

  function refreshVaultPanel(bindingBox) {
    clearCache();
    if (bindingBox && bindingBox.id) window.history.replaceState(window.history.state, "", window.location.pathname + window.location.search + "#" + bindingBox.id);
    navigate(new URL(window.location.href), { history: "replace", pageScrollTop: currentPageScrollTop() }).then(function () { if (bindingBox && bindingBox.id) openVaultBinding(bindingBox.id); });
  }

  function openVaultBinding(bindingId) {
    var target = document.getElementById(bindingId);
    if (!target) return;
    var panel = target.closest("[data-vault-runtime-panel]");
    if (panel) panel.open = true;
    target.scrollIntoView({ block: "nearest" });
  }

  function addVaultStatusButton(box, operationId) {
    if (!box || !operationId) return;
    var generation = (Number(box.dataset.vaultPollGeneration) || 0) + 1;
    box.dataset.vaultPollGeneration = String(generation);
    var message = document.createElement("p"); message.textContent = vaultPhaseLabel("queued");
    var button = document.createElement("button"); button.type = "button"; button.className = "ops-button secondary"; button.textContent = "Aggiorna risultato";
    box.replaceChildren(message, button);
    var deadline = Date.now() + 90000;
    var timer = null, busy = false, finished = false;
    async function checkStatus() {
      if (busy || finished || !box.isConnected || Number(box.dataset.vaultPollGeneration) !== generation) return;
      busy = true; button.disabled = true;
      if (timer) window.clearTimeout(timer);
      try {
        var result = await hostingRequest("/control/vault/runtime/status", { operationId: operationId });
        if (!box.isConnected || Number(box.dataset.vaultPollGeneration) !== generation) return;
        var operation = result.operation || result;
        message.textContent = vaultPhaseLabel(operation.phase);
        if (["verified", "rolled-back"].includes(operation.phase)) { finished = true; refreshVaultPanel(box.closest("[data-vault-binding]")); return; }
        if (["failed", "requires-reconciliation"].includes(operation.phase)) { finished = true; button.remove(); return; }
      } catch (error) { message.textContent = error.message || "Stato non disponibile. Aggiorna il risultato."; }
      finally {
        busy = false; if (button.isConnected) button.disabled = false;
        if (!finished && box.isConnected && Number(box.dataset.vaultPollGeneration) === generation && Date.now() < deadline) timer = window.setTimeout(checkStatus, 2000);
        else if (!finished && box.isConnected) message.textContent += " Controllo automatico terminato: puoi aggiornare il risultato.";
      }
    }
    button.addEventListener("click", checkStatus);
    timer = window.setTimeout(checkStatus, 2000);
  }

  var vaultRevealStates = new WeakMap();
  function setVaultRevealLabel(button, visible) {
    if (!button) return;
    var label = button.querySelector("[data-vault-reveal-label]");
    if (label) label.textContent = visible ? "Nascondi" : "Mostra"; else button.textContent = visible ? "Nascondi" : "Mostra";
    button.setAttribute("aria-pressed", String(visible));
    if (button.hasAttribute("aria-label")) button.setAttribute("aria-label", button.getAttribute("aria-label").replace(/^(Mostra|Nascondi)/, visible ? "Nascondi" : "Mostra"));
  }
  function hideVaultSecret(box, button) {
    if (!box) return;
    var previous = vaultRevealStates.get(box);
    if (previous && previous.timer) window.clearTimeout(previous.timer);
    vaultRevealStates.set(box, { generation: (previous?.generation || 0) + 1, timer: null });
    var input = box.querySelector("[data-vault-reveal-value]");
    var copyButton = box.querySelector("[data-vault-copy-action]");
    if (input) { input.value = ""; if (input.tagName === "INPUT") input.type = "password"; input.dataset.vaultVisible = "false"; }
    var revealed = box.querySelector("[data-secret-revealed]"); if (revealed) revealed.hidden = true;
    if (copyButton) copyButton.disabled = true;
    setVaultRevealLabel(button || box.querySelector("[data-vault-reveal-action]"), false);
  }
  function clearVaultReveals() {
    document.querySelectorAll("[data-vault-reveal-box]").forEach(function (box) { hideVaultSecret(box); });
  }
  async function revealVaultSecret(button) {
    var id = button.getAttribute("data-vault-id") || "";
    var confirm = button.getAttribute("data-vault-confirm") || "";
    var box = button.closest("[data-vault-reveal-box]");
    var input = box?.querySelector("[data-vault-reveal-value]");
    var copyButton = box?.querySelector("[data-vault-copy-action]");
    if (!id || !confirm || !box || !input || button.disabled || passkeyActionInFlight) return;
    if (input.dataset.vaultVisible === "true") { hideVaultSecret(box, button); return; }
    hideVaultSecret(box, button);
    var state = vaultRevealStates.get(box);
    button.disabled = true; button.setAttribute("aria-busy", "true");
    passkeyActionInFlight = true;
    try {
      await authenticateWithSystemPasskey();
      if (!box.isConnected || document.hidden || vaultRevealStates.get(box) !== state) return;
      var headers = new Headers(); headers.set("Accept", "application/json"); headers.set("Content-Type", "application/x-www-form-urlencoded"); headers.set("X-Requested-With", "platform-control-center"); addMutationHeaders(headers, "POST");
      var response = await fetch("/control/vault/secrets/" + encodeURIComponent(id) + "/reveal", { body: new URLSearchParams({ confirm: confirm }), credentials: "same-origin", headers: headers, method: "POST" });
      var payload = await response.json();
      if (!response.ok) throw new Error(payload.message || payload.error || "Valore non disponibile.");
      if (!box.isConnected || document.hidden || vaultRevealStates.get(box) !== state) return;
      if (input.tagName === "INPUT") input.type = "text";
      input.value = payload.value || ""; input.dataset.vaultVisible = "true";
      var revealed = box.querySelector("[data-secret-revealed]"); if (revealed) revealed.hidden = false;
      setVaultRevealLabel(button, true); if (copyButton) copyButton.disabled = false;
      state.timer = window.setTimeout(function () { if (vaultRevealStates.get(box) === state) hideVaultSecret(box, button); }, Math.min(30000, Math.max(1, Number(payload.ttlMs) || 30000)));
    } catch (error) {
      var message = ["NotAllowedError", "AbortError"].includes(error?.name) ? "Autenticazione annullata. Il valore resta nascosto." : error?.message || "Valore non disponibile.";
      var inline = box.querySelector("[data-secret-reveal-status]");
      if (inline) { inline.textContent = message; inline.hidden = false; }
      else showError(message);
    }
    finally { passkeyActionInFlight = false; if (button.isConnected) { button.disabled = false; button.removeAttribute("aria-busy"); } }
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
    clearVaultReveals();
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

  async function preloadControlCenterPages(urls, onProgress, options) {
    var queue = Array.isArray(urls) ? urls.slice() : portalPageUrlsForPreload();
    var workerCount = options && Number.isInteger(options.workerCount) && options.workerCount > 0
      ? options.workerCount
      : preloadWorkerCount;
    var generation = options ? options.generation : undefined;
    var total = queue.length;
    var completed = 0;
    var failed = [];
    if (!total) return { total: 0, completed: 0, failed: [] };
    var workers = Array.from({ length: Math.min(workerCount, queue.length) }, async function () {
      while (queue.length && isCurrentBackgroundPreload(generation)) {
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
    if (document.body.dataset.ccPreloading === "true") return;
    backgroundPreloadPending = true;
    if (backgroundPreloadHandle !== null || backgroundPreloadRunning) return;
    var generation = backgroundPreloadGeneration;
    var run = function () {
      backgroundPreloadHandle = null;
      if (!backgroundPreloadPending || !isCurrentBackgroundPreload(generation)) return;
      backgroundPreloadPending = false;
      backgroundPreloadRunning = true;
      var finish = function () {
        backgroundPreloadRunning = false;
        if (backgroundPreloadPending) scheduleControlCenterPreload();
      };
      preloadControlCenterPages(undefined, null, {
        generation: generation,
        workerCount: backgroundPreloadWorkerCount,
      }).then(finish, finish);
    };
    backgroundPreloadHandle = window.setTimeout(run, backgroundPreloadQuietMs);
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

  function filterApplications(root) {
    if (!root) return;
    var input = root.querySelector("[data-application-search-input]");
    var query = String(input ? input.value : "").trim().toLocaleLowerCase("it");
    var visible = 0;
    var changed = new Set(), positions = new Map();
    var rows = Array.from(root.querySelectorAll("[data-application-row]"));
    rows.forEach(function (row) { if (!row.hidden && row.getBoundingClientRect) positions.set(row, row.getBoundingClientRect().top); });
    rows.forEach(function (row) { var animation = portalMotions.get(row); if (animation) { animation.cancel(); portalMotions.delete(row); } });
    rows.forEach(function (row) {
      var matches = String(row.dataset.applicationSearch || "").toLocaleLowerCase("it").indexOf(query) !== -1;
      if (matches && row.hidden) changed.add(row);
      row.hidden = !matches;
      if (matches) visible += 1;
    });
    root.querySelectorAll("[data-app-folder-group]").forEach(function (group) {
      group.hidden = Boolean(query) && !group.querySelector("[data-application-row]:not([hidden])");
    });
    var empty = root.querySelector("[data-application-search-empty]");
    if (empty) empty.hidden = !query || visible > 0;
    rows.forEach(function (row) {
      if (row.hidden) return;
      if (changed.has(row)) animatePortalElement(row, [{ opacity: 0, transform: "translateY(4px)" }, { opacity: 1, transform: "translateY(0)" }]);
      else if (positions.has(row) && row.getBoundingClientRect) {
        var delta = positions.get(row) - row.getBoundingClientRect().top;
        if (Math.abs(delta) > 1) animatePortalElement(row, [{ transform: "translateY(" + delta + "px)" }, { transform: "translateY(0)" }]);
      }
    });
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
    if (payload.type === "file") {
      window.open(url.href, "_blank", "noopener,noreferrer");
      return true;
    }
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

  var readyVpsRestores = new WeakSet();

  function openProjectRestore(event) {
    var close = event.target.closest('[data-project-restore-close]');
    if (close) { close.closest('dialog').close(); return; }
    var button = event.target.closest('[data-project-restore-open]');
    if (!button) return;
    var form = button.closest('form'), dialog = button.closest('#project-backups').querySelector('[data-project-restore-dialog]');
    if (!form || !dialog) return;
    var previous = dialog.querySelector('[data-vps-restore]'), root = previous.cloneNode(true);
    previous.replaceWith(root);
    root.dataset.initialPoint = form.elements.backupRef.selectedOptions[0]?.dataset.manifestId || '';
    root.dataset.restoreMode = form.elements.restoreMode.value;
    root.querySelector('[data-restore-point]').closest('label').hidden = true;
    dialog.showModal(); startVpsRestore(root);
  }

  function startVpsRestore(target) {
    var root = target && target.matches && target.matches('[data-vps-restore]') ? target : document.querySelector('dialog[open] [data-vps-restore]');
    if (!root || readyVpsRestores.has(root)) return;
    readyVpsRestores.add(root);
    var projectId = root.getAttribute('data-project-id') || '';
    var status = root.querySelector('[data-restore-status]');
    var select = root.querySelector('[data-restore-point]');
    var review = root.querySelector('[data-restore-review]');
    var typed = root.querySelector('[data-restore-typed]');
    var confirmed = root.querySelector('[data-restore-confirm]');
    var apply = root.querySelector('[data-restore-apply]');
    var plan = null, busy = false;
    async function api(payload) {
      var headers = new Headers({ Accept: 'application/json' });
      if (payload) { headers.set('Content-Type', 'application/json'); addMutationHeaders(headers, 'POST'); }
      var response = await fetch(payload ? '/control/backups/production-restore' : '/control/backups/vps' + (projectId ? '?projectId=' + encodeURIComponent(projectId) : ''), { method: payload ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store', headers: headers, ...(payload ? { body: JSON.stringify(projectId ? Object.assign({}, payload, { projectId: projectId }) : payload) } : {}) });
      var value = await response.json();
      if (!root.isConnected) throw Error('Pannello sostituito.');
      if (redirectForReauthentication(response, value)) throw Error('Conferma la passkey prima del ripristino.');
      if (!response.ok) throw Error('Punto non disponibile o ripristino non attivato. Aggiorna il piano prima di riprovare.');
      return value;
    }
    function invalidate() { plan = null; review.hidden = true; confirmed.checked = false; typed.value = ''; apply.disabled = true; }
    select.addEventListener('change', invalidate);
    function enable() { apply.disabled = busy || !plan || !plan.enabled || !confirmed.checked || typed.value !== plan.manifestId; }
    typed.addEventListener('input', enable); confirmed.addEventListener('change', enable);
    root.querySelector('[data-restore-plan]').addEventListener('click', async function () {
      if (busy || !select.value) return; busy = true; invalidate();
      try {
        plan = (await api({ manifestId: select.value, restoreMode: root.dataset.restoreMode || 'all' })).details;
        root.querySelector('[data-restore-details]').textContent = JSON.stringify({ punto: plan.manifestId, data: plan.createdAt, contenuto: plan.resources, ripristina: plan.scope, preserva: plan.preserves, downtime: plan.downtimeRequired, rollbackLocale: plan.originalStateRetainedForRollback }, null, 2);
        review.hidden = false;
        status.textContent = plan.enabled ? 'Piano pronto. Verifica punto, portata e disponibilità della passkey prima di confermare.' : 'Piano disponibile; attivazione operativa del ripristino ancora disabilitata.';
      } catch (error) { status.textContent = error.message; } finally { busy = false; enable(); }
    });
    apply.addEventListener('click', async function () {
      if (busy || !plan || !confirmed.checked || typed.value !== plan.manifestId) return;
      busy = true; apply.disabled = true;
      var selected = plan; invalidate();
      try {
        var result = await api({ manifestId: selected.manifestId, restoreMode: selected.restoreMode, apply: true, reviewedManifestId: selected.manifestId, confirm: selected.confirmationRequired });
        status.textContent = 'Ripristino accodato (' + result.job.id + '). Il risultato non è ancora verificato. ' + (projectId ? 'L’applicazione sarà temporaneamente indisponibile.' : 'Il portale può disconnettersi durante il ripristino.');
      } catch (error) { status.textContent = error.message; } finally { busy = false; }
    });
    api().then(function (value) {
      var catalog = value.catalog;
      if (!catalog) throw Error('Catalogo VPS non configurato.');
      select.replaceChildren();
      catalog.manifests.forEach(function (point) { var option = document.createElement('option'); option.value = point.id; option.disabled = point.restoreCompatible === false; option.textContent = point.createdAt + ' · ' + point.id + (point.restoreCompatible === false ? ' · incompatibile con il profilo corrente' : ''); select.append(option); });
      var compatible = catalog.manifests.find(function (point) { return point.restoreCompatible !== false; });
      if (compatible) select.value = compatible.id;
      if (root.dataset.initialPoint && catalog.manifests.some(function (point) { return point.id === root.dataset.initialPoint && point.restoreCompatible !== false; })) select.value = root.dataset.initialPoint;
      status.textContent = catalog.manifests.length ? catalog.manifests.length + ' punti remoti verificati. Scegli un punto per il piano manuale.' : 'Nessun backup remoto verificato: ripristino non disponibile.';
      if (root.dataset.initialPoint) root.querySelector('[data-restore-plan]').click();
    }).catch(function (error) { if (root.isConnected) status.textContent = error.message; });
  }

  // Hosting controls are mounted into the existing generic application detail
  // screen. The server remains the source of truth for visibility and hosts.
  function hostingProjectFromDetail(detail) {
    var match = String(detail && detail.id || "").match(/^project-([a-z0-9][a-z0-9._-]{0,127})$/i);
    return match ? match[1] : "";
  }

  function hostingText(value, fallback) {
    return typeof value === "string" && value.trim() ? value.trim() : fallback;
  }

  function hostingRequest(path, payload) {
    var headers = new Headers({ Accept: "application/json" });
    if (payload) {
      headers.set("Content-Type", "application/json");
      addMutationHeaders(headers, "POST");
    }
    return fetch(path, {
      method: payload ? "POST" : "GET",
      credentials: "same-origin",
      cache: "no-store",
      headers: headers,
      ...(payload ? { body: JSON.stringify(payload) } : {}),
    }).then(async function (response) {
      var value = await response.json().catch(function () { return {}; });
      if (redirectForReauthentication(response, value)) throw reauthenticationRedirectError();
      if (!response.ok || value.ok === false) throw Error(value.message || value.error?.message || value.error || "Richiesta non riuscita.");
      return value;
    });
  }

  window.controlCenterRuntimeUpdates = Object.freeze({ request: hostingRequest, authenticate: authenticateWithSystemPasskey });

  function hostingModeLabel(mode) {
    return ({ public: "Pubblico", private: "Privato", offline: "Offline" })[mode] || "Da verificare";
  }

  function hostingJobLabel(state) {
    return ({ authorized: "Autorizzata", cloning: "Copia dei dati", available: "Disponibile", activation_failed: "Attivazione non riuscita", interrupted: "Interrotta", queued: "In coda", pending: "In coda", staged: "Preparazione", publishing: "Pubblicazione", activating: "Attivazione", running: "In corso", succeeded: "Completata", completed: "Completata", failed: "Non riuscita", cancelled: "Annullata", canceled: "Annullata" })[String(state || "").toLowerCase()] || hostingText(state, "Stato non disponibile");
  }

  function hostingPanelState(panel) {
    var state = projectHostingStates.get(panel);
    if (!state) { state = { operation: "", loading: false, verified: false, visibility: null, cloneActive: false, cancelPending: false }; projectHostingStates.set(panel, state); }
    return state;
  }

  function hostingFeedback(panel, phase, message, busy) {
    if (!panel.isConnected) return;
    panel.dataset.hostingPhase = phase;
    panel.setAttribute("aria-busy", busy ? "true" : "false");
    panel.querySelector("[data-hosting-message]").textContent = message;
    var progress = panel.querySelector("[data-hosting-progress]");
    progress.hidden = !busy;
    progress.setAttribute("aria-label", message || "Operazione hosting in corso");
  }

  function syncHostingControls(panel) {
    var state = hostingPanelState(panel);
    var busy = Boolean(state.operation || state.loading);
    panel.querySelectorAll("[data-hosting-mode]").forEach(function (button) {
      button.disabled = busy || state.cloneActive || !state.verified;
      button.setAttribute("aria-pressed", state.visibility && state.visibility.effective === button.dataset.hostingMode ? "true" : "false");
    });
    panel.querySelector("[data-hosting-clone]").disabled = busy || state.cloneActive || panel.dataset.cloneEligible !== "true";
    panel.querySelector("[data-hosting-refresh]").disabled = busy;
    panel.querySelectorAll("[data-hosting-cancel]").forEach(function (button) { button.disabled = busy || state.cancelPending; });
  }

  function renderHostingVisibility(panel, project, visibility) {
    var state = hostingPanelState(panel);
    var current = panel.querySelector("[data-hosting-current]");
    var verified = visibility.verified === true && ["public", "private", "offline"].includes(visibility.effective);
    state.verified = verified;
    if (verified) state.visibility = visibility;
    current.replaceChildren();
    var label = document.createElement("strong");
    label.textContent = state.visibility
      ? (verified ? "Visibilità attiva: " : "Ultimo stato verificato: ") + hostingModeLabel(state.visibility.effective)
      : "Visibilità effettiva non verificata";
    current.append(label);
    current.dataset.verified = verified ? "true" : "false";
    if (!verified) {
      var pending = document.createElement("span");
      pending.textContent = "La visibilità attuale deve ancora essere verificata dal servizio.";
      current.append(pending);
    }
    if (visibility.desired && visibility.desired !== visibility.effective) {
      var requested = document.createElement("span");
      requested.textContent = "Richiesta: " + hostingModeLabel(visibility.desired) + " · in attesa di verifica";
      current.append(requested);
    }
    if (project) {
      var production = document.createElement("span");
      production.textContent = "Produzione: " + hostingText(project.productionHostname || (project.production && project.production.hostname), "Host produzione non disponibile");
      current.append(production);
    }
    var relatedHosts = Array.isArray(visibility.hosts) ? visibility.hosts : [];
    if (relatedHosts.length > 1) {
      var hosts = document.createElement("span");
      hosts.textContent = "Host verificati: " + relatedHosts.map(function (host) { return hostingText(host && host.hostname, ""); }).filter(Boolean).join(", ");
      current.append(hosts);
    }
  }

  function mountProjectHosting(detail) {
    if (!detail || !detail.isConnected) return;
    var projectId = hostingProjectFromDetail(detail);
    var focus = detail.querySelector(".ops-project-detail-focus");
    if (!projectId || !focus) return;
    var existing = detail.querySelector("[data-project-hosting]");
    if (existing && existing.dataset.projectId === projectId) return;
    var panel = document.createElement("section");
    panel.className = "ops-project-detail-panel cc-project-hosting";
    panel.id = "project-hosting";
    panel.dataset.projectHosting = "";
    panel.dataset.projectId = projectId;
    panel.setAttribute("aria-labelledby", "cc-hosting-title-" + projectId);
    panel.innerHTML = '<div class="ops-project-detail-panel-head"><div><h3 id="cc-hosting-title-' + projectId + '">Visibilità e copia privata</h3><p class="cc-hosting-description">La visibilità effettiva viene riletta dal servizio dopo ogni modifica.</p></div><button type="button" class="ops-button secondary compact" data-hosting-refresh>Aggiorna</button></div>' +
      '<div class="cc-hosting-current" data-hosting-current role="status" aria-live="polite">Lettura dello stato verificato…</div>' +
      '<div class="cc-hosting-actions" role="group" aria-label="Imposta visibilità"><button type="button" class="ops-button secondary" data-hosting-mode="public" disabled>Pubblico</button><button type="button" class="ops-button secondary" data-hosting-mode="private" disabled>Privato</button><button type="button" class="ops-button secondary" data-hosting-mode="offline" disabled>Offline</button></div>' +
      '<div class="cc-hosting-copy"><div><strong>Copia privata</strong><p>Accesso con Cloudflare Access per il solo account owner. Dati isolati dalla produzione; email e pianificazioni disattivate.</p><p data-hosting-clone-unavailable hidden></p></div><button type="button" class="ops-button open" data-hosting-clone disabled>Crea copia privata</button></div>' +
      '<div class="cc-hosting-job" data-hosting-job hidden></div><p class="cc-hosting-message" data-hosting-message role="status" aria-live="polite"></p><div class="cc-hosting-progress" data-hosting-progress role="progressbar" aria-label="Lettura dello stato" hidden><span></span></div>';
    var slot = focus.querySelector("[data-project-hosting-slot]");
    if (slot) slot.replaceWith(panel);
    else focus.insertBefore(panel, focus.querySelector("#project-databases"));
    refreshProjectHosting(panel);
  }

  function refreshProjectHosting(panel, options) {
    if (!panel || !panel.isConnected) return Promise.resolve(null);
    var state = hostingPanelState(panel);
    if (state.operation && !(options && options.duringOperation)) return Promise.resolve(null);
    if (projectHostingLoads.has(panel)) return projectHostingLoads.get(panel);
    var projectId = panel.dataset.projectId;
    if (!projectId) return Promise.resolve(null);
    state.loading = true;
    if (!state.operation) hostingFeedback(panel, "loading", "Lettura della visibilità e degli host…", true);
    syncHostingControls(panel);
    var request = hostingRequest("/control/projects/" + encodeURIComponent(projectId) + "/hosting-status").then(function (value) {
      if (!panel.isConnected) return null;
      var project = value.project || {};
      renderHostingVisibility(panel, project, project.visibility || {});
      var clone = value.privateCopy || {};
      var cloneStatus = String(clone.status || "").toLowerCase();
      panel.dataset.targetHostname = hostingText(clone.hostname || clone.targetHostname, "");
      panel.dataset.cloneState = cloneStatus;
      panel.dataset.cloneJobId = hostingText(clone.jobId || clone.requestId, "");
      panel.dataset.cloneCancellable = clone.cancellable === true ? "true" : "false";
      panel.dataset.cloneEligible = clone.eligible === true ? "true" : "false";
      state.cloneActive = ["authorized", "queued", "pending", "staged", "publishing", "activating", "running", "cloning"].includes(cloneStatus);
      if (!state.cloneActive) state.cancelPending = false;
      renderProjectHostingJob(panel, clone);
      var unavailable = panel.querySelector("[data-hosting-clone-unavailable]");
      unavailable.hidden = clone.eligible === true;
      unavailable.textContent = clone.eligible === true ? "" : privateCopyUnavailableReason(clone.reason);
      if (!state.operation) {
        if (state.cloneActive) hostingFeedback(panel, "copy-progress", state.cancelPending ? "Annullamento richiesto. Attendo la conferma del servizio…" : "Copia privata: " + hostingJobLabel(cloneStatus) + ". Attendo il prossimo stato del servizio…", true);
        else if (["failed", "activation_failed", "interrupted"].includes(cloneStatus)) hostingFeedback(panel, "error", "La creazione della copia non è riuscita. Aggiorna per verificare il risultato.", false);
        else hostingFeedback(panel, state.verified ? "ready" : "unverified", state.verified ? "Stato aggiornato e verificato." : "Stato non ancora verificato. Aggiorna per riprovare.", false);
      }
      var previousPoll = projectHostingPolls.get(panel);
      if (previousPoll) window.clearTimeout(previousPoll);
      if (state.cloneActive) projectHostingPolls.set(panel, window.setTimeout(function () { projectHostingPolls.delete(panel); refreshProjectHosting(panel); }, 2500));
      else projectHostingPolls.delete(panel);
      return value;
    }).catch(function (error) {
      if (panel.isConnected && error.name !== "ReauthenticationRedirect") {
        renderHostingVisibility(panel, null, {});
        if (!state.operation) hostingFeedback(panel, "error", "Stato non disponibile. L’ultima visibilità verificata resta indicata sopra. Aggiorna per riprovare.", false);
      }
      return null;
    }).finally(function () { state.loading = false; projectHostingLoads.delete(panel); if (panel.isConnected) syncHostingControls(panel); });
    projectHostingLoads.set(panel, request);
    return request;
  }

  async function verifyHostingVisibility(panel, mode) {
    for (var attempt = 0; attempt < 4; attempt += 1) {
      var value = await refreshProjectHosting(panel, { duringOperation: true });
      if (!panel.isConnected) throw Error("Pannello sostituito.");
      var visibility = value && value.project && value.project.visibility;
      if (visibility && visibility.verified === true && visibility.effective === mode) return value;
      if (attempt < 3) await new Promise(function (resolve) { window.setTimeout(resolve, 1000); });
    }
    throw Error("La nuova visibilità non è ancora confermata. Rileggi lo stato prima di riprovare.");
  }

  function privateCopyUnavailableReason(reason) {
    var normalized = String(reason || "").trim().toLowerCase();
    var known = {
      already_exists: "Esiste già una copia privata per questa applicazione.",
      host_conflict: "L’host previsto per la copia è già in uso.",
      source_unverified: "Prima di creare la copia, verifica l’host e la sorgente dell’applicazione.",
      unsupported: "La configurazione attuale non consente di creare una copia privata.",
      "source not admitted by native application operator": "Questa applicazione non è ancora stata verificata per la copia privata.",
    };
    if (known[normalized]) return known[normalized];
    return "La copia privata non è disponibile per questa applicazione.";
  }

  function renderProjectHostingJob(panel, copy) {
    var box = panel.querySelector("[data-hosting-job]");
    var status = String(copy && copy.status || "").toLowerCase();
    var jobId = hostingText(copy && (copy.jobId || copy.requestId), "");
    if (!status || status === "absent") { box.hidden = true; box.replaceChildren(); return; }
    box.hidden = false;
    box.replaceChildren();
    var heading = document.createElement("strong");
    heading.textContent = "Copia privata · " + hostingJobLabel(status);
    box.append(heading);
    var host = document.createElement("span");
    host.textContent = "Host: " + hostingText(copy.hostname || copy.targetHostname, "In attesa del nome host verificato");
    box.append(host);
    if (jobId) {
      var id = document.createElement("small"); id.textContent = "Operazione " + jobId; box.append(id);
    }
    if (copy.cancellable === true && jobId) {
      var cancel = document.createElement("button"); cancel.type = "button"; cancel.className = "ops-button danger compact"; cancel.dataset.hostingCancel = jobId; cancel.textContent = "Annulla creazione"; box.append(cancel);
    }
  }

  function openHostingConfirm(panel, operation, mode) {
    var state = hostingPanelState(panel);
    if (state.operation || state.loading || state.cloneActive || !state.verified) return;
    state.operation = "review";
    syncHostingControls(panel);
    var projectId = panel.dataset.projectId;
    var target = panel.dataset.targetHostname;
    var dialog = document.createElement("dialog");
    dialog.className = "cc-restore-dialog cc-hosting-dialog";
    var title = operation === "clone" ? "Crea copia privata" : "Cambia visibilità";
    dialog.setAttribute("aria-label", title);
    var actionLabel = operation === "clone" ? "CLONE" : String(mode || "").toUpperCase();
    dialog.innerHTML = '<div class="cc-dialog-head"><h2>' + title + '</h2><button type="button" data-hosting-close aria-label="Chiudi">' + (document.querySelector('template[data-control-icon="xmark"]')?.innerHTML || "Chiudi") + '</button></div>' +
      (operation === "clone"
        ? '<dl class="cc-hosting-review"><dt>Host previsto</dt><dd data-hosting-target></dd><dt>Origine</dt><dd>La produzione resta separata dalla copia.</dd><dt>Dati</dt><dd>Archivio e credenziali isolati dalla produzione.</dd><dt>Invio email</dt><dd>Disattivato</dd><dt>Pianificazioni</dt><dd>Disattivate</dd><dt>Accesso</dt><dd>Cloudflare Access · solo account owner</dd></dl>'
        : '<p>La visibilità attuale rimane quella verificata finché il servizio non conferma il nuovo stato.</p><p class="cc-hosting-review-value">Nuovo stato richiesto: <strong>' + hostingModeLabel(mode) + '</strong></p><div class="cc-hosting-plan" data-hosting-plan hidden><strong>Piano per <span data-hosting-plan-host></span></strong><div class="cc-hosting-plan-hosts" data-hosting-plan-hosts></div><small data-hosting-plan-revision></small></div>') +
      '<label>Per confermare, scrivi <strong>' + actionLabel + '</strong><input type="text" data-hosting-typed autocomplete="off" spellcheck="false"></label><p data-hosting-dialog-message role="status" aria-live="polite"></p><div class="cc-hosting-progress" data-hosting-dialog-progress role="progressbar" aria-label="Preparazione modifica" hidden><span></span></div><div class="cc-hosting-dialog-actions"><button type="button" class="ops-button secondary" data-hosting-plan-retry hidden>Aggiorna piano e riprova</button><button type="button" class="ops-button secondary" data-hosting-close data-hosting-dismiss>Annulla</button><button type="button" class="ops-button open" data-hosting-apply disabled>' + (operation === "clone" ? "Crea copia privata" : "Richiedi modifica") + '</button></div>';
    if (operation === "clone") dialog.querySelector("[data-hosting-target]").textContent = target || "Host in attesa dei dati verificati";
    document.body.append(dialog);
    var input = dialog.querySelector("[data-hosting-typed]");
    var apply = dialog.querySelector("[data-hosting-apply]");
    var retry = dialog.querySelector("[data-hosting-plan-retry]");
    var message = dialog.querySelector("[data-hosting-dialog-message]");
    var reviewedPlan = null, busy = false, submitted = false, succeeded = false;
    function dialogFeedback(phase, text, loading) {
      dialog.dataset.hostingPhase = phase;
      dialog.setAttribute("aria-busy", loading ? "true" : "false");
      message.textContent = text;
      apply.textContent = ({ authenticating: "Conferma passkey…", applying: "Applicazione…", verifying: "Verifica…" })[phase] || (operation === "clone" ? "Crea copia privata" : "Richiedi modifica");
      var progress = dialog.querySelector("[data-hosting-dialog-progress]"); progress.hidden = !loading; progress.setAttribute("aria-label", text);
    }
    function updateApply() {
      apply.disabled = closingReview || busy || succeeded || (operation === "visibility" && !reviewedPlan) || input.value.trim() !== actionLabel;
      input.disabled = closingReview || busy || succeeded || (operation === "visibility" && !reviewedPlan);
      dialog.querySelectorAll("[data-hosting-close]").forEach(function (button) { button.disabled = closingReview || busy; });
    }
    var closingReview = false;
    function closeReview() {
      if (busy || closingReview) return;
      closingReview = true;
      if (!dialog.animate || window.matchMedia("(prefers-reduced-motion: reduce)").matches) { dialog.close(); return; }
      dialog.dataset.closing = "true";
      dialog.querySelectorAll("button,input").forEach(function (control) { control.disabled = true; });
      var leave = dialog.animate([{ opacity: 1, transform: "translateY(0) scale(1)" }, { opacity: 0, transform: "translateY(4px) scale(.995)" }], { duration: 140, easing: "cubic-bezier(.22,1,.36,1)" });
      var finish = function () { if (dialog.isConnected) dialog.close(); };
      leave.finished.then(finish, finish);
    }
    input.addEventListener("input", updateApply);
    dialog.querySelectorAll("[data-hosting-close]").forEach(function (button) { button.addEventListener("click", closeReview); });
    dialog.addEventListener("cancel", function (event) { event.preventDefault(); if (!busy) closeReview(); });
    dialog.addEventListener("close", function () {
      if (!succeeded && !busy) {
        state.operation = "";
        if (!submitted) hostingFeedback(panel, "cancelled", "Operazione annullata. Nessun comando inviato.", false);
        syncHostingControls(panel);
      }
      dialog.remove();
    }, { once: true });
    async function loadPlan() {
      if (closingReview || !dialog.isConnected) return;
      reviewedPlan = null; input.value = ""; retry.hidden = true;
      state.operation = "review";
      syncHostingControls(panel);
      dialogFeedback("planning", "Carico il piano aggiornato per questa modifica…", true);
      hostingFeedback(panel, "planning", "Preparazione del piano per " + hostingModeLabel(mode) + "…", true);
      updateApply();
      try {
        var value = await hostingRequest("/control/projects/" + encodeURIComponent(projectId) + "/hosting-plan?mode=" + encodeURIComponent(mode));
        if (closingReview || !dialog.isConnected) return;
        var plan = value.plan || {};
        if ((typeof plan.revision !== "string" && typeof plan.revision !== "number") || !plan.confirmationRequired) throw Error("Il piano non include revisione e conferma valide.");
        reviewedPlan = plan;
        var hostPlans = Array.isArray(plan.hostPlans) ? plan.hostPlans : [];
        var hostnames = Array.isArray(plan.hostnames) ? plan.hostnames : [];
        if (!hostnames.length) hostnames = hostPlans.map(function (hostPlan) { return hostPlan.hostname; });
        if (!hostnames.length && plan.hostname) hostnames = [plan.hostname];
        hostnames = hostnames.filter(function (hostname, index, list) { return typeof hostname === "string" && hostname.trim() && list.indexOf(hostname) === index; });
        dialog.querySelector("[data-hosting-plan-host]").textContent = hostnames.length > 1 ? hostnames.length + " host" : (hostnames[0] || "Host non disponibile");
        dialog.querySelector("[data-hosting-plan-revision]").textContent = "Revisione " + String(plan.revision);
        var hostList = dialog.querySelector("[data-hosting-plan-hosts]"); hostList.replaceChildren();
        hostnames.forEach(function (hostname) {
          var hostPlan = hostPlans.find(function (candidate) { return candidate && candidate.hostname === hostname; });
          var section = document.createElement("section"); section.className = "cc-hosting-plan-host";
          var heading = document.createElement("strong"); heading.textContent = hostname; section.append(heading);
          var actions = document.createElement("ul");
          (Array.isArray(hostPlan && hostPlan.actions) ? hostPlan.actions : []).forEach(function (item) { var row = document.createElement("li"); row.textContent = typeof item === "string" ? item : hostingText(item && (item.description || item.label), "Modifica prevista"); actions.append(row); });
          if (!actions.childElementCount) { var row = document.createElement("li"); row.textContent = "Applica lo stato " + hostingModeLabel(plan.requestedMode || mode) + " secondo il piano verificato."; actions.append(row); }
          section.append(actions); hostList.append(section);
        });
        if (!hostnames.length) {
          var actions = document.createElement("ul");
          (Array.isArray(plan.actions) ? plan.actions : []).forEach(function (item) { var row = document.createElement("li"); row.textContent = typeof item === "string" ? item : hostingText(item && (item.description || item.label), "Modifica prevista"); actions.append(row); });
          hostList.append(actions);
        }
        dialog.querySelector("[data-hosting-plan]").hidden = false;
        dialogFeedback("review", "Piano pronto. Controlla host e modifiche, poi conferma.", false);
        hostingFeedback(panel, "review", "Piano pronto. In attesa della tua conferma.", false);
        updateApply(); input.focus();
      } catch (error) {
        if (closingReview || !dialog.isConnected) return;
        retry.hidden = false;
        dialogFeedback("error", "Piano non disponibile. Aggiorna il piano per riprovare.", false);
        hostingFeedback(panel, "error", "Piano non disponibile. Nessuna modifica confermata.", false);
        updateApply();
      }
    }
    retry.addEventListener("click", function () {
      if (closingReview || !dialog.isConnected) return;
      if (operation === "visibility") loadPlan();
      else { retry.hidden = true; input.value = ""; dialogFeedback("review", "Controlla i dati e conferma nuovamente la richiesta.", false); updateApply(); }
    });
    apply.addEventListener("click", async function () {
      if (closingReview || !dialog.isConnected || apply.disabled || busy) return;
      busy = true; submitted = true; retry.hidden = true; state.operation = operation;
      updateApply(); syncHostingControls(panel);
      try {
        dialogFeedback("authenticating", "Conferma l’operazione con la passkey…", true);
        hostingFeedback(panel, "authenticating", "In attesa della conferma con passkey…", true);
        await authenticateWithSystemPasskey();
        dialogFeedback("applying", operation === "clone" ? "Invio della richiesta di copia privata…" : "Applico lo stato " + hostingModeLabel(mode) + " agli host previsti…", true);
        hostingFeedback(panel, "applying", operation === "clone" ? "Richiesta di copia privata in corso…" : "Modifica a " + hostingModeLabel(mode) + " in corso…", true);
        var path = "/control/projects/" + encodeURIComponent(projectId) + (operation === "clone" ? "/clone" : "/visibility");
        var payload = operation === "clone" ? { confirm: "CLONE-PRIVATE:" + projectId } : { mode: mode, expectedRevision: reviewedPlan.revision, confirm: reviewedPlan.confirmationRequired };
        await hostingRequest(path, payload);
        dialogFeedback("verifying", "Richiesta inviata. Verifico lo stato effettivo dal servizio…", true);
        hostingFeedback(panel, "verifying", "Verifica della visibilità effettiva e degli host…", true);
        if (operation === "visibility") await verifyHostingVisibility(panel, mode);
        else if (!await refreshProjectHosting(panel, { duringOperation: true })) throw Error("Stato della copia non ancora verificato.");
        succeeded = true;
        state.operation = "";
        var text = operation === "visibility" ? hostingModeLabel(mode) + " verificato dal servizio su tutti gli host." : "Richiesta di copia accodata. L’avanzamento viene aggiornato dal servizio.";
        dialogFeedback("success", text, false);
        hostingFeedback(panel, state.cloneActive ? "copy-progress" : "success", text, state.cloneActive);
        apply.hidden = true;
        dialog.querySelector("[data-hosting-dismiss]").textContent = "Chiudi";
        clearCache();
      } catch (error) {
        reviewedPlan = null; input.value = "";
        dialogFeedback("verifying", "Ricontrollo lo stato dopo la richiesta non confermata…", true);
        hostingFeedback(panel, "verifying", "Ricontrollo della visibilità effettiva…", true);
        await refreshProjectHosting(panel, { duringOperation: true });
        state.operation = "";
        var text = error.name === "ReauthenticationRedirect" ? "Conferma la passkey per continuare." : "Operazione non confermata. Rileggi il piano prima di riprovare; lo stato sopra riflette l’ultima verifica.";
        dialogFeedback("error", text, false);
        hostingFeedback(panel, "error", text, false);
        retry.hidden = false;
      } finally {
        busy = false;
        updateApply();
        if (panel.isConnected) syncHostingControls(panel);
      }
    });
    dialog.showModal();
    if (operation === "visibility") loadPlan();
    else { dialogFeedback("review", "Controlla i dati della copia prima di confermare.", false); updateApply(); input.focus(); }
  }

  async function cancelProjectHostingClone(panel, button) {
    var state = hostingPanelState(panel);
    if (button.disabled || state.operation || state.loading) return;
    state.operation = "cancel"; state.cancelPending = true;
    syncHostingControls(panel);
    try {
      hostingFeedback(panel, "authenticating", "Conferma l’annullamento con la passkey…", true);
      await authenticateWithSystemPasskey();
      hostingFeedback(panel, "cancelling", "Invio dell’annullamento della copia privata…", true);
      var id = button.dataset.hostingCancel;
      await hostingRequest("/control/projects/" + encodeURIComponent(panel.dataset.projectId) + "/clone/" + encodeURIComponent(id) + "/cancel", { confirm: "CANCEL-CLONE:" + id });
      hostingFeedback(panel, "verifying", "Verifico l’annullamento con il servizio…", true);
      var value = await refreshProjectHosting(panel, { duringOperation: true });
      if (!value) throw Error("Annullamento non ancora verificato.");
      var cancelled = ["cancelled", "canceled"].includes(String(value.privateCopy && value.privateCopy.status || "").toLowerCase());
      hostingFeedback(panel, cancelled ? "success" : "cancelling", cancelled ? "Creazione della copia annullata e verificata." : "Annullamento richiesto. Attendo la conferma del servizio…", !cancelled);
    } catch (error) {
      state.cancelPending = false;
      hostingFeedback(panel, "error", "Annullamento non confermato. Aggiorna lo stato prima di riprovare.", false);
    } finally { state.operation = ""; if (panel.isConnected) syncHostingControls(panel); }
  }

  function initProjectHosting() {
    function scan() { document.querySelectorAll(".ops-project-detail-screen[id^='project-']").forEach(mountProjectHosting); }
    scan();
    if (window.MutationObserver) new MutationObserver(scan).observe(document.body, { childList: true, subtree: true });
    document.addEventListener("click", function (event) {
      var refresh = event.target.closest("[data-hosting-refresh]");
      if (refresh && !refresh.disabled) { refreshProjectHosting(refresh.closest("[data-project-hosting]")); return; }
      var mode = event.target.closest("[data-hosting-mode]");
      if (mode && !mode.disabled) { openHostingConfirm(mode.closest("[data-project-hosting]"), "visibility", mode.dataset.hostingMode); return; }
      var clone = event.target.closest("[data-hosting-clone]");
      if (clone && !clone.disabled) { var panel = clone.closest("[data-project-hosting]"); if (panel.dataset.cloneEligible === "true") openHostingConfirm(panel, "clone"); return; }
      var cancel = event.target.closest("[data-hosting-cancel]");
      if (cancel && !cancel.disabled) cancelProjectHostingClone(cancel.closest("[data-project-hosting]"), cancel);
    });
  }


  var readyGlobalBackupControls = new WeakSet();

  function mountGlobalBackupControl(root) {
    if (readyGlobalBackupControls.has(root)) return;
    readyGlobalBackupControls.add(root);
    var toggle = root.querySelector("[data-backup-control-toggle]");
    var label = root.querySelector("[data-backup-control-label]");
    var status = root.querySelector("[data-backup-control-status]");
    var refresh = root.querySelector("[data-backup-control-refresh]");
    var control = null, request = null, queueActive = false, busy = false, timer = null, errorMessage = "";
    function render() {
      if (!root.isConnected) return;
      toggle.hidden = !control;
      toggle.disabled = busy || !control || !control.available || !queueActive || Boolean(request && ["queued", "running"].includes(request.status));
      toggle.setAttribute("aria-busy", busy || request && ["queued", "running"].includes(request.status) ? "true" : "false");
      if (control) {
        toggle.setAttribute("aria-checked", control.enabled ? "true" : "false");
        label.textContent = control.enabled ? "ON" : "OFF";
      }
      if (errorMessage) status.textContent = errorMessage;
      else if (!control) status.textContent = "Verifica dello stato…";
      else if (request && ["queued", "running", "done"].includes(request.status)) status.textContent = (request.enabled ? "Attivazione" : "Disattivazione") + " in attesa della conferma del server…";
      else if (!control.available) status.textContent = control.enabled ? "Attivi · Controllo non ancora disponibile." : "Backup non configurati.";
      else if (!queueActive) status.textContent = "Stato verificato: " + (control.enabled ? "attivi" : "disattivati") + ". Comando temporaneamente non disponibile.";
      else status.textContent = control.enabled ? "Attivi · Backup automatici e manuali abilitati." : "Disattivati · Backup automatici, manuali e invio remoto sospesi.";
      refresh.hidden = !errorMessage && !(request && ["queued", "running", "done"].includes(request.status));
    }
    function schedule(delay) {
      clearTimeout(timer);
      if (root.isConnected) timer = setTimeout(load, delay);
    }
    async function load() {
      if (!root.isConnected || document.hidden) return;
      try {
        var value = await hostingRequest("/control/backups/control" + (request ? "?requestId=" + encodeURIComponent(request.id) : ""));
        if (!root.isConnected) return;
        if (!value.control || typeof value.control.enabled !== "boolean") throw Error("Stato del server non disponibile.");
        control = value.control;
        queueActive = value.controlQueueActive === true;
        request = value.request || request;
        if (request && control.requestId === request.id && control.enabled === request.enabled) {
          request = null;
          errorMessage = "";
          clearCache();
        } else if (request && request.status === "failed") {
          errorMessage = "Richiesta non riuscita. Stato verificato: " + (control.enabled ? "attivi." : "disattivati.");
          request = null;
        }
        render();
        schedule(request ? 2000 : 30000);
      } catch (error) {
        if (!root.isConnected || error.name === "ReauthenticationRedirect") return;
        errorMessage = "Impossibile verificare lo stato dei backup. Ricontrolla prima di riprovare.";
        queueActive = false;
        render();
        schedule(request ? 5000 : 30000);
      }
    }
    toggle.addEventListener("click", async function () {
      if (toggle.disabled || !control) return;
      clearTimeout(timer);
      busy = true;
      errorMessage = "";
      render();
      try {
        var value = await hostingRequest("/control/backups/control", { enabled: !control.enabled, expectedRevision: control.revision });
        if (!root.isConnected) return;
        if (!value.accepted || !value.request) throw Error("Richiesta non accettata.");
        request = value.request;
      } catch (error) {
        if (!root.isConnected || error.name === "ReauthenticationRedirect") return;
        errorMessage = "Richiesta non riuscita. Lo stato dei backup resta quello verificato dal server.";
      } finally {
        busy = false;
        render();
        if (request) schedule(500);
      }
    });
    refresh.addEventListener("click", function () { errorMessage = ""; load(); });
    root.addEventListener("cc-backup-control-refresh", load);
    load();
  }

  function initGlobalBackupControls() {
    function scan() { document.querySelectorAll("[data-global-backup-control]").forEach(mountGlobalBackupControl); }
    scan();
    if (window.MutationObserver) new MutationObserver(scan).observe(document.body, { childList: true, subtree: true });
  }

  var hostMetricPanels = new WeakMap();
  function mountHostMetrics(root) {
    if (hostMetricPanels.has(root)) return;
    var timer = null, loading = false;
    var button = root.querySelector("[data-host-metrics-refresh]");
    var status = root.querySelector("[data-host-metrics-status]");
    function active() { return root.isConnected && !document.hidden && Boolean(root.closest("[data-overview-page]")); }
    function numeric(value) { return typeof value === "number" && Number.isFinite(value) && value >= 0; }
    function percent(value) { return new Intl.NumberFormat("it-IT", { maximumFractionDigits: 1 }).format(value) + "%"; }
    function bytes(value) {
      if (!numeric(value)) return "—";
      var units = ["B", "KiB", "MiB", "GiB", "TiB"], unit = 0;
      while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
      return new Intl.NumberFormat("it-IT", { maximumFractionDigits: 1 }).format(value) + " " + units[unit];
    }
    function amount(value) { return numeric(value) ? new Intl.NumberFormat("it-IT", { maximumFractionDigits: 2 }).format(value) : "—"; }
    function speed(value) { return numeric(value) ? bytes(value) + "/s" : "—"; }
    function pair(left, right, formatter) { return formatter(left) + " / " + formatter(right); }
    function table(id, rows, columns, cells) {
      var body = root.querySelector('[data-host-table="' + id + '"]');
      if (!body) return;
      body.replaceChildren();
      if (!rows.length) { var row = document.createElement("tr"), cell = document.createElement("td"); cell.colSpan = columns; cell.textContent = "Dati non disponibili dal collector host."; row.append(cell); body.append(row); return; }
      rows.forEach(function (item) { var row = document.createElement("tr"); cells(item).forEach(function (text) { var cell = document.createElement("td"); cell.textContent = text; row.append(cell); }); body.append(row); });
    }
    function detail(id, text) { var cell = root.querySelector('[data-host-detail="' + id + '"]'); if (cell) cell.textContent = text; }
    function render(value) {
      ["cpu", "memory", "disk"].forEach(function (id) {
        var metric = value[id] || {};
        var available = metric.available === true && numeric(metric.usedPercent);
        var main = root.querySelector('[data-host-metric="' + id + '"]');
        var detail = root.querySelector('[data-host-metric-detail="' + id + '"]');
        var meter = root.querySelector('[data-host-metric-meter="' + id + '"]');
        main.textContent = available ? percent(metric.usedPercent) : "—";
        detail.textContent = !available ? "Non disponibile" : id === "cpu" ? (numeric(metric.cores) ? metric.cores + " core · " : "") + "media 2 minuti" : bytes(metric.usedBytes) + " / " + bytes(metric.totalBytes);
        meter.hidden = !available;
        if (available) meter.value = Math.min(100, metric.usedPercent);
      });
      var network = value.network || {}, totals = network.totals || {};
      var networkNode = root.querySelector('[data-host-metric="network"]');
      var rxNode = networkNode.querySelector('[data-host-network-value="rx"]');
      var txNode = networkNode.querySelector('[data-host-network-value="tx"]');
      if (rxNode && txNode) {
        rxNode.textContent = network.available ? speed(totals.rxBytesPerSecond) : "—";
        txNode.textContent = network.available ? speed(totals.txBytesPerSecond) : "—";
      } else networkNode.textContent = network.available ? "Ricezione " + speed(totals.rxBytesPerSecond) + "\nInvio " + speed(totals.txBytesPerSecond) : "—";
      root.querySelector('[data-host-metric-detail="network"]').textContent = network.available ? "Media 2 minuti · interfacce host, bridge e tunnel esclusi" : "Non disponibile";
      var load = value.load || {}, swap = value.swap || {}, inodes = value.inodes || {}, io = value.diskIo || {}, ioTotals = io.totals || {}, processes = value.processes || {}, descriptors = value.fileDescriptors || {};
      detail("load", load.available ? [load.one, load.five, load.fifteen].map(amount).join(" / ") : "Non disponibile");
      var uptime = value.uptimeSeconds;
      detail("uptime", numeric(uptime) ? Math.floor(uptime / 86400) + " g · " + Math.floor(uptime % 86400 / 3600) + " h · " + Math.floor(uptime % 3600 / 60) + " min" : "Non disponibile");
      detail("processes", processes.available ? pair(processes.running, processes.blocked, amount) : "Non disponibile");
      detail("fileDescriptors", descriptors.available ? pair(descriptors.allocated, descriptors.maximum, amount) : "Non disponibile");
      detail("swap", swap.available ? pair(swap.usedBytes, swap.totalBytes, bytes) + (numeric(swap.usedPercent) ? " · " + percent(swap.usedPercent) : "") : "Non disponibile");
      detail("inodes", inodes.available ? pair(inodes.used, inodes.total, amount) + (numeric(inodes.usedPercent) ? " · " + percent(inodes.usedPercent) : "") : "Non disponibile");
      detail("ioTotals", io.available ? pair(ioTotals.readBytesPerSecond, ioTotals.writeBytesPerSecond, speed) : "Non disponibile");
      detail("ioOperations", io.available ? pair(ioTotals.readsPerSecond, ioTotals.writesPerSecond, amount) : "Non disponibile");
      table("network", network.available && Array.isArray(network.interfaces) ? network.interfaces : [], 7, function (row) { return [String(row.name || "—"), speed(row.rxBytesPerSecond), speed(row.txBytesPerSecond), bytes(row.rxBytes), bytes(row.txBytes), pair(row.rxErrors, row.txErrors, amount), pair(row.rxDrops, row.txDrops, amount)]; });
      table("diskIo", io.available && Array.isArray(io.devices) ? io.devices : [], 6, function (row) { return [String(row.name || "—"), speed(row.readBytesPerSecond), speed(row.writeBytesPerSecond), amount(row.readsPerSecond), amount(row.writesPerSecond), numeric(row.busyPercent) ? percent(row.busyPercent) : "—"]; });
      var pressure = value.pressure || {};
      root.querySelectorAll("[data-host-pressure]").forEach(function (cell) { var value = pressure[cell.dataset.hostPressure]; cell.textContent = pressure.available && numeric(value) ? percent(value) : "Non disponibile"; });
      root.ccHostMetricsSample = { metrics: value, observedAt: Date.now() };
      root.dispatchEvent(new CustomEvent("cc-host-metrics-sample", { detail: root.ccHostMetricsSample, bubbles: true }));
    }
    async function load() {
      clearTimeout(timer);
      if (!active() || loading) return;
      loading = true; if (button) button.disabled = true; root.setAttribute("aria-busy", "true");
      try {
        var value = await hostingRequest("/control/resources/host");
        if (!active()) return;
        if (value.scope !== "host" || value.source !== "prometheus-node-exporter") throw Error("Fonte host non verificata.");
        var age = Date.now() - Date.parse(value.capturedAt || "");
        if (!Number.isFinite(age) || age > 60000 || age < -5000) {
          render({}); if (status) status.textContent = "Metriche host non disponibili o non aggiornate. Il filesystem del Control Center non viene usato come sostituto.";
        } else {
          render(value);
          var any = [value.cpu, value.memory, value.disk, value.network, value.diskIo, value.load, value.swap, value.inodes, value.processes, value.pressure].some(function (metric) { return metric && metric.available === true; });
          if (status) status.textContent = any ? "Ultimo campione: " + new Date(value.capturedAt).toLocaleTimeString("it-IT") + " · Fonte host: node_exporter" : "Metriche host non disponibili. Riprova tra pochi secondi.";
        }
      } catch (error) {
        if (active() && error.name !== "ReauthenticationRedirect") { render({}); if (status) status.textContent = "Metriche host non disponibili. Aggiorna per riprovare."; }
      } finally {
        loading = false; if (button) button.disabled = false; root.setAttribute("aria-busy", "false");
        if (active()) timer = setTimeout(load, 2000);
      }
    }
    hostMetricPanels.set(root, { refresh: load });
    if (button) button.addEventListener("click", load);
    load();
  }
  function initHostMetrics() {
    function scan() { document.querySelectorAll("[data-host-metrics]").forEach(mountHostMetrics); }
    scan();
    if (window.MutationObserver) new MutationObserver(scan).observe(document.body, { childList: true, subtree: true });
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) return;
      document.querySelectorAll("[data-host-metrics]").forEach(function (root) { var state = hostMetricPanels.get(root); if (state) state.refresh(); });
      document.querySelectorAll("[data-global-backup-control]").forEach(function (root) { root.dispatchEvent(new Event("cc-backup-control-refresh")); });
    });
  }

  function init() {
    if (initialized) return;
    initialized = true;
    document.addEventListener("visibilitychange", function () { if (document.hidden) clearVaultReveals(); });
    window.addEventListener("pagehide", clearVaultReveals);
    document.body.dataset.ccEnhanced = "true";
    document.body.dataset.ccBootId = bootId;
    initProjectHosting();
    initGlobalBackupControls();
    initHostMetrics();
    if (window.location.hash.indexOf("#vault-runtime-") === 0) openVaultBinding(window.location.hash.slice(1));
    window.history.replaceState({ ccDynamic: true }, "", window.location.pathname + window.location.search + window.location.hash);
    restoreSidebarState({ instantOpsNav: true });
    positionOpsNavPill({ instant: true });
    startStatusTabs();
    document.addEventListener("click", openProjectRestore);
    startFileManagers();
    fitSingleLineText();
    animatePortalPage();
    storeCache(window.location.href, document.documentElement.outerHTML, "");
    runInitialControlCenterPreload();

    document.addEventListener("toggle", function (event) {
      var details = event.target;
      if (!(details instanceof HTMLDetailsElement) || !details.open || !details.closest(".cc-applications")) return;
      document.querySelectorAll(".cc-applications details[open]").forEach(function (other) { if (other !== details) other.open = false; });
    }, true);
    document.addEventListener("keydown", function (event) {
      if (event.key !== "Escape") return;
      var focusedDetails = event.target.closest ? event.target.closest(".cc-applications details[open]") : null;
      document.querySelectorAll(".cc-applications details[open]").forEach(function (details) { details.open = false; });
      if (focusedDetails) { event.preventDefault(); var summary = focusedDetails.querySelector("summary"); if (summary) summary.focus(); }
    });
    document.addEventListener("click", function (event) {
      var currentPopover = event.target.closest ? event.target.closest(".cc-applications details") : null;
      document.querySelectorAll(".cc-applications details[open]").forEach(function (details) { if (details !== currentPopover) details.open = false; });
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
      var vaultBindingLink = event.target.closest ? event.target.closest("[data-vault-binding-link]") : null;
      if (vaultBindingLink) {
        event.preventDefault();
        var bindingTarget = "vault-runtime-" + vaultBindingLink.getAttribute("data-vault-binding-link");
        openVaultBinding(bindingTarget);
        window.history.replaceState(window.history.state, "", window.location.pathname + window.location.search + "#" + bindingTarget);
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
      if (event.defaultPrevented) return;
      var form = event.target;
      if (!(form instanceof HTMLFormElement)) return;
      if (form.hasAttribute("data-vault-manage-form")) { event.preventDefault(); submitVaultManagement(form); return; }
      if (form.hasAttribute("data-vault-runtime-form")) { event.preventDefault(); submitVaultRuntime(form); return; }
      if (form.hasAttribute("data-app-folder-form")) {
        event.preventDefault();
        var button = event.submitter || form.querySelector("button[type=submit]");
        var payload = Object.fromEntries(new FormData(form).entries());
        if (button) button.disabled = true;
        hostingRequest(form.getAttribute("action"), payload).then(function (result) {
          var url = new URL(window.location.href);
          url.searchParams.set("section", "projects");
          if (form.hasAttribute("data-folder-create") || form.hasAttribute("data-folder-delete")) url.searchParams.set("folder", result.folderId);
          clearCache();
          return navigate(url, { history: "replace" });
        }).catch(function (error) {
          if (error.name !== "ReauthenticationRedirect") showError(error.message || "Impossibile aggiornare la cartella.");
        }).finally(function () { if (button && button.isConnected) button.disabled = false; });
        return;
      }
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
      var applicationSearch = event.target.closest ? event.target.closest("[data-application-search-input]") : null;
      if (applicationSearch) { filterApplications(applicationSearch.closest("[data-app-folders]")); return; }
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
