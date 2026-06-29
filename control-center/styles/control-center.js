(function () {
  "use strict";

  var appSelector = ".cc-app-shell, .login-shell";
  var cacheLimit = 8;
  var sidebarStateKey = "platform-control-center-sidebar";
  var htmlCache = new Map();
  var activeRequest = null;
  var initialized = false;
  var bootId = "cc-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2);
  var resourceLiveTimer = null;
  var resourceLiveInFlight = false;

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

  function storeCache(url, html) {
    htmlCache.set(url, html);
    while (htmlCache.size > cacheLimit) {
      htmlCache.delete(htmlCache.keys().next().value);
    }
  }

  function clearCache() {
    htmlCache.clear();
  }

  function payloadFromForm(form, submitter) {
    var data = new FormData(form);
    if (submitter && submitter.name && !data.has(submitter.name)) {
      data.append(submitter.name, submitter.value || "");
    }
    return new URLSearchParams(data);
  }

  async function requestHtml(url, options) {
    var method = (options && options.method ? options.method : "GET").toUpperCase();
    var useCache = method === "GET";
    var cacheKey = url.href;
    if (useCache && htmlCache.has(cacheKey)) {
      return { html: htmlCache.get(cacheKey), url: cacheKey, fromCache: true };
    }

    if (activeRequest) activeRequest.abort();
    activeRequest = new AbortController();

    var headers = new Headers(options && options.headers ? options.headers : {});
    headers.set("Accept", "text/html,*/*;q=0.8");
    headers.set("X-Requested-With", "platform-control-center");

    var response = await fetch(url.href, {
      body: options ? options.body : undefined,
      credentials: "same-origin",
      headers: headers,
      method: method,
      redirect: "follow",
      signal: activeRequest.signal,
    });

    var contentType = response.headers.get("content-type") || "";
    if (contentType.indexOf("application/json") !== -1) {
      var payload = await response.json();
      if (!response.ok) throw new Error(payload.message || payload.error || "Request failed.");
      throw new Error(payload.message || "The server returned JSON instead of a page update.");
    }

    var html = await response.text();
    if (!response.ok) {
      throw new Error(extractError(html) || "Request failed.");
    }

    var finalUrl = response.url || url.href;
    if (useCache) {
      storeCache(cacheKey, html);
      storeCache(finalUrl, html);
    }
    return { html: html, url: finalUrl, fromCache: false };
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
      if (attribute.name.indexOf("data-cc-") === 0 && attribute.name !== "data-cc-navigation" && attribute.name !== "data-cc-enhanced" && attribute.name !== "data-cc-boot-id") {
        document.body.removeAttribute(attribute.name);
      }
    });
    Array.from(nextBody.attributes).forEach(function (attribute) {
      if (attribute.name.indexOf("data-cc-") === 0) {
        document.body.setAttribute(attribute.name, attribute.value);
      }
    });
    document.body.dataset.ccEnhanced = "true";
    document.body.dataset.ccBootId = bootId;
  }

  function applyHtml(html, finalUrl, mode) {
    var parsed = new DOMParser().parseFromString(html, "text/html");
    var nextBody = parsed.body;
    if (!nextBody || !parsed.querySelector(appSelector)) {
      window.location.assign(finalUrl);
      return;
    }

    document.title = parsed.title || document.title;
    syncBodyAttributes(nextBody);
    document.body.replaceChildren.apply(
      document.body,
      Array.from(nextBody.childNodes).map(function (node) {
        return document.importNode(node, true);
      })
    );

    var target = new URL(finalUrl, window.location.href);
    var historyUrl = target.pathname + target.search + target.hash;
    if (mode === "replace") {
      window.history.replaceState({ ccDynamic: true }, "", historyUrl);
    } else if (mode === "push" && historyUrl !== window.location.pathname + window.location.search + window.location.hash) {
      window.history.pushState({ ccDynamic: true }, "", historyUrl);
    }

    setBusy(false);
    restoreSidebarState();
    startResourceLiveUpdates();
    startStatusTabs();
    scrollAfterRender(target);
    document.dispatchEvent(new CustomEvent("cc:navigation-complete", { detail: { url: target.href } }));
  }

  function setText(node, value) {
    if (!node) return;
    var next = value == null ? "" : String(value);
    if (node.textContent !== next) node.textContent = next;
  }

  function applyMetricTone(node, tone) {
    if (!node) return;
    ["good", "info", "warn", "bad", "error", "pending"].forEach(function (name) {
      node.classList.remove(name);
    });
    node.classList.add(tone || "info");
  }

  function updateResourceCards(cards) {
    if (!cards || typeof cards !== "object") return;
    Object.keys(cards).forEach(function (key) {
      var card = document.querySelector('[data-resource-card="' + key + '"]');
      var item = cards[key] || {};
      if (!card) return;
      setText(card.querySelector("strong"), item.status);
      setText(card.querySelector("small"), item.summary);
      applyMetricTone(card, item.tone);
    });
  }

  function updateResourceSummaries(summaries) {
    if (!summaries || typeof summaries !== "object") return;
    Object.keys(summaries).forEach(function (key) {
      var box = document.querySelector('[data-resource-summary="' + key + '"]');
      var item = summaries[key] || {};
      if (!box) return;
      setText(box.querySelector("strong"), item.status);
      setText(box.querySelector("em"), item.detail);
    });
  }

  function findResourceRow(applicationId) {
    var id = String(applicationId || "");
    return Array.from(document.querySelectorAll("[data-resource-row]")).find(function (row) {
      return row.getAttribute("data-resource-row") === id;
    });
  }

  function updateResourceRows(rows) {
    if (!Array.isArray(rows)) return;
    rows.forEach(function (item) {
      var row = findResourceRow(item.applicationId);
      if (!row) return;
      var status = row.querySelector('[data-resource-cell="status"] .ops-state');
      setText(status, item.status);
      ["cpu", "memory", "disk", "containers", "measuredFrom", "limits"].forEach(function (key) {
        setText(row.querySelector('[data-resource-cell="' + key + '"]'), item[key]);
      });
    });
  }

  function applyResourcePayload(payload) {
    if (!payload || typeof payload !== "object") return;
    updateResourceCards(payload.cards);
    updateResourceSummaries(payload.summaries);
    updateResourceRows(payload.rows);
    setText(document.querySelector("[data-resource-captured-at]"), payload.capturedAt);
  }

  function stopResourceLiveUpdates() {
    if (resourceLiveTimer) {
      window.clearInterval(resourceLiveTimer);
      resourceLiveTimer = null;
    }
    resourceLiveInFlight = false;
  }

  function startResourceLiveUpdates() {
    stopResourceLiveUpdates();
    var root = document.querySelector("[data-resource-live]");
    if (!root) return;
    var url = sameOriginUrl(root.getAttribute("data-resource-live-url") || "/control/resources/summary");
    if (!url) return;
    var refreshMs = Number(root.getAttribute("data-resource-refresh-ms") || 1000);
    var intervalMs = Number.isFinite(refreshMs) ? Math.max(1000, refreshMs) : 1000;
    var poll = async function () {
      if (resourceLiveInFlight || !document.querySelector("[data-resource-live]")) return;
      resourceLiveInFlight = true;
      try {
        var response = await fetch(url.href, {
          cache: "no-store",
          credentials: "same-origin",
          headers: { Accept: "application/json" },
        });
        if (response.ok) applyResourcePayload(await response.json());
      } catch {
        // Resource polling is best-effort; the static page remains usable.
      } finally {
        resourceLiveInFlight = false;
      }
    };
    poll();
    resourceLiveTimer = window.setInterval(poll, intervalMs);
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

  function restoreSidebarState() {
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

  async function navigate(url, options) {
    if (!url || !canRenderPath(url)) return false;
    var historyMode = options && options.history ? options.history : "push";
    setBusy(true);
    try {
      var result = await requestHtml(url, { method: "GET" });
      applyHtml(result.html, result.url || url.href, historyMode);
      return true;
    } catch (error) {
      setBusy(false);
      if (error && error.name === "AbortError") return true;
      showError(error && error.message ? error.message : "Navigation failed.");
      return false;
    }
  }

  async function submitForm(form, submitter) {
    var method = String(form.method || "GET").toUpperCase();
    var action = sameOriginUrl(form.getAttribute("action") || window.location.href);
    if (!action || !canRenderPath(action) && action.pathname.indexOf("/actions/") !== 0) return false;

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
      applyHtml(result.html, result.url || window.location.href, "push");
      return true;
    } catch (error) {
      setBusy(false);
      if (error && error.name === "AbortError") return true;
      showError(error && error.message ? error.message : "Action failed.");
      return false;
    }
  }

  function prefetch(url) {
    if (!url || !canRenderPath(url) || htmlCache.has(url.href)) return;
    requestHtml(url, { method: "GET" }).catch(function () {});
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

  function init() {
    if (initialized) return;
    initialized = true;
    document.body.dataset.ccEnhanced = "true";
    document.body.dataset.ccBootId = bootId;
    window.history.replaceState({ ccDynamic: true }, "", window.location.pathname + window.location.search + window.location.hash);
    restoreSidebarState();
    startResourceLiveUpdates();
    startStatusTabs();

    document.addEventListener("click", function (event) {
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
      var toggle = event.target.closest ? event.target.closest("[data-cc-sidebar-toggle]") : null;
      if (toggle) {
        event.preventDefault();
        toggleSidebarGroup(toggle);
        return;
      }
      if (!isPlainClick(event)) return;
      var url = linkFromEvent(event);
      if (!url) return;
      event.preventDefault();
      navigate(url, { history: "push" });
    });

    document.addEventListener("submit", function (event) {
      var form = event.target;
      if (!(form instanceof HTMLFormElement)) return;
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

    document.addEventListener("mouseover", function (event) {
      var url = linkFromEvent(event);
      if (url) prefetch(url);
    });

    document.addEventListener("focusin", function (event) {
      var url = linkFromEvent(event);
      if (url) prefetch(url);
    });

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
