function graph(id, label, series, unit = "%") {
  return `<div class="cc-overview-plot" data-overview-chart="${id}" data-overview-unit="${unit}">
    <div class="cc-overview-plot-scale"><span data-overview-ceiling>—</span><span>0${unit === "%" ? "%" : " B"}</span></div>
    <svg viewBox="0 0 600 160" preserveAspectRatio="none" role="img" aria-label="${label}: in attesa di dati">
      <path class="cc-overview-gridline" d="M0 20H600 M0 80H600 M0 140H600"></path>
      ${series.map((key, index) => `<path class="cc-overview-area series-${index}" data-overview-area="${key}" d=""></path><path class="cc-overview-line series-${index}" data-overview-line="${key}" d=""></path><circle class="cc-overview-point series-${index}" data-overview-point="${key}" r="3" hidden></circle>`).join("")}
    </svg>
    <span class="cc-overview-plot-empty" data-overview-chart-empty>In attesa del primo campione</span>
    <div class="cc-overview-time"><span data-overview-chart-start>Da apertura pagina</span><span>Ora</span></div>
  </div>`;
}

function utilization(id, label, subtitle) {
  return `<article class="cc-overview-card cc-overview-utilization">
    <div class="cc-overview-card-head"><h3>${label}</h3><span class="cc-overview-card-caption">${subtitle}</span></div>
    <strong class="cc-overview-number" data-host-metric="${id}">—</strong>
    <small class="cc-overview-caption" data-host-metric-detail="${id}">Lettura in corso</small>
    <meter min="0" max="100" value="0" data-host-metric-meter="${id}" aria-label="Utilizzo ${label}" hidden></meter>
    ${graph(id, `Utilizzo ${label}`, [id])}
  </article>`;
}

export function renderOverview() {
  return `<section class="cc-overview" data-overview-page>
    <section class="cc-overview-dashboard" data-host-metrics aria-label="Risorse della VPS">
      <div class="cc-overview-primary">${utilization("cpu", "CPU", "Media su 2 minuti")}${utilization("memory", "RAM", "Memoria utilizzata")}</div>
      <div class="cc-overview-capacity">
        <article class="cc-overview-card"><div class="cc-overview-card-head"><h3>Disco</h3><span class="cc-overview-card-caption">Filesystem principale</span></div><strong class="cc-overview-capacity-number" data-host-metric="disk">—</strong><small class="cc-overview-caption" data-host-metric-detail="disk">Spazio usato / totale</small><meter min="0" max="100" value="0" data-host-metric-meter="disk" aria-label="Utilizzo disco" hidden></meter></article>
        <article class="cc-overview-card"><div class="cc-overview-card-head"><h3>Inode</h3><span class="cc-overview-card-caption">File e directory</span></div><strong class="cc-overview-capacity-number" data-overview-value="inodes">—</strong><small class="cc-overview-caption" data-overview-detail="inodes">Inode usati / totali</small><meter min="0" max="100" value="0" data-overview-meter="inodes" aria-label="Utilizzo inode" hidden></meter></article>
        <article class="cc-overview-card cc-overview-swap"><div class="cc-overview-card-head"><h3>Swap</h3><span class="cc-overview-card-caption" data-overview-detail="swap">Memoria su disco</span></div><strong class="cc-overview-capacity-number" data-overview-value="swap">—</strong>${graph("swap", "Memoria swap utilizzata", ["swap"], "bytes")}</article>
      </div>
      <div class="cc-overview-throughput">
        <article class="cc-overview-card"><div class="cc-overview-card-head"><h3>Connessione</h3><span class="cc-overview-card-caption">Media su 2 minuti</span></div><strong class="cc-overview-network-number" data-host-metric="network">—</strong><small class="cc-overview-caption" data-host-metric-detail="network">Ricezione / invio</small><div class="cc-overview-legend"><span><i></i>Ricezione</span><span><i class="series-1"></i>Invio</span></div>${graph("network", "Velocità della connessione", ["networkRx", "networkTx"], "bytes/s")}</article>
        <article class="cc-overview-card"><div class="cc-overview-card-head"><h3>Attività disco</h3><span class="cc-overview-card-caption">Media su 2 minuti</span></div><div class="cc-overview-io-numbers"><div><span>Lettura</span><strong data-overview-value="diskRead">—</strong></div><div><span>Scrittura</span><strong data-overview-value="diskWrite">—</strong></div></div><small class="cc-overview-caption">Dispositivi fisici del server</small><div class="cc-overview-legend"><span><i></i>Lettura</span><span><i class="series-1"></i>Scrittura</span></div>${graph("diskIo", "Velocità delle letture e scritture disco", ["diskRead", "diskWrite"], "bytes/s")}</article>
      </div>
      <p class="cc-overview-history-note">Grafici dei campioni raccolti da quando apri questa pagina, fino a 2 minuti. Le interruzioni indicano dati non disponibili.</p>
      <section class="cc-host-detail"><h3>Pressione sulle risorse · PSI</h3><p class="cc-overview-caption">Percentuale del tempo di attesa o stallo negli ultimi 2 minuti.</p><dl class="cc-host-pressure">${[["cpuWaitingPercent", "CPU · attesa"], ["memoryWaitingPercent", "RAM · attesa"], ["memoryStalledPercent", "RAM · stallo"], ["ioWaitingPercent", "I/O · attesa"], ["ioStalledPercent", "I/O · stallo"]].map(([id, label]) => `<div><dt>${label}</dt><dd data-host-pressure="${id}">Non disponibile</dd></div>`).join("")}</dl></section>
    </section>
  </section>`;
}
