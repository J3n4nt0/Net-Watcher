// NetWatch - shared SNMP snapshot renderer.
// Depends on app.js (escapeHtml, formatBytes, formatBps).
// Every string that originates from a remote device is escaped.

const LAYER_LABELS = { 1: "Physical", 2: "Data link (L2)", 3: "Network (L3)", 4: "Transport", 7: "Application" };

function usageClass(pct) { return pct >= 90 ? "crit" : pct >= 75 ? "warn" : ""; }

function usageBar(pct) {
  const p = Math.max(0, Math.min(100, Number(pct) || 0));
  return `<div class="bar"><div class="bar-fill ${usageClass(p)}" style="width:${p}%"></div></div>`;
}

function statusBadge(status) {
  if (status === null || status === undefined) return `<span class="badge badge-unknown">—</span>`;
  const cls = status === "up" ? "badge-up"
    : ["down", "lowerLayerDown", "notPresent"].includes(status) ? "badge-down" : "badge-unknown";
  return `<span class="badge ${cls}">${escapeHtml(status)}</span>`;
}

function snmpStatCard(value, label) {
  return `<div class="card stat-card"><div class="stat-value" style="font-size:18px;">${escapeHtml(value)}</div>
          <div class="stat-label">${escapeHtml(label)}</div></div>`;
}

function renderSnmpDetail(data, opts = {}) {
  const s = data.system;
  const hr = data.host_resources;
  const ifs = data.interfaces || [];
  const hasRates = ifs.some(i => i.in_bps !== null && i.in_bps !== undefined);
  const visible = opts.onlyUp ? ifs.filter(i => i.oper_status === "up") : ifs;

  const stats = [
    snmpStatCard(s.name || data.host || "—", "Name"),
    snmpStatCard(s.vendor || "—", "Vendor"),
    snmpStatCard(s.uptime_human || "—", "Uptime"),
    snmpStatCard(`${data.interface_summary.up} / ${data.interface_summary.total}`, "Interfaces up"),
  ];
  if (hr.cpu_avg !== null && hr.cpu_avg !== undefined) stats.push(snmpStatCard(hr.cpu_avg + " %", "CPU load (avg)"));
  if (data.traffic) {
    stats.push(snmpStatCard(`↓ ${formatBps(data.traffic.in_bps)}  ↑ ${formatBps(data.traffic.out_bps)}`, "Traffic (all up interfaces)"));
  }

  const layers = (s.layers || []).map(n => LAYER_LABELS[n] || ("L" + n)).join(", ");
  const system = `
    <h2>System</h2>
    <div class="card"><dl class="kv">
      <dt>Description</dt><dd>${escapeHtml(s.description) || "—"}</dd>
      <dt>Object ID</dt><dd class="mono">${escapeHtml(s.object_id) || "—"}</dd>
      <dt>Location</dt><dd>${escapeHtml(s.location) || "—"}</dd>
      <dt>Contact</dt><dd>${escapeHtml(s.contact) || "—"}</dd>
      <dt>Layers served</dt><dd>${escapeHtml(layers) || "—"}</dd>
      ${data.elapsed_ms !== undefined ? `<dt>Query time</dt><dd>${escapeHtml(data.elapsed_ms)} ms</dd>` : ""}
    </dl></div>`;

  let interfaces = `<h2>Interfaces</h2><div class="card">
    <div class="toolbar-inline" style="margin-bottom:10px;">
      <label><input type="checkbox" style="width:auto;" ${opts.onlyUp ? "checked" : ""}
        onchange="window.snmpFilterChanged && window.snmpFilterChanged(this.checked)"> Only show interfaces that are up</label>
      <span class="status-text" style="margin:0;">${visible.length} of ${ifs.length} shown</span>
    </div>`;
  if (!ifs.length) {
    interfaces += `<div class="status-text">This host does not expose an interface table.</div></div>`;
  } else {
    const rows = visible.map(i => `
      <tr>
        <td>${statusBadge(i.oper_status)}</td>
        <td>${escapeHtml(i.name)}${i.alias ? `<div class="status-text" style="margin:0;">${escapeHtml(i.alias)}</div>` : ""}</td>
        <td>${escapeHtml(i.type) || "—"}</td>
        <td>${formatBps(i.speed_bps)}</td>
        <td class="mono">${escapeHtml(i.mac) || "—"}</td>
        ${hasRates ? `<td>${formatBps(i.in_bps)}</td><td>${formatBps(i.out_bps)}</td>` : ""}
        <td>${formatBytes(i.in_octets)}</td>
        <td>${formatBytes(i.out_octets)}</td>
        <td>${escapeHtml(i.in_errors ?? "—")} / ${escapeHtml(i.out_errors ?? "—")}</td>
      </tr>`).join("");
    interfaces += `<div class="table-wrap"><table style="min-width:820px;">
      <thead><tr><th>Status</th><th>Interface</th><th>Type</th><th>Speed</th><th>MAC</th>
        ${hasRates ? "<th>In (now)</th><th>Out (now)</th>" : ""}
        <th>In (total)</th><th>Out (total)</th><th>Errors in/out</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="10" class="status-text">No interfaces match the filter.</td></tr>`}</tbody>
    </table></div></div>`;
  }

  let addresses = "";
  if ((data.addresses || []).length) {
    addresses = `<h2>IP addresses</h2><div class="card"><div class="table-wrap"><table style="min-width:360px;">
      <thead><tr><th>Address</th><th>Netmask</th><th>Interface</th></tr></thead><tbody>
      ${data.addresses.map(a => {
        const iface = ifs.find(i => i.index === a.if_index);
        return `<tr><td class="mono">${escapeHtml(a.ip)}</td><td class="mono">${escapeHtml(a.netmask) || "—"}</td>
                <td>${iface ? escapeHtml(iface.name) : escapeHtml(a.if_index ?? "—")}</td></tr>`;
      }).join("")}</tbody></table></div></div>`;
  }

  let resources = "";
  if ((hr.cpu_loads || []).length || (hr.storage || []).length) {
    const cpu = (hr.cpu_loads || []).map((load, n) => `
      <div class="metric"><span>CPU ${n + 1}</span>${usageBar(load)}<span>${escapeHtml(load)}%</span></div>`).join("");
    const storage = (hr.storage || []).map(st => `
      <tr><td>${escapeHtml(st.descr)}</td><td>${escapeHtml(st.type)}</td>
          <td style="min-width:120px;">${usageBar(st.used_pct)}</td>
          <td>${escapeHtml(st.used_pct)}%</td>
          <td>${formatBytes(st.used_bytes)} / ${formatBytes(st.size_bytes)}</td></tr>`).join("");
    resources = `<h2>CPU &amp; storage</h2><div class="card">${cpu}
      ${storage ? `<div class="table-wrap" style="margin-top:10px;"><table style="min-width:520px;">
        <thead><tr><th>Name</th><th>Type</th><th>Usage</th><th></th><th>Used / total</th></tr></thead>
        <tbody>${storage}</tbody></table></div>` : ""}</div>`;
  } else {
    resources = `<h2>CPU &amp; storage</h2><div class="card"><div class="status-text">
      This agent does not expose the host-resources MIB (normal for most switches and routers).</div></div>`;
  }

  return `<div class="grid grid-4">${stats.join("")}</div>${system}${interfaces}${addresses}${resources}`;
}
