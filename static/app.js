const form = document.getElementById("checkForm");
const statusEl = document.getElementById("status");
const runBtn = document.getElementById("runBtn");
const exportBtn = document.getElementById("exportBtn");
const tbody = document.getElementById("resultsBody");
const ipsEl = document.getElementById("ips");

let lastResults = [];

function setStatus(msg, kind = "") {
  statusEl.textContent = msg;
  statusEl.className = `status ${kind}`.trim();
}

function safe(v) {
  if (v === undefined || v === null) return "";
  return String(v);
}

function vtStatsToString(stats) {
  if (!stats || typeof stats !== "object") return "";
  const keys = ["malicious", "suspicious", "harmless", "undetected", "timeout"];
  const parts = keys.filter((k) => k in stats).map((k) => `${k}:${stats[k]}`);
  return parts.join(" ");
}

function clearTable() {
  tbody.innerHTML = "";
}

function renderEmpty(text) {
  tbody.innerHTML = `<tr class="empty"><td colspan="8">${text}</td></tr>`;
}

function abuseSummary(ip, a) {
  const score = a.abuseConfidenceScore ?? "";
  const reports = a.totalReports ?? "";
  const distinct = a.numDistinctUsers ?? "";
  let line1 = `${ip} results`;
  if (reports !== "") {
    line1 = `${ip} was found in AbuseIPDB. This IP was reported ${reports} times${distinct !== "" ? ` by ${distinct} distinct users` : ""}.`;
  }
  let line2 = "";
  if (score !== "") line2 = `Confidence of Abuse is ${score}%.`;
  const tor = a.isTor ? "This address is a Tor exit node. The owner/provider may not be behind the offending traffic." : "";
  return [line1, line2, tor].filter(Boolean).join(" ");
}

function fmtKeyVal(label, value, mono = false) {
  const v = safe(value);
  if (!v) return "";
  return `<div class="kv"><div class="k">${label}</div><div class="v ${mono ? "mono" : ""}">${v}</div></div>`;
}

function hostnamesList(hostnames) {
  if (!Array.isArray(hostnames) || hostnames.length === 0) return "";
  const items = hostnames.map((h) => `<li class="mono">${safe(h)}</li>`).join("");
  return `<div class="kv"><div class="k">Hostnames</div><div class="v"><ul class="list">${items}</ul></div></div>`;
}

function render(results, invalid) {
  clearTable();

  if (invalid && invalid.length) {
    setStatus(`Ignored invalid: ${invalid.join(", ")}`, "warn");
  } else {
    setStatus("");
  }

  if (!results.length) {
    renderEmpty("No results.");
    exportBtn.disabled = true;
    return;
  }

  const rows = results
    .map((r) => {
      const a = r.abuseipdb || {};
      const v = r.virustotal || {};
      const aScore = a.abuseConfidenceScore ?? "";
      const rep = v.reputation ?? "";
      const aErr = a.ok ? "" : safe(a.error || a.status);
      const vErr = v.ok ? "" : safe(v.error || v.status);
      const err = [aErr, vErr].filter(Boolean).join(" | ");

      const links = r.links || {};
      const abuseLink = links.abuseipdb ? `<a href="${links.abuseipdb}" target="_blank" rel="noreferrer">AbuseIPDB</a>` : "";
      const vtLink = links.virustotal ? `<a href="${links.virustotal}" target="_blank" rel="noreferrer">VirusTotal</a>` : "";

      const detailsId = `d-${safe(r.ip).replaceAll(":", "-").replaceAll(".", "-")}`;
      const abuseDetails = a.ok
        ? `
          <div class="details-block">
            <div class="details-title">AbuseIPDB</div>
            <div class="details-summary">${abuseSummary(r.ip, a)}</div>
            <div class="grid">
              ${fmtKeyVal("ISP", a.isp)}
              ${fmtKeyVal("Usage Type", a.usageType)}
              ${fmtKeyVal("ASN", a.asn, true)}
              ${fmtKeyVal("ASN Name", a.asnName)}
              ${fmtKeyVal("Domain", a.domain)}
              ${fmtKeyVal("Country", [a.countryName, a.countryCode].filter(Boolean).join(" "))}
              ${fmtKeyVal("Region", a.region)}
              ${fmtKeyVal("City", a.city)}
              ${fmtKeyVal("Last Reported", a.lastReportedAt, true)}
              ${fmtKeyVal("Whitelisted", a.isWhitelisted === true ? "true" : a.isWhitelisted === false ? "false" : "")}
            </div>
            ${hostnamesList(a.hostnames)}
          </div>
        `
        : `
          <div class="details-block">
            <div class="details-title">AbuseIPDB</div>
            <div class="details-summary badtext">${safe(aErr || "No data")}</div>
          </div>
        `;

      const vtDetails = v.ok
        ? `
          <div class="details-block">
            <div class="details-title">VirusTotal</div>
            <div class="grid">
              ${fmtKeyVal("Reputation", v.reputation, true)}
              ${fmtKeyVal("ASN", v.asn, true)}
              ${fmtKeyVal("AS Owner", v.as_owner)}
              ${fmtKeyVal("Country", v.country)}
              ${fmtKeyVal("Network", v.network, true)}
              ${fmtKeyVal("Tags", Array.isArray(v.tags) && v.tags.length ? v.tags.join(", ") : "")}
            </div>
            <div class="kv">
              <div class="k">Last analysis stats</div>
              <div class="v mono">${safe(vtStatsToString(v.last_analysis_stats))}</div>
            </div>
          </div>
        `
        : `
          <div class="details-block">
            <div class="details-title">VirusTotal</div>
            <div class="details-summary badtext">${safe(vErr || "No data")}</div>
          </div>
        `;

      return `
        <tr class="main-row">
          <td class="mono">${safe(r.ip)}</td>
          <td>${safe(aScore)}</td>
          <td>${safe(a.totalReports ?? "")}</td>
          <td>${safe(rep)}</td>
          <td class="mono">${safe(vtStatsToString(v.last_analysis_stats))}</td>
          <td>${abuseLink} ${vtLink}</td>
          <td><button class="btn tiny secondary" type="button" data-toggle="${detailsId}">View</button></td>
          <td class="small ${err ? "bad" : ""}">${safe(err)}</td>
        </tr>
        <tr class="details-row" id="${detailsId}" style="display:none">
          <td colspan="8">
            <div class="details-wrap">
              ${abuseDetails}
              ${vtDetails}
            </div>
          </td>
        </tr>
      `;
    })
    .join("");

  tbody.innerHTML = rows;
  exportBtn.disabled = false;
}

function toCsvValue(v) {
  const s = safe(v);
  if (/[,"\n]/.test(s)) return `"${s.replaceAll('"', '""')}"`;
  return s;
}

function exportCsv() {
  const header = [
    "ip",
    "abuse_ok",
    "abuse_score",
    "abuse_reports",
    "vt_ok",
    "vt_reputation",
    "vt_malicious",
    "vt_suspicious",
    "vt_harmless",
    "vt_undetected",
    "abuse_link",
    "vt_link",
    "errors",
  ];

  const lines = [header.join(",")];
  for (const r of lastResults) {
    const a = r.abuseipdb || {};
    const v = r.virustotal || {};
    const stats = v.last_analysis_stats || {};
    const links = r.links || {};
    const aErr = a.ok ? "" : safe(a.error || a.status);
    const vErr = v.ok ? "" : safe(v.error || v.status);
    const err = [aErr, vErr].filter(Boolean).join(" | ");

    const row = [
      r.ip,
      a.ok,
      a.abuseConfidenceScore ?? "",
      a.totalReports ?? "",
      v.ok,
      v.reputation ?? "",
      stats.malicious ?? "",
      stats.suspicious ?? "",
      stats.harmless ?? "",
      stats.undetected ?? "",
      links.abuseipdb ?? "",
      links.virustotal ?? "",
      err,
    ].map(toCsvValue);
    lines.push(row.join(","));
  }

  const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `ip-check-${new Date().toISOString().slice(0, 19).replaceAll(":", "-")}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const ips = ipsEl.value || "";

  runBtn.disabled = true;
  exportBtn.disabled = true;
  setStatus("Running checks…", "info");
  renderEmpty("Working…");

  try {
    const body = new FormData();
    body.set("ips", ips);
    const res = await fetch("/api/check", { method: "POST", body });
    const json = await res.json().catch(() => null);
    if (!res.ok) {
      const msg = json?.error || `Request failed (${res.status})`;
      setStatus(msg, "bad");
      renderEmpty(msg);
      lastResults = [];
      return;
    }

    lastResults = json.results || [];
    render(lastResults, json.invalid || []);
    setStatus(`Done. ${lastResults.length} checked.`, "ok");
  } catch (err) {
    const msg = `Error: ${err}`;
    setStatus(msg, "bad");
    renderEmpty(msg);
    lastResults = [];
  } finally {
    runBtn.disabled = false;
  }
});

exportBtn.addEventListener("click", exportCsv);

document.addEventListener("click", (e) => {
  const btn = e.target && e.target.closest ? e.target.closest("[data-toggle]") : null;
  if (!btn) return;
  const id = btn.getAttribute("data-toggle");
  const row = document.getElementById(id);
  if (!row) return;
  const open = row.style.display !== "none";
  row.style.display = open ? "none" : "";
  btn.textContent = open ? "View" : "Hide";
});
