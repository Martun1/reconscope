"use strict";

const GRADE_COLOR = { A: "var(--A)", B: "var(--B)", C: "var(--C)", D: "var(--D)", F: "var(--F)" };
const SEV_COLOR = {
  good: "var(--good)", info: "var(--info)", low: "var(--low)",
  medium: "var(--medium)", high: "var(--high)", critical: "var(--critical)",
};
const SEV_BG = {
  good: "rgba(53,208,127,.15)", info: "rgba(95,116,136,.2)", low: "rgba(86,195,214,.15)",
  medium: "rgba(242,193,78,.15)", high: "rgba(224,123,208,.15)", critical: "rgba(240,85,106,.18)",
};

const $ = (id) => document.getElementById(id);
let lastReport = null;

$("scanForm").addEventListener("submit", (e) => {
  e.preventDefault();
  runScan(false);
});
$("demoBtn").addEventListener("click", () => {
  $("domain").value = $("domain").value || "acme-shop.example";
  runScan(true);
});
$("exportBtn")?.addEventListener("click", exportJSON);
$("printBtn")?.addEventListener("click", () => window.print());

// Auto-run from the URL, e.g. /?domain=example.com&demo=1 — handy for sharing a
// result link or linking straight to the demo.
(function autorun() {
  const p = new URLSearchParams(location.search);
  const d = p.get("domain");
  if (!d) return;
  const demo = ["1", "true", "yes"].includes((p.get("demo") || "").toLowerCase());
  $("domain").value = d;
  if (!demo) $("authorized").checked = true;
  runScan(demo);
})();

async function runScan(demo) {
  const domain = $("domain").value.trim();
  const notice = $("notice");
  notice.hidden = true;

  if (!domain) { showNotice("Enter a domain first."); return; }
  if (!demo && !$("authorized").checked) {
    showNotice("Tick the authorization box to scan a live domain — or use the demo.");
    return;
  }

  $("empty").hidden = true;
  $("results").hidden = true;
  $("loading").hidden = false;
  $("scanBtn").disabled = true;

  try {
    const res = await fetch(`/api/scan?domain=${encodeURIComponent(domain)}&demo=${demo ? 1 : 0}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "scan failed");
    lastReport = data;
    render(data);
  } catch (err) {
    showNotice("Scan failed: " + err.message);
    $("empty").hidden = false;
  } finally {
    $("loading").hidden = true;
    $("scanBtn").disabled = false;
  }
}

function showNotice(msg) {
  const n = $("notice");
  n.textContent = msg;
  n.hidden = false;
}

function render(r) {
  // overall dial
  const g = r.overall_grade;
  $("ovGrade").textContent = g;
  $("ovGrade").style.color = GRADE_COLOR[g];
  $("ovScore").textContent = r.overall_score + " / 100";
  const circ = 327;
  const fg = $("dialFg");
  fg.style.stroke = GRADE_COLOR[g];
  fg.style.strokeDashoffset = circ * (1 - r.overall_score / 100);

  $("resDomain").textContent = r.domain + (r.meta.demo ? "  ·  demo data" : "");
  const bits = [];
  if (r.meta.addresses && r.meta.addresses.length) bits.push(r.meta.addresses.join(", "));
  if (r.meta.issuer) bits.push("cert: " + r.meta.issuer);
  if (typeof r.meta.subdomain_count === "number") bits.push(r.meta.subdomain_count + " subdomains");
  $("resMeta").textContent = bits.join("  ·  ");
  $("resTime").textContent = "scanned " + r.scanned_at.replace("T", " ") + (r.meta.registrar ? "  ·  " + r.meta.registrar : "");

  // category cards
  const grid = $("categories");
  grid.innerHTML = "";
  for (const cat of r.categories) grid.appendChild(cardFor(cat));

  // top fixes
  const fixes = topFixes(r);
  const fx = $("fixes"), list = $("fixList");
  list.innerHTML = "";
  if (fixes.length) {
    fx.hidden = false;
    for (const f of fixes) {
      const li = document.createElement("li");
      const sev = document.createElement("span");
      sev.className = "sev";
      sev.textContent = f.severity.toUpperCase();
      sev.style.color = SEV_COLOR[f.severity];
      sev.style.background = SEV_BG[f.severity];
      li.appendChild(sev);
      li.appendChild(document.createTextNode(f.recommendation));
      list.appendChild(li);
    }
  } else {
    fx.hidden = true;
  }

  $("results").hidden = false;
}

function cardFor(cat) {
  const card = document.createElement("div");
  card.className = "card";

  const head = document.createElement("div");
  head.className = "card-head";
  if (cat.error) {
    head.innerHTML = `<span class="chip" style="background:var(--info)">–</span>
      <h4>${esc(cat.title)}</h4><span class="caret">▸</span>`;
    const err = document.createElement("p");
    err.className = "err";
    err.textContent = "Not assessed — " + cat.error;
    card.appendChild(head);
    card.appendChild(err);
    return card;
  }

  const chip = document.createElement("span");
  chip.className = "chip";
  chip.textContent = cat.grade;
  chip.style.background = GRADE_COLOR[cat.grade];
  head.appendChild(chip);
  const h = document.createElement("h4");
  h.textContent = cat.title;
  head.appendChild(h);
  const caret = document.createElement("span");
  caret.className = "caret";
  caret.textContent = "▸";
  head.appendChild(caret);
  card.appendChild(head);

  const sum = document.createElement("p");
  sum.className = "card-sum";
  sum.textContent = cat.summary;
  card.appendChild(sum);

  const ul = document.createElement("ul");
  ul.className = "findings";
  for (const f of cat.findings) {
    const li = document.createElement("li");
    const sev = document.createElement("span");
    sev.className = "sev";
    sev.textContent = f.severity;
    sev.style.color = SEV_COLOR[f.severity];
    sev.style.background = SEV_BG[f.severity];
    li.appendChild(sev);
    const body = document.createElement("div");
    const msg = document.createElement("span");
    msg.className = "fmsg";
    msg.textContent = f.message;
    body.appendChild(msg);
    if (f.recommendation) {
      const rec = document.createElement("span");
      rec.className = "frec";
      rec.textContent = "→ " + f.recommendation;
      body.appendChild(rec);
    }
    li.appendChild(body);
    ul.appendChild(li);
  }
  card.appendChild(ul);

  // open cards that have something to fix by default
  const hasIssue = cat.findings.some((f) => !["good", "info"].includes(f.severity));
  if (hasIssue) card.classList.add("open");
  head.addEventListener("click", () => card.classList.toggle("open"));
  return card;
}

function topFixes(r) {
  const rank = { good: 0, info: 1, low: 2, medium: 3, high: 4, critical: 5 };
  const items = [];
  for (const cat of r.categories) {
    for (const f of cat.findings || []) {
      if (f.recommendation && rank[f.severity] >= 2) {
        items.push({ severity: f.severity, recommendation: f.recommendation, r: rank[f.severity] });
      }
    }
  }
  items.sort((a, b) => b.r - a.r);
  return items.slice(0, 6);
}

function exportJSON() {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `reconscope-${lastReport.domain}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}
