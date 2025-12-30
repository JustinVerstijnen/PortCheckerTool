let isLoading = false;

const PRESETS = [
  { port: 80, label: "HTTP" },
  { port: 443, label: "HTTPS" },
  { port: 22, label: "SSH" },
  { port: 21, label: "FTP" },
  { port: 25, label: "SMTP" },
  { port: 587, label: "SMTP Submission" },
  { port: 465, label: "SMTPS" },
  { port: 53, label: "DNS" },
  { port: 143, label: "IMAP" },
  { port: 993, label: "IMAPS" },
  { port: 1433, label: "MS SQL" },
  { port: 3389, label: "RDP" },
  { port: 3306, label: "MySQL" },
  { port: 5432, label: "PostgreSQL" },
  { port: 6379, label: "Redis" },
  { port: 25565, label: "Minecraft" },
  { port: 27017, label: "MongoDB" },
];

document.addEventListener("DOMContentLoaded", () => {
  const hostInput = document.getElementById("hostInput");
  const portInput = document.getElementById("portInput");
  const checkBtn = document.getElementById("checkPortBtn");
  const presetGrid = document.getElementById("presetGrid");

  // Safety: if HTML ids don't match, fail gracefully (no hard crash)
  if (!hostInput || !portInput || !checkBtn || !presetGrid) {
    console.error("Port checker: required elements not found in DOM.");
    return;
  }

  // Build preset buttons
  PRESETS.forEach(p => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "preset-btn";
    b.innerHTML = `${p.port} <small>${p.label}</small>`;
    b.addEventListener("click", () => {
      portInput.value = String(p.port);
      portInput.focus();
    });
    presetGrid.appendChild(b);
  });

  hostInput.focus();

  function onEnter(e) {
    if (e.key === "Enter") {
      e.preventDefault();
      if (!isLoading) checkPort();
    }
  }

  hostInput.addEventListener("keydown", onEnter);
  portInput.addEventListener("keydown", onEnter);

  checkBtn.addEventListener("click", (e) => {
    e.preventDefault();
    if (!isLoading) checkPort();
  });
});

function normalizeHost(input) {
  let h = (input || "").trim();
  if (!h) return "";
  h = h.replace(/^https?:\/\//i, "");
  h = h.split("/")[0].trim();
  h = h.replace(/\.$/, "");
  return h;
}

function isValidPort(p) {
  const n = Number(p);
  return Number.isInteger(n) && n >= 1 && n <= 65535;
}

function addRow(tbody, field, value) {
  const row = document.createElement("tr");
  const c1 = document.createElement("td");
  c1.textContent = field;
  const c2 = document.createElement("td");
  c2.textContent = value;
  row.appendChild(c1);
  row.appendChild(c2);
  tbody.appendChild(row);
}

async function checkPort() {
  isLoading = true;

  const hostInput = document.getElementById("hostInput");
  const portInput = document.getElementById("portInput");
  const checkBtn = document.getElementById("checkPortBtn");

  const loader = document.getElementById("loader");
  const resultsSection = document.getElementById("resultsSection");
  const tbody = document.querySelector("#resultTable tbody");

  // Safety guards
  if (!hostInput || !portInput || !checkBtn || !loader || !resultsSection || !tbody) {
    console.error("Port checker: missing UI elements for rendering.");
    isLoading = false;
    return;
  }

  checkBtn.disabled = true;
  loader.style.display = "flex";
  resultsSection.style.display = "none";
  tbody.innerHTML = "";

  const host = normalizeHost(hostInput.value);
  const port = portInput.value;

  hostInput.value = host;

  if (!host) {
    alert("Please enter a hostname or IP address.");
    loader.style.display = "none";
    checkBtn.disabled = false;
    isLoading = false;
    return;
  }

  if (!isValidPort(port)) {
    alert("Please enter a valid port number (1-65535).");
    loader.style.display = "none";
    checkBtn.disabled = false;
    isLoading = false;
    return;
  }

  try {
    const url = `/api/portcheck?host=${encodeURIComponent(host)}&port=${encodeURIComponent(port)}`;
    const resp = await fetch(url);

    const contentType = resp.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) {
      const text = await resp.text();
      addRow(tbody, "Error", "API did not return JSON (likely 404 / misdeployment).");
      addRow(tbody, "HTTP status", String(resp.status));
      addRow(tbody, "Response (first 200 chars)", text.slice(0, 200));
      resultsSection.style.display = "block";
      return;
    }

    const data = await resp.json();

    addRow(tbody, "Host", data.host ?? host);
    addRow(tbody, "Port", String(data.port ?? port));
    addRow(tbody, "Open", data.open === true ? "✅ Yes, the checked port is opened to the internet." : "❌ No, the checked port could not be found.");

    if (Array.isArray(data.resolved_ips)) addRow(tbody, "Resolved IPs", data.resolved_ips.join(", "));
    if (Array.isArray(data.blocked) && data.blocked.length) {
      addRow(tbody, "Blocked", data.blocked.map(b => `${b.ip} (${b.reason})`).join(" | "));
    }
    if (Array.isArray(data.attempts) && data.attempts.length) {
      addRow(
        tbody,
        "Attempts",
        data.attempts.map(a => `${a.ip}: ${a.open ? "open" : "closed"} (${a.latency_ms}ms${a.error ? `, ${a.error}` : ""})`).join(" | ")
      );
    }
    if (data.error) addRow(tbody, "Error", String(data.error));

    resultsSection.style.display = "block";
  } catch (e) {
    console.error(e);
    alert("An error occurred while checking the port.");
  } finally {
    loader.style.display = "none";
    checkBtn.disabled = false;
    isLoading = false;
  }
}
