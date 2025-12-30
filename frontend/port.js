let isLoading = false;

document.addEventListener("DOMContentLoaded", function () {
  const hostInput = document.getElementById("hostInput");
  const portInput = document.getElementById("portInput");
  const checkBtn = document.getElementById("checkPortBtn");

  hostInput.focus();

  function runIfReady(e) {
    if (e.key === "Enter") {
      e.preventDefault();
      if (!isLoading) checkPort();
    }
  }

  hostInput.addEventListener("keydown", runIfReady);
  portInput.addEventListener("keydown", runIfReady);

  checkBtn.addEventListener("click", function (e) {
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
    const data = await resp.json();

    // Basic summary
    addRow(tbody, "Host", data.host ?? host);
    addRow(tbody, "Port", String(data.port ?? port));
    addRow(tbody, "Open", (data.open === true) ? "✅ Yes" : "❌ No");
    addRow(tbody, "Timeout", (data.timeout_sec != null) ? `${data.timeout_sec}s` : "");

    // Resolution info
    if (Array.isArray(data.resolved_ips)) {
      addRow(tbody, "Resolved IPs", data.resolved_ips.join(", "));
    }

    // Blocked IPs (if any)
    if (Array.isArray(data.blocked) && data.blocked.length > 0) {
      const blockedText = data.blocked.map(b => `${b.ip} (${b.reason})`).join(" | ");
      addRow(tbody, "Blocked", blockedText);
    }

    // Attempts
    if (Array.isArray(data.attempts) && data.attempts.length > 0) {
      const attemptText = data.attempts
        .map(a => `${a.ip}: ${a.open ? "open" : "closed"} (${a.latency_ms}ms${a.error ? `, ${a.error}` : ""})`)
        .join(" | ");
      addRow(tbody, "Attempts", attemptText);
    }

    // API-level error message
    if (data.ok === false && data.error) {
      addRow(tbody, "Error", data.error);
    }

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
