let isLoading = false;

document.addEventListener("DOMContentLoaded", function () {
    const hostInput = document.getElementById("hostInput");
    const portInput = document.getElementById("portInput");
    const checkBtn = document.getElementById("checkBtn");

    hostInput.focus();

    function runIfReady(event) {
        if (event.key === "Enter") {
            event.preventDefault();
            if (!isLoading) checkPort();
        }
    }

    hostInput.addEventListener("keydown", runIfReady);
    portInput.addEventListener("keydown", runIfReady);

    checkBtn.addEventListener("click", function (event) {
        event.preventDefault();
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
    const checkBtn = document.getElementById("checkBtn");
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

        // If backend isn't deployed, SWA returns HTML (404 page) and JSON parsing will fail.
        const contentType = resp.headers.get("content-type") || "";
        if (!contentType.includes("application/json")) {
            const text = await resp.text();
            addRow(tbody, "Error", "API did not return JSON. Most likely the Functions API is not deployed/connected.");
            addRow(tbody, "HTTP status", String(resp.status));
            addRow(tbody, "Response", text.slice(0, 200) + (text.length > 200 ? "…" : ""));
            resultsSection.style.display = "block";
            return;
        }

        const data = await resp.json();

        addRow(tbody, "Host", data.host ?? host);
        addRow(tbody, "Port", String(data.port ?? port));
        addRow(tbody, "Open", (data.open === true) ? "✅ Yes" : "❌ No");
        if (data.timeout_sec != null) addRow(tbody, "Timeout", `${data.timeout_sec}s`);

        if (Array.isArray(data.resolved_ips)) addRow(tbody, "Resolved IPs", data.resolved_ips.join(", "));
        if (Array.isArray(data.blocked) && data.blocked.length) {
            addRow(tbody, "Blocked", data.blocked.map(b => `${b.ip} (${b.reason})`).join(" | "));
        }
        if (Array.isArray(data.attempts) && data.attempts.length) {
            addRow(tbody, "Attempts", data.attempts.map(a =>
                `${a.ip}: ${a.open ? "open" : "closed"} (${a.latency_ms}ms${a.error ? `, ${a.error}` : ""})`
            ).join(" | "));
        }
        if (data.ok === false && data.error) addRow(tbody, "Error", data.error);

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
