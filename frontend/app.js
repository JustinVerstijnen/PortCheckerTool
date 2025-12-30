let isLoading = false;
let currentMode = "single"; // "single" | "bulk"

document.addEventListener("DOMContentLoaded", function () {
    const domainInput = document.getElementById("domainInput");
    const checkBtn = document.getElementById("checkBtn");
    const bulkBtn = document.getElementById("bulkBtn");
    const exportBtn = document.getElementById("exportBtn");

    domainInput.focus();

    domainInput.addEventListener("keydown", function (event) {
        if (event.key === "Enter") {
            if (isLoading) return;
            event.preventDefault();
            checkDomain();
        }
    });

    checkBtn.addEventListener("click", function (event) {
        event.preventDefault();
        checkDomain();
    });

    if (bulkBtn) {
        bulkBtn.addEventListener("click", function (event) {
            event.preventDefault();
            openBulkModal();
        });
    }

    const bulkClose = document.getElementById("bulkClose");
    if (bulkClose) bulkClose.addEventListener("click", closeBulkModal);

    const bulkModal = document.getElementById("bulkModal");
    if (bulkModal) {
        bulkModal.addEventListener("click", function (e) {
            // close when clicking outside the dialog
            if (e.target === bulkModal) closeBulkModal();
        });
    }

    const bulkRunBtn = document.getElementById("bulkRunBtn");
    if (bulkRunBtn) bulkRunBtn.addEventListener("click", runBulkLookup);

    exportBtn.addEventListener("click", function (event) {
        event.preventDefault();
        exportReport();
    });
});

function openBulkModal() {
    const bulkModal = document.getElementById("bulkModal");
    const bulkTextarea = document.getElementById("bulkTextarea");
    if (!bulkModal || !bulkTextarea) return;

    bulkModal.style.display = "flex";
    setTimeout(() => bulkTextarea.focus(), 0);
}

function closeBulkModal() {
    const bulkModal = document.getElementById("bulkModal");
    if (!bulkModal) return;
    bulkModal.style.display = "none";
}

function normalizeDomain(input) {
    let d = (input || "").trim();
    if (!d) return "";
    // strip protocol/path if someone pastes a URL
    d = d.replace(/^https?:\/\//i, "");
    d = d.split("/")[0].trim();
    // strip trailing dot
    d = d.replace(/\.$/, "");
    return d.toLowerCase();
}

function isValidDomain(domain) {
    const domainPattern = /^(?!\-)([a-zA-Z0-9\-]{1,63}(?<!\-)\.)+[a-zA-Z]{2,}$/;
    return domainPattern.test(domain);
}

async function checkDomain() {
    isLoading = true;
    currentMode = "single";

    const checkBtn = document.getElementById("checkBtn");
    const bulkBtn = document.getElementById("bulkBtn");
    const exportBtn = document.getElementById("exportBtn");

    checkBtn.disabled = true;
    if (bulkBtn) bulkBtn.disabled = true;

    let domain = normalizeDomain(document.getElementById("domainInput").value);
    document.getElementById("domainInput").value = domain;

    if (!isValidDomain(domain)) {
        alert("The input does not appear to be a valid domain. Please check your entry.");
        isLoading = false;
        checkBtn.disabled = false;
        if (bulkBtn) bulkBtn.disabled = false;
        return;
    }

    const loader = document.getElementById("loader");
    const resultsSection = document.getElementById("resultsSection");
    const bulkResultsSection = document.getElementById("bulkResultsSection");
    const tbody = document.querySelector("#resultTable tbody");
    const extraInfo = document.getElementById("extraInfo");

    // Reset views
    if (bulkResultsSection) bulkResultsSection.style.display = "none";
    resultsSection.style.display = "none";
    exportBtn.style.display = "none";
    loader.style.display = "flex";

    // Clear existing content
    tbody.innerHTML = "";
    extraInfo.innerHTML = "";

    try {
        const response = await fetch(`/api/lookup?domain=${encodeURIComponent(domain)}`);
        const data = await response.json();

        // Fill the table
        for (const [type, record] of Object.entries(data)) {
            if (type === "NS" || type === "WHOIS") continue;

            const row = document.createElement("tr");
            const typeCell = document.createElement("td");
            typeCell.textContent = type;

            const statusCell = document.createElement("td");
            statusCell.textContent = record.status ? "✅" : "❌";

            const valueCell = document.createElement("td");
            if (Array.isArray(record.value)) {
                const list = document.createElement("ul");
                record.value.forEach((val) => {
                    const li = document.createElement("li");
                    li.textContent = val;
                    list.appendChild(li);
                });
                valueCell.appendChild(list);
            } else {
                valueCell.textContent = record.value;
            }

            row.appendChild(typeCell);
            row.appendChild(statusCell);
            row.appendChild(valueCell);
            tbody.appendChild(row);
        }

        // Confetti if all green
        let allGreen = true;
        for (const [type, record] of Object.entries(data)) {
            if (type === "NS" || type === "WHOIS") continue;
            if (!record.status) {
                allGreen = false;
                break;
            }
        }
        if (allGreen && typeof confetti === "function") {
            confetti({
                particleCount: 300,
                spread: 200,
                origin: { y: 0.6 },
            });
        }

        // Extra info: Nameservers (API returns an array)
        if (data.NS) {
            const nsBox = document.createElement("div");
            nsBox.className = "infobox";
            const listItems = Array.isArray(data.NS) ? data.NS.map((ns) => `<li>${ns}</li>`).join("") : "";
            nsBox.innerHTML = `<h3>Nameservers for ${domain}:</h3><ul>${listItems}</ul>`;
            extraInfo.appendChild(nsBox);
        }

        // Extra info: WHOIS (API returns registrar/creation_date or error)
        if (data.WHOIS) {
            const whoisBox = document.createElement("div");
            whoisBox.className = "infobox";

            if (data.WHOIS.error) {
                whoisBox.innerHTML = `<h3>WHOIS Information for ${domain}:</h3><p>${data.WHOIS.error}</p>`;
            } else {
                const registrar = data.WHOIS.registrar || "Not found";
                const creation = data.WHOIS.creation_date || "Not found";
                whoisBox.innerHTML = `<h3>WHOIS Information for ${domain}:</h3>
                <ul>
                    <li>Registrar: ${registrar}</li>
                    <li>Date of Registration: ${creation}</li>
                </ul>`;
            }

            extraInfo.appendChild(whoisBox);
        }
    } catch (e) {
        console.error(e);
        alert("An error occurred. My apologies for the inconvenience.");
    } finally {
        loader.style.display = "none";
        checkBtn.disabled = false;
        if (bulkBtn) bulkBtn.disabled = false;
        isLoading = false;

        resultsSection.style.display = "block";
        exportBtn.style.display = "inline-block";
    }
}

function statusIcon(status) {
    return status ? "✅" : "❌";
}

function formatValueForTitle(value) {
    if (Array.isArray(value)) return value.join("\n");
    return (value ?? "").toString();
}

async function runBulkLookup() {
    if (isLoading) return;

    const bulkTextarea = document.getElementById("bulkTextarea");
    const bulkRunBtn = document.getElementById("bulkRunBtn");
    const bulkBtn = document.getElementById("bulkBtn");
    const checkBtn = document.getElementById("checkBtn");
    const exportBtn = document.getElementById("exportBtn");

    const raw = (bulkTextarea?.value || "").split(/\r?\n/);
    const domains = raw
        .map(normalizeDomain)
        .filter((d) => d.length > 0);

    // de-duplicate while preserving order
    const seen = new Set();
    const uniqueDomains = [];
    for (const d of domains) {
        if (!seen.has(d)) {
            seen.add(d);
            uniqueDomains.push(d);
        }
    }

    const invalid = uniqueDomains.filter((d) => !isValidDomain(d));
    if (uniqueDomains.length === 0) {
        alert("Paste at least 1 domain (one per line).");
        return;
    }
    if (invalid.length > 0) {
        alert("Invalid domains found:\n\n" + invalid.slice(0, 25).join("\n"));
        return;
    }

    closeBulkModal();

    isLoading = true;
    currentMode = "bulk";

    checkBtn.disabled = true;
    if (bulkBtn) bulkBtn.disabled = true;
    if (bulkRunBtn) bulkRunBtn.disabled = true;

    const loader = document.getElementById("loader");
    const resultsSection = document.getElementById("resultsSection");
    const bulkResultsSection = document.getElementById("bulkResultsSection");
    const bulkProgressText = document.getElementById("bulkProgressText");
    const bulkTbody = document.querySelector("#bulkTable tbody");

    // Hide single results, show loader
    resultsSection.style.display = "none";
    exportBtn.style.display = "none";
    if (bulkResultsSection) bulkResultsSection.style.display = "none";
    loader.style.display = "flex";

    // Reset bulk table
    if (bulkTbody) bulkTbody.innerHTML = "";
    if (bulkProgressText) {
        bulkProgressText.style.display = "block";
        bulkProgressText.textContent = `0/${uniqueDomains.length} processed...`;
    }

    const recordCols = ["MX", "SPF", "DKIM", "DMARC", "MTA-STS", "DNSSEC"];

    try {
        for (let i = 0; i < uniqueDomains.length; i++) {
            const domain = uniqueDomains[i];

            let data = null;
            try {
                const response = await fetch(`/api/lookup?domain=${encodeURIComponent(domain)}`);
                data = await response.json();
            } catch (e) {
                data = null;
            }

            const row = document.createElement("tr");

            const domainCell = document.createElement("td");
            domainCell.textContent = domain;
            row.appendChild(domainCell);

            for (const col of recordCols) {
                const cell = document.createElement("td");
                if (data && data[col]) {
                    cell.textContent = statusIcon(!!data[col].status);
                    cell.title = formatValueForTitle(data[col].value);
                } else {
                    cell.textContent = "❌";
                    cell.title = "No data";
                }
                row.appendChild(cell);
            }

            // Nameservers column (API returns an array)
            const nsCell = document.createElement("td");
            if (data && data.NS) {
                if (Array.isArray(data.NS)) {
                    nsCell.textContent = data.NS.join(", ");
                    nsCell.title = data.NS.join("\n");
                } else {
                    nsCell.textContent = String(data.NS);
                    nsCell.title = String(data.NS);
                }
            } else {
                nsCell.textContent = "";
            }
            row.appendChild(nsCell);

            if (bulkTbody) bulkTbody.appendChild(row);

            if (bulkProgressText) {
                bulkProgressText.textContent = `${i + 1}/${uniqueDomains.length} processed...`;
            }
        }
    } finally {
        loader.style.display = "none";
        isLoading = false;

        checkBtn.disabled = false;
        if (bulkBtn) bulkBtn.disabled = false;
        if (bulkRunBtn) bulkRunBtn.disabled = false;

        if (bulkProgressText) bulkProgressText.style.display = "none";
        if (bulkResultsSection) bulkResultsSection.style.display = "block";
        exportBtn.style.display = "inline-block";
    }
}

async function exportReport() {
    const exportBtn = document.getElementById("exportBtn");
    if (exportBtn.disabled) return;

    let table = null;
    let filename = "";
    let label = "";
    let count = 0;
    let templateFile = "export-template-single.html";

    if (currentMode === "bulk") {
        table = document.querySelector("#bulkTable");
        count = document.querySelectorAll("#bulkTable tbody tr").length;
        label = `Bulk export (${count} domains)`;
        filename = "bulk_dns_report.html";
        templateFile = "export-template-bulk.html";
    } else {
        table = document.querySelector("#resultTable");
        const domain = normalizeDomain(document.getElementById("domainInput").value);
        if (!isValidDomain(domain)) {
            alert("The input does not appear to be a valid domain. Please check your entry.");
            return;
        }
        label = domain;
        filename = domain + "_dns_report.html";
        templateFile = "export-template-single.html";
    }

    let tableHTML = "";
    if (table) {
        const clone = table.cloneNode(true);
        clone.querySelectorAll(".tooltip").forEach((el) => el.remove());
        tableHTML = clone.outerHTML;
    }

    const template = await fetch(templateFile).then((r) => r.text());

    const filled = template
        .replaceAll("{{domain}}", label)
        .replaceAll("{{count}}", String(count))
        .replace("{{report_content}}", tableHTML);

    const blob = new Blob([filled], { type: "text/html;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", filename);
    link.style.display = "none";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

