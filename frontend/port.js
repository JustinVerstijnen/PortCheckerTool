document.getElementById("checkPortBtn").onclick = async () => {
const host = document.getElementById("hostInput").value;
const port = document.getElementById("portInput").value;
const res = await fetch(`/api/portcheck?host=${encodeURIComponent(host)}&port=${port}`);
const data = await res.json();
const tbody = document.querySelector("#resultTable tbody");
tbody.innerHTML = "";
for (const k in data) {
  const r = document.createElement("tr");
  r.innerHTML = `<td>${k}</td><td>${JSON.stringify(data[k])}</td>`;
  tbody.appendChild(r);
}
document.getElementById("resultsSection").style.display = "block";
};