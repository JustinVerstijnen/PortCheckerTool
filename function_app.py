# Module imports
import azure.functions as func
import json
import dns.resolver
import dns.exception
import requests
import whois
import socket
import time
import ipaddress

app = func.FunctionApp()

def record_not_found(record_type, domain):
    return f"{record_type} record not found: {domain}"

def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def _is_ip_allowed(ip_str: str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, "Invalid IP address"

    if (
        ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local or
        ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified or
        ip_str == "169.254.169.254"
    ):
        return False, "IP blocked"
    return True, ""

def _resolve_host_to_ips(host: str):
    ips = set()
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        for info in infos:
            ips.add(info[4][0])
    except Exception:
        pass
    return sorted(list(ips))

def _tcp_connect(ip, port, timeout):
    start = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            latency = (time.perf_counter() - start) * 1000
            return True, round(latency, 2), ""
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000
        return False, round(latency, 2), str(e)

@app.route(route="portcheck")
def portcheck(req: func.HttpRequest) -> func.HttpResponse:
    host = (req.params.get("host") or "").strip()
    port_raw = (req.params.get("port") or "").strip()

    if not host or not port_raw:
        return func.HttpResponse("host and port required", status_code=400)

    try:
        port = int(port_raw)
        if port < 1 or port > 65535:
            raise ValueError()
    except ValueError:
        return func.HttpResponse("invalid port", status_code=400)

    ips = [host] if _is_ip_literal(host) else _resolve_host_to_ips(host)
    if not ips:
        return func.HttpResponse(json.dumps({"open": False, "error": "resolution failed"}),
                                 mimetype="application/json")

    results = []
    for ip in ips:
        allowed, reason = _is_ip_allowed(ip)
        if not allowed:
            results.append({"ip": ip, "blocked": reason})
            continue
        ok, latency, err = _tcp_connect(ip, port, 3)
        results.append({"ip": ip, "open": ok, "latency_ms": latency, "error": err})

        if ok:
            return func.HttpResponse(json.dumps({
                "host": host, "port": port, "open": True, "attempts": results
            }), mimetype="application/json")

    return func.HttpResponse(json.dumps({
        "host": host, "port": port, "open": False, "attempts": results
    }), mimetype="application/json")
