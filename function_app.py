# Module imports
import azure.functions as func
import json
import dns.resolver
import dns.exception
import requests
import whois

# NEW imports for port checking
import socket
import time
import ipaddress

# Function settings
app = func.FunctionApp()

def record_not_found(record_type, domain):
    return f"{record_type} record not found: {domain}"

def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def _is_ip_allowed(ip_str: str) -> (bool, str):
    """
    Blocks private/loopback/link-local/multicast/reserved ranges to reduce SSRF / internal scanning risk.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, "Invalid IP address"

    if ip_obj.is_loopback:
        return False, "Loopback IP blocked"
    if ip_obj.is_private:
        return False, "Private IP blocked"
    if ip_obj.is_link_local:
        return False, "Link-local IP blocked"
    if ip_obj.is_multicast:
        return False, "Multicast IP blocked"
    if ip_obj.is_reserved:
        return False, "Reserved IP blocked"
    if ip_obj.is_unspecified:
        return False, "Unspecified IP blocked"

    # Explicitly block common cloud metadata IPs (defense-in-depth)
    if ip_str == "169.254.169.254":
        return False, "Metadata IP blocked"

    return True, ""

def _resolve_host_to_ips(host: str):
    """
    Resolve hostname to IPs (A/AAAA) using system resolver. Returns a deduped list.
    """
    ips = set()
    try:
        # getaddrinfo handles A + AAAA; returns tuples with sockaddr
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        for info in infos:
            sockaddr = info[4]
            ip = sockaddr[0]
            ips.add(ip)
    except Exception:
        # If resolution fails, keep empty list (handled by caller)
        pass
    return sorted(list(ips))

def _tcp_connect(ip: str, port: int, timeout_sec: float) -> (bool, float, str):
    """
    Attempt a TCP connect to ip:port. Returns (open, latency_ms, error_message)
    """
    start = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout_sec):
            latency_ms = (time.perf_counter() - start) * 1000.0
            return True, latency_ms, ""
    except Exception as e:
        latency_ms = (time.perf_counter() - start) * 1000.0
        return False, latency_ms, str(e)

@app.route(route="lookup")
def dns_lookup(req: func.HttpRequest) -> func.HttpResponse:
    domain = req.params.get('domain')
    if not domain:
        return func.HttpResponse("Please pass a domain on the query string", status_code=400)

    results = {}

    # MX lookup
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_valid = len(mx_records) > 0
        results['MX'] = {
            "status": mx_valid,
            "value": [str(r.exchange) for r in mx_records]
        }
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        results['MX'] = {"status": False, "value": record_not_found("MX", domain)}
    except Exception as e:
        results['MX'] = {"status": False, "value": str(e)}

    # SPF lookup (TXT record)
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        spf_records = []
        for r in txt_records:
            full_record = ''.join([b.decode('utf-8') for b in r.strings])
            if full_record.startswith('v=spf1'):
                spf_records.append(full_record)

        if spf_records:
            valid_spf = any('-all' in r for r in spf_records)
            results['SPF'] = {"status": valid_spf, "value": spf_records}
        else:
            results['SPF'] = {"status": False, "value": record_not_found("SPF", domain)}
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        results['SPF'] = {"status": False, "value": record_not_found("SPF", domain)}
    except Exception as e:
        results['SPF'] = {"status": False, "value": str(e)}

    # DKIM lookup
    try:
        selectors = ['selector1', 'selector2']
        dkim_results = []
        dkim_valid = True

        for selector in selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            try:
                dkim_records = dns.resolver.resolve(dkim_domain, 'TXT')
                dkim_txt = [b.decode('utf-8') for r in dkim_records for b in r.strings]
                dkim_results.append(f"{selector}: {dkim_txt[0]}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                dkim_results.append(f"{selector}: DKIM record not found: {dkim_domain}")
                dkim_valid = False
            except Exception as e:
                dkim_results.append(f"{selector}: {str(e)}")
                dkim_valid = False

        results['DKIM'] = {"status": dkim_valid, "value": dkim_results}
    except Exception as e:
        results['DKIM'] = {"status": False, "value": str(e)}

    # DMARC lookup
    try:
        dmarc_domain = "_dmarc." + domain
        dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
        dmarc_txt = ["".join([b.decode("utf-8") for b in rr.strings]) for rr in dmarc_records]

        valid_dmarc = any("p=reject" in record for record in dmarc_txt)
        results['DMARC'] = {"status": valid_dmarc, "value": dmarc_txt}
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        results['DMARC'] = {"status": False, "value": record_not_found("DMARC", dmarc_domain)}
    except Exception as e:
        results['DMARC'] = {"status": False, "value": str(e)}

    # MTA-STS lookup with validation
    try:
        mta_sts_domain = "_mta-sts." + domain
        try:
            mta_sts_records = dns.resolver.resolve(mta_sts_domain, 'TXT')
            mta_sts_dns_ok = True
            mta_sts_txt_value = ''.join([b.decode('utf-8') for b in mta_sts_records[0].strings])  # Get the TXT record value
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            mta_sts_dns_ok = False
            results['MTA-STS'] = {"status": False, "value": record_not_found("MTA-STS", mta_sts_domain)}
            mta_sts_dns_ok = None  # Stop further processing

        if mta_sts_dns_ok is not None:
            try:
                well_known_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
                fallback_url = f"https://{domain}/.well-known/mta-sts.txt"
                r = requests.get(well_known_url, timeout=5)
                mta_sts_http_ok = r.status_code == 200
                if not mta_sts_http_ok:
                    try:
                        r2 = requests.get(fallback_url, timeout=5)
                        mta_sts_http_ok = r2.status_code == 200
                    except:
                        mta_sts_http_ok = False
            except:
                mta_sts_http_ok = False

            # STRICT VALIDATION: both must succeed
            mta_sts_valid = mta_sts_dns_ok and mta_sts_http_ok
            results['MTA-STS'] = {
                "status": mta_sts_valid,
                "value": [
                    f"{mta_sts_txt_value}",
                    f"DNS: {mta_sts_dns_ok}\t\tHTTP: {mta_sts_http_ok}"
                ]
            }
    except Exception as e:
        results['MTA-STS'] = {"status": False, "value": str(e)}

    # DNSSEC lookup
    try:
        ds_records = dns.resolver.resolve(domain, 'DS')
        dnssec_valid = len(ds_records) > 0
        ds_values = [str(r) for r in ds_records]
        results['DNSSEC'] = {"status": dnssec_valid, "value": ds_values}
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        results['DNSSEC'] = {"status": False, "value": record_not_found("DNSSEC", domain)}
    except Exception as e:
        results['DNSSEC'] = {"status": False, "value": str(e)}

    # NS lookup
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        ns_list = [str(r.target) for r in ns_records]
        results['NS'] = ns_list
    except:
        results['NS'] = []

    # WHOIS lookup
    try:
        whois_data = whois.whois(domain)
        results['WHOIS'] = {
            "registrar": whois_data.registrar,
            "creation_date": str(whois_data.creation_date)
        }
    except Exception as e:
        results['WHOIS'] = {"error": str(e)}

    return func.HttpResponse(json.dumps(results), mimetype="application/json")


# ==========================
# NEW: Port checker endpoint
# ==========================
@app.route(route="portcheck")
def port_check(req: func.HttpRequest) -> func.HttpResponse:
    host = (req.params.get("host") or "").strip()
    port_raw = (req.params.get("port") or "").strip()
    timeout_raw = (req.params.get("timeout") or "").strip()

    if not host:
        return func.HttpResponse("Please pass a host (IP or hostname) on the query string", status_code=400)
    if not port_raw:
        return func.HttpResponse("Please pass a port on the query string", status_code=400)

    try:
        port = int(port_raw)
        if port < 1 or port > 65535:
            raise ValueError()
    except ValueError:
        return func.HttpResponse("Port must be an integer between 1 and 65535", status_code=400)

    try:
        timeout_sec = float(timeout_raw) if timeout_raw else 3.0
        if timeout_sec <= 0 or timeout_sec > 15:
            # keep reasonable bounds
            timeout_sec = 3.0
    except ValueError:
        timeout_sec = 3.0

    # Resolve host -> list of IPs
    ips = []
    if _is_ip_literal(host):
        ips = [host]
    else:
        ips = _resolve_host_to_ips(host)

    if not ips:
        return func.HttpResponse(
            json.dumps({
                "ok": False,
                "host": host,
                "port": port,
                "error": "Unable to resolve hostname",
                "resolved_ips": []
            }),
            mimetype="application/json",
            status_code=200
        )

    # Filter blocked IPs
    allowed_ips = []
    blocked = []
    for ip in ips:
        allowed, reason = _is_ip_allowed(ip)
        if allowed:
            allowed_ips.append(ip)
        else:
            blocked.append({"ip": ip, "reason": reason})

    if not allowed_ips:
        return func.HttpResponse(
            json.dumps({
                "ok": False,
                "host": host,
                "port": port,
                "error": "All resolved IPs are blocked",
                "resolved_ips": ips,
                "blocked": blocked
            }),
            mimetype="application/json",
            status_code=200
        )

    # Attempt connect (first IP that succeeds wins)
    attempts = []
    for ip in allowed_ips:
        is_open, latency_ms, err = _tcp_connect(ip, port, timeout_sec)
        attempts.append({
            "ip": ip,
            "open": is_open,
            "latency_ms": round(latency_ms, 2),
            "error": err if not is_open else ""
        })
        if is_open:
            return func.HttpResponse(
                json.dumps({
                    "ok": True,
                    "host": host,
                    "port": port,
                    "open": True,
                    "timeout_sec": timeout_sec,
                    "resolved_ips": ips,
                    "blocked": blocked,
                    "attempts": attempts
                }),
                mimetype="application/json",
                status_code=200
            )

    # None succeeded
    return func.HttpResponse(
        json.dumps({
            "ok": True,
            "host": host,
            "port": port,
            "open": False,
            "timeout_sec": timeout_sec,
            "resolved_ips": ips,
            "blocked": blocked,
            "attempts": attempts
        }),
        mimetype="application/json",
        status_code=200
    )
