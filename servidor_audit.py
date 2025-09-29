#!/usr/bin/env python3
"""
server_audit.py

Uso:
  python3 server_audit.py --host example.com
  python3 server_audit.py --input hosts.txt --csv output.csv --pdf output.pdf

Descrição:
  Lê um host único ou uma lista de hosts em .txt (um por linha), coleta informações via DNS,
  whois (se disponível), faz checagem de portas e HTTPS (certificado e cabeçalhos HTTP),
  executa heurísticas simples de "vulnerabilidades" (ex.: portas abertas conhecidas, certificado expirado),
  e exporta resultados em CSV e opcionalmente em PDF (tabela).

Dependências (instale com pip):
  pip install dnspython requests reportlab python-whois

"""

import argparse
import csv
import socket
import ssl
import sys
import time
from datetime import datetime
from io import StringIO

# Optional imports
try:
    import dns.resolver
except Exception:
    print("Erro: dnspython não encontrado. Instale com: pip install dnspython")
    raise

try:
    import requests
except Exception:
    requests = None

try:
    import whois as whois_module
except Exception:
    whois_module = None

# Importando reportlab de forma controlada
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    reportlab_available = True
except Exception:
    reportlab_available = False

# Common ports to check
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 587, 3306, 3389, 8080]
SOCKET_TIMEOUT = 2.0

# ===================== Funções principais =====================

def resolve_dns(name):
    out = {"A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": []}
    resolver = dns.resolver.Resolver()
    for rtype in ["A", "AAAA", "CNAME", "MX", "NS"]:
        try:
            answers = resolver.resolve(name, rtype, lifetime=3)
            for r in answers:
                out[rtype].append(str(r).rstrip('.'))
        except Exception:
            pass
    return out

def reverse_dns(ip):
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return ""

def whois_lookup(domain):
    if not whois_module:
        return "whois not instalado"
    try:
        w = whois_module.whois(domain)
        if isinstance(w, dict):
            keys = [k for k in ("domain_name","registrar","creation_date","expiration_date","emails") if k in w]
            return {k: w.get(k) for k in keys}
        else:
            return {
                "domain_name": getattr(w, 'domain_name', None),
                "registrar": getattr(w, 'registrar', None),
                "creation_date": getattr(w, 'creation_date', None),
                "expiration_date": getattr(w, 'expiration_date', None),
                "emails": getattr(w, 'emails', None),
            }
    except Exception as e:
        return f"whois error: {e}"

def scan_port(host, port, timeout=SOCKET_TIMEOUT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

def grab_cert_info(host, port=443, timeout=5):
    info = {"valid_from": None, "valid_to": None, "subject": None, "issuer": None}
    try:
        context = ssl.create_default_context()
        conn = socket.create_connection((host, port), timeout=timeout)
        sock = context.wrap_socket(conn, server_hostname=host)
        cert = sock.getpeercert()
        sock.close()
        info['subject'] = dict(x[0] for x in cert.get('subject', ())) if cert.get('subject') else None
        info['issuer'] = dict(x[0] for x in cert.get('issuer', ())) if cert.get('issuer') else None
        info['valid_from'] = cert.get('notBefore')
        info['valid_to'] = cert.get('notAfter')
    except Exception as e:
        info['error'] = str(e)
    return info

def fetch_http_headers(host, port=80, use_https=False, timeout=5):
    if not requests:
        return {"error": "requests not installed"}
    try:
        scheme = 'https' if use_https else 'http'
        url = f"{scheme}://{host}"
        if port not in (80, 443):
            url = f"{scheme}://{host}:{port}"
        r = requests.head(url, timeout=timeout, allow_redirects=True)
        headers = dict(r.headers)
        headers['status_code'] = r.status_code
        return headers
    except Exception as e:
        return {"error": str(e)}

def check_cert_expired(valid_to_str):
    if not valid_to_str:
        return None
    try:
        dt = datetime.strptime(valid_to_str, '%b %d %H:%M:%S %Y %Z')
    except Exception:
        try:
            dt = datetime.fromisoformat(valid_to_str)
        except Exception:
            return None
    return dt < datetime.utcnow()

# ===================== Análise do host =====================

def analyze_host(host):
    row = {
        'input': host,
        'resolved_ips': [],
        'reverse_dns': [],
        'dns_a': [],
        'dns_aaaa': [],
        'dns_cname': [],
        'dns_mx': [],
        'dns_ns': [],
        'whois': None,
        'open_ports': [],
        'http_server_header': None,
        'tls_valid_to': None,
        'tls_expired': None,
        'tls_error': None,
        'vuln_notes': []
    }

    dns_info = resolve_dns(host)
    row['dns_a'] = dns_info.get('A', [])
    row['dns_aaaa'] = dns_info.get('AAAA', [])
    row['dns_cname'] = dns_info.get('CNAME', [])
    row['dns_mx'] = dns_info.get('MX', [])
    row['dns_ns'] = dns_info.get('NS', [])

    ips = row['dns_a'] + row['dns_aaaa']
    row['resolved_ips'] = ips

    for ip in ips:
        rd = reverse_dns(ip)
        row['reverse_dns'].append({ip: rd})

    try:
        w = whois_lookup(host)
        row['whois'] = w
    except Exception as e:
        row['whois'] = f"whois failed: {e}"

    for port in COMMON_PORTS:
        try:
            if scan_port(host, port):
                row['open_ports'].append(port)
        except Exception:
            pass

    try:
        if 443 in row['open_ports']:
            cert = grab_cert_info(host, 443)
            if cert.get('error'):
                row['tls_error'] = cert.get('error')
            else:
                row['tls_valid_to'] = cert.get('valid_to')
                row['tls_expired'] = check_cert_expired(cert.get('valid_to'))
        if requests:
            if 80 in row['open_ports']:
                hdrs = fetch_http_headers(host, 80, use_https=False)
                if isinstance(hdrs, dict) and 'error' not in hdrs:
                    row['http_server_header'] = hdrs.get('Server')
                    row['security_headers'] = {k: hdrs.get(k) for k in (
                        'Strict-Transport-Security','Content-Security-Policy','X-Frame-Options','X-Content-Type-Options')}
            if 443 in row['open_ports']:
                hdrs = fetch_http_headers(host, 443, use_https=True)
                if isinstance(hdrs, dict) and 'error' not in hdrs:
                    row['http_server_header'] = row.get('http_server_header') or hdrs.get('Server')
                    row['security_headers'] = {k: hdrs.get(k) for k in (
                        'Strict-Transport-Security','Content-Security-Policy','X-Frame-Options','X-Content-Type-Options')}
    except Exception as e:
        row['vuln_notes'].append(f"http/tls check error: {e}")

    if any(p in row['open_ports'] for p in (21,23,3306,3389)):
        row['vuln_notes'].append('Portas críticas abertas (verifique segurança e patches)')
    if row.get('tls_expired'):
        row['vuln_notes'].append('Certificado TLS expirado')
    if 80 in row['open_ports'] and 443 not in row['open_ports']:
        row['vuln_notes'].append('HTTP sem HTTPS - risco de interceptação')

    return row

# ===================== Exportação =====================

def write_csv(rows, csv_path):
    keys = ['input','resolved_ips','dns_a','dns_aaaa','dns_cname','dns_mx','dns_ns','reverse_dns','whois','open_ports','http_server_header','tls_valid_to','tls_expired','tls_error','vuln_notes']
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(keys)
        for r in rows:
            writer.writerow([
                r.get('input'),
                ';'.join(r.get('resolved_ips') or []),
                ';'.join(r.get('dns_a') or []),
                ';'.join(r.get('dns_aaaa') or []),
                ';'.join(r.get('dns_cname') or []),
                ';'.join(r.get('dns_mx') or []),
                ';'.join(r.get('dns_ns') or []),
                ';'.join([f"{list(x.keys())[0]}->{list(x.values())[0]}" for x in (r.get('reverse_dns') or [])]),
                str(r.get('whois')),
                ';'.join([str(p) for p in (r.get('open_ports') or [])]),
                r.get('http_server_header'),
                r.get('tls_valid_to'),
                str(r.get('tls_expired')),
                r.get('tls_error'),
                ';'.join(r.get('vuln_notes') or [])
            ])
    print(f"CSV salvo em: {csv_path}")

def write_pdf(rows, pdf_path):
    if not reportlab_available:
        print('reportlab não instalado — instale com: pip install reportlab')
        return
    doc = SimpleDocTemplate(pdf_path, pagesize=A4)
    styles = getSampleStyleSheet()
    elems = []
    elems.append(Paragraph('Relatório de Auditoria de Servidores', styles['Title']))
    elems.append(Spacer(1,12))

    for r in rows:
        title = Paragraph(f"Host: {r.get('input')}", styles['Heading2'])
        elems.append(title)
        table_data = [
            ['Campo','Valor'],
            ['Resolved IPs', ', '.join(r.get('resolved_ips') or [])],
            ['DNS A', ', '.join(r.get('dns_a') or [])],
            ['DNS AAAA', ', '.join(r.get('dns_aaaa') or [])],
            ['CNAME', ', '.join(r.get('dns_cname') or [])],
            ['MX', ', '.join(r.get('dns_mx') or [])],
            ['NS', ', '.join(r.get('dns_ns') or [])],
            ['Reverse DNS', ', '.join([f"{list(x.keys())[0]} -> {list(x.values())[0]}" for x in (r.get('reverse_dns') or [])])],
            ['Open Ports', ', '.join([str(p) for p in (r.get('open_ports') or [])])],
            ['HTTP Server Header', str(r.get('http_server_header'))],
            ['TLS valid to', str(r.get('tls_valid_to'))],
            ['TLS expired', str(r.get('tls_expired'))],
            ['Vulnerability notes', ', '.join(r.get('vuln_notes') or [])]
        ]
        t = Table(table_data, colWidths=[120, 380])
        t.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(1,0),colors.grey),
            ('TEXTCOLOR',(0,0),(1,0),colors.whitesmoke),
            ('ALIGN',(0,0),(-1,-1),'LEFT'),
            ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
            ('FONTSIZE',(0,0),(-1,-1),8),
            ('BOTTOMPADDING',(0,0),(-1,0),6),
            ('GRID',(0,0),(-1,-1),0.25,colors.black)
        ]))
        elems.append(t)
        elems.append(Spacer(1,12))
    doc.build(elems)
    print(f"PDF salvo em: {pdf_path}")

# ===================== Main =====================

def main():
    parser = argparse.ArgumentParser(description='Auditoria simples por DNS/porta/HTTP/TLS')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--host', help='Host único (ex: example.com)')
    group.add_argument('--input', help='Arquivo .txt com hosts, um por linha')
    parser.add_argument('--csv', help='Caminho do CSV de saída', default='report.csv')
    parser.add_argument('--pdf', help='Caminho do PDF de saída (opcional)', default=None)
    args = parser.parse_args()

    hosts = []
    if args.host:
        hosts = [args.host.strip()]
    else:
        with open(args.input, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                hosts.append(line)

    results = []
    for h in hosts:
        print(f"Analisando: {h}")
        try:
            r = analyze_host(h)
            results.append(r)
        except Exception as e:
            print(f"Erro ao analisar {h}: {e}")

    write_csv(results, args.csv)
    if args.pdf:
        write_pdf(results, args.pdf)

if __name__ == '__main__':
    main()
