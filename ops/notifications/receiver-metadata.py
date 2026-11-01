#!/usr/bin/env python3
"""Read only owned-window Mailu transport metadata; never print raw logs or peers.

This recovers the existing 2026-10-31 noAUTH preflight, without another connection.
Run through bao-exec --only COOLIFY_WIRE_TOKEN,COOLIFY_URL.
"""
import datetime as dt
import json
import os
import re
import urllib.request

SERVICE = 'kzcsybgqrftglacdf3j8bfk1'
DEPLOYMENT = 'oqghicv2rzlscimmgel2twfs'
START = dt.datetime(2026, 10, 31, 7, 7, 7, tzinfo=dt.timezone.utc)
END = START + dt.timedelta(seconds=1)
OWNED = {'168.119.120.255': 'owned_gateway_host', '10.10.0.2': 'owned_vpn_host'}
STAMP = re.compile(r'20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)')
IP = re.compile(r'(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])')
FIELD = re.compile(r'\b(rip|lip|remote|client|peer|server|local|upstream|addr|address|src|dst|source|destination)\s*[=:]\s*\[?$')
PROCESSES = ('submission-login', 'smtp-login', 'smtpd-login', 'imap-login', 'pop3-login')


def summarize(logs):
    if not isinstance(logs, str) or len(logs.encode()) > 2_000_000:
        raise RuntimeError('logs_bound')
    times, records = [], []
    for line in logs.splitlines():
        stamp = STAMP.search(line)
        if not stamp:
            continue
        when = dt.datetime.fromisoformat(stamp[0].replace('Z', '+00:00'))
        times.append(when)
        if not START - dt.timedelta(seconds=2) <= when <= END + dt.timedelta(seconds=2):
            continue
        addresses = list(IP.finditer(line))
        if not any(address[0] in OWNED for address in addresses):
            continue
        peers = []
        for address in addresses:
            field = FIELD.search(line[max(0, address.start() - 60):address.start()].lower())
            peers.append({'role': OWNED.get(address[0], 'redacted'),
                          'field': field[1] if field else 'unclassified'})
        lower = line.lower()
        process = next((value for value in PROCESSES if re.search(r'\b' + value + r':', lower)), 'unclassified')
        ports = [{'field': match[1], 'is_587': match[2] == '587'} for match in
                 re.finditer(r'\b(lport|rport|port|local_port|remote_port)\s*[=:]\s*(\d{1,5})\b', lower)]
        records.append({'receiver_utc': when.isoformat(), 'process': process,
                        'address_roles': peers, 'port_fields': ports,
                        'tls': bool(re.search(r'\bTLS\b', line, re.I)),
                        'no_auth_attempts': 'no auth attempts' in lower,
                        'connection_closed': 'connection closed' in lower})
    # Metadata is evidence for review, never automatic source-IP clearance.
    return {'record': 'owned_mailu_receiver_metadata', 'deployment_uuid': DEPLOYMENT,
            'read_only': True, 'raw_logs_emitted': False, 'source_ip_cleared': False,
            'timestamped_rows': len(times),
            'window_covered': bool(times and min(times) <= START and max(times) >= END),
            'owned_window_rows': records}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    url = (os.environ['COOLIFY_URL'].rstrip('/') + '/api/v1/services/' + SERVICE +
           '/logs?sub_service_name=front&lines=2000&show_timestamps=true')
    request = urllib.request.Request(url, headers={
        'Authorization': 'Bearer ' + os.environ['COOLIFY_WIRE_TOKEN'], 'Accept': 'application/json'})
    with opener.open(request, timeout=20) as response:
        raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise RuntimeError('response_bound')
    result = json.loads(raw)
    print(json.dumps(summarize(result['logs']), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('owned_mailu_receiver_metadata_unavailable_no_raw_output')
        raise SystemExit(1) from None
