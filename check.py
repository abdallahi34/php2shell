#!/usr/bin/env python3
"""Rimscope : vérifier une version PHP pour PHP2Shell. Python 3.10+, sans dépendances."""
import argparse
import datetime
import json
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

REVIEWED = '2026-10-23'
FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
NOTE = ('CVE-2026-115560 : consulter aussi l’avis PHP du 23/10/2026 sur '
        'session.upload_progress.enabled. Les deux correctifs initiaux ne couvrent '
        'pas ce cas supplémentaire. Aucune conclusion sur la sécurité globale du site.')


def assess(version):
    """Compare within a known branch; never treat an unknown branch as fixed."""
    if not isinstance(version, str):
        return 'INDETERMINE', 'Aucune version PHP exploitable.'
    m = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(.*)', version.strip())
    if not m:
        return 'INDETERMINE', 'Version incomplète ou non reconnue ; vérifier le runtime.'
    major, minor, patch = map(int, m.group(1, 2, 3))
    suffix = m.group(4)
    if suffix and (not re.match(r'^[-+~]', suffix) or
                   re.search(r'(?:^|[-+~.])(rc\d*|alpha\d*|beta\d*|dev|snapshot)', suffix, re.I)):
        return 'INDETERMINE', 'Version de développement/préversion ; vérifier l’avis PHP.'
    branch = (major, minor)
    if branch in FIXED:
        target = f'{major}.{minor}.{FIXED[branch]}'
        if patch >= FIXED[branch]:
            return ('CORRECTIF_AMONT_PRESENT',
                    f'Numéro au moins égal à {target} pour les deux CVE initiales. '
                    'Confirmer le binaire réellement utilisé, sa provenance et le redémarrage des workers.')
        return ('VERIFICATION_EDITEUR_REQUISE',
                f'Numéro inférieur à {target}. Mettre à jour, sauf correctif rétroporté '
                'confirmé dans l’avis du fournisseur du paquet ; un numéro seul ne suffit pas.')
    if branch < (8, 2):
        return ('BRANCHE_HORS_SUPPORT_AMONT',
                'Branche sans nouvelles versions de sécurité amont au 23/10/2026. '
                'Migrer vers une branche supportée ou vérifier les correctifs du fournisseur LTS.')
    return 'INDETERMINE', 'Branche absente des données vérifiées ; consulter l’avis PHP actuel.'


def validate_url(value):
    value = value.strip()
    if '://' not in value:
        value = 'https://' + value
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Caractères de contrôle interdits dans l’URL.')
    p = urllib.parse.urlsplit(value)
    if p.scheme not in ('https', 'http') or not p.hostname:
        raise ValueError('Fournir une URL HTTP(S) valide.')
    if p.username is not None or p.password is not None:
        raise ValueError('Ne pas inclure de mot de passe ou d’identifiant dans l’URL.')
    _ = p.port  # Validate numeric port and range.
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path or '/', p.query, ''))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def origin(url):
    p = urllib.parse.urlsplit(url)
    return p.scheme, p.hostname.lower(), p.port or (443 if p.scheme == 'https' else 80)


def inspect_url(url, timeout=10):
    """HEAD, puis GET si nécessaire, au plus trois redirections de même origine.

    No response bodies are read. Default TLS verification remains enabled.
    No cookies, auth, multipart requests, payloads or version enumeration.
    """
    current = validate_url(url)
    opener = urllib.request.build_opener(NoRedirect)
    method = 'HEAD'
    redirects = 0
    for _ in range(5):
        request = urllib.request.Request(current, method=method, headers={
            'User-Agent': 'Rimscope-PHP2Shell-Check/1.0 (inventory; no exploit)',
            'Accept': '*/*'})
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error  # Still inspect headers for 4xx/5xx responses.
        try:
            code = response.code
            headers = response.headers
            if code in (301, 302, 303, 307, 308):
                redirects += 1
                if redirects > 3:
                    raise ValueError('Plus de trois redirections ; contrôle interrompu.')
                location = headers.get('Location')
                if not location:
                    raise ValueError('Redirection sans destination ; contrôle indéterminé.')
                destination = validate_url(urllib.parse.urljoin(current, location))
                if origin(destination) != origin(current):
                    raise ValueError('Redirection vers une autre origine : relancer avec son URL explicite.')
                current = destination
                continue
            if code in (405, 501) and method == 'HEAD':
                method = 'GET'
                continue
            advertised = headers.get_all('X-Powered-By') or []
            versions = sorted(set(re.findall(r'PHP/(\d+\.\d+\.\d+(?:[A-Za-z0-9.+~_-]*))',
                                             ','.join(advertised), re.I)))
            if not versions and method == 'HEAD' and 200 <= code < 300:
                # Some servers expose PHP only on GET responses. Read no body.
                method = 'GET'
                continue
            return {'mode': 'remote_headers', 'url': current, 'http_status': code,
                    'request_method': method,
                    'php_versions': versions,
                    'limitation': 'En-têtes déclaratifs : ils peuvent être cachés, falsifiés ou issus d’un proxy. '
                                  'Absence de PHP dans les en-têtes ≠ absence de PHP. Aucun test de vulnérabilité.'}
        finally:
            response.close()
    raise ValueError('Trop de redirections ou de tentatives ; contrôle interrompu.')


def inspect_local(binary='php'):
    code = ('echo json_encode(array("php_version"=>PHP_VERSION,"sapi"=>PHP_SAPI,'
            '"session_upload_progress"=>ini_get("session.upload_progress.enabled"),'
            '"session_serialize_handler"=>ini_get("session.serialize_handler")));')
    result = subprocess.run([binary, '-r', code], capture_output=True, text=True,
                            timeout=10, check=True)
    data = json.loads(result.stdout)
    if not isinstance(data, dict) or not isinstance(data.get('php_version'), str):
        raise ValueError('Réponse inattendue du binaire PHP.')
    return {'mode': 'local_cli', 'runtime': data,
            'php_versions': [data['php_version']],
            'limitation': 'Ce binaire CLI peut différer du PHP-FPM/mod_php du site, de ses pools '
                          'et de ses conteneurs. Les réglages CLI ne prouvent pas ceux du serveur web.'}


def build_report(evidence):
    versions = evidence.get('php_versions', [])
    findings = [{'version': v, 'status': assess(v)[0], 'detail': assess(v)[1]} for v in versions]
    if not findings:
        findings = [{'version': None, 'status': 'INDETERMINE',
                     'detail': 'Version non annoncée : vérifier auprès de l’hébergeur ou sur le runtime.'}]
    return {'tool': 'Rimscope PHP2Shell Check', 'knowledge_date': REVIEWED,
            'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'scope': ['CVE-2026-109618', 'CVE-2026-109619'],
            'evidence': evidence, 'findings': findings, 'additional_advisory': NOTE,
            'sources': ['https://www.php.net/',
                        'https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w',
                        'https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('site', nargs='?', help='URL du site (alternative à --url)')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--url', help='Votre site, ex. https://example.org')
    mode.add_argument('--php-version', help='Version déclarée manuellement, ex. 8.4.27')
    mode.add_argument('--local', action='store_true', help='Inspecter le PHP CLI local')
    parser.add_argument('--php-binary', default='php', help='Binaire local, utilisé avec --local')
    parser.add_argument('--timeout', type=float, default=10)
    parser.add_argument('--json', action='store_true', help='Afficher un rapport JSON')
    parser.add_argument('--output', help='Enregistrer le rapport JSON à cet emplacement')
    args = parser.parse_args(argv)
    if args.site:
        if args.url or args.php_version or args.local:
            parser.error('Ne pas combiner une URL positionnelle avec un autre mode.')
        args.url = args.site
    if not 0 < args.timeout <= 60:
        parser.error('--timeout doit être compris entre 0 et 60 secondes (0 exclu).')
    if not (args.url or args.php_version or args.local):
        if not sys.stdin.isatty():
            parser.error('Fournir --url, --php-version ou --local.')
        args.url = input('Rimscope — URL de votre site : ').strip()
        if not args.url:
            parser.error('URL vide.')
    try:
        if args.local:
            evidence = inspect_local(args.php_binary)
        elif args.php_version:
            evidence = {'mode': 'manual_version', 'php_versions': [args.php_version],
                        'limitation': 'Version fournie manuellement, non vérifiée sur le serveur.'}
        else:
            evidence = inspect_url(args.url, args.timeout)
        report = build_report(evidence)
        encoded = json.dumps(report, ensure_ascii=False, indent=2)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as handle:
                handle.write(encoded + '\n')
        if args.json:
            print(encoded)
        else:
            print('\nRIMSCOPE • PHP2Shell Check\nDonnées vérifiées : ' + REVIEWED)
            for item in report['findings']:
                print(f"\n[{item['status']}] PHP {item['version'] or 'inconnu'}\n{item['detail']}")
            print('\nLimite : ' + evidence['limitation'])
            if 'http_status' in evidence:
                print(f"HTTP {evidence['http_status']} • {evidence['url']}")
            print('\n' + NOTE + '\nGuide : GUIDE.md')
        statuses = {f['status'] for f in report['findings']}
        if statuses & {'VERIFICATION_EDITEUR_REQUISE', 'BRANCHE_HORS_SUPPORT_AMONT'}:
            return 1
        if 'INDETERMINE' in statuses:
            return 2
        return 0
    except (ValueError, OSError, urllib.error.URLError, subprocess.SubprocessError) as error:
        message = {'status': 'ERREUR', 'error': str(error)}
        print(json.dumps(message, ensure_ascii=False) if args.json else f'Erreur : {error}', file=sys.stderr)
        return 3


if __name__ == '__main__':
    sys.exit(main())
