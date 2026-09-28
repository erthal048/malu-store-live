import os
import json
import hmac
import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR
DB_PATH = Path(os.getenv('DB_PATH', BASE_DIR / 'malu_live.db'))
VERIFY_TOKEN = os.getenv('VERIFY_TOKEN', 'MALU_LIVE_VERIFICAR_2026')
APP_SECRET = os.getenv('APP_SECRET', '').strip()
MAX_COMMENTS = int(os.getenv('MAX_COMMENTS', '1000'))


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_key TEXT UNIQUE,
            username TEXT NOT NULL,
            text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            raw_json TEXT
        )
    ''')
    conn.commit()
    conn.close()


def verify_signature(raw_body: bytes, signature: str) -> bool:
    if not APP_SECRET:
        return True
    if not signature.startswith('sha256='):
        return False
    expected = hmac.new(APP_SECRET.encode('utf-8'), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, 'sha256=' + expected)


def first_value(*values):
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return ''


def extract_username(value):
    if isinstance(value, dict):
        return first_value(value.get('username'), value.get('user_name'), value.get('name'))
    return value if isinstance(value, str) else ''


def extract_text(value):
    if isinstance(value, dict):
        return first_value(value.get('text'), value.get('message'), value.get('comment'))
    return value if isinstance(value, str) else ''


def event_key_for(item, entry_index, change_index):
    for key in ('id', 'comment_id', 'event_id', 'commentId'):
        if isinstance(item, dict) and item.get(key):
            return str(item[key])
    raw = json.dumps(item, sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha256(raw.encode('utf-8')).hexdigest()
    return f'{entry_index}:{change_index}:{digest}'


def extract_comments(payload):
    found = []
    entries = payload.get('entry') or payload.get('entries') or []
    if isinstance(entries, dict):
        entries = [entries]

    for ei, entry in enumerate(entries):
        changes = entry.get('changes') or []
        if isinstance(changes, dict):
            changes = [changes]
        for ci, change in enumerate(changes):
            field = str(change.get('field', '')).lower()
            if field not in {'comments', 'live_comments', 'live-comment', 'livecomment'}:
                continue
            value = change.get('value') or change
            candidates = []
            if isinstance(value, list):
                candidates = value
            elif isinstance(value, dict):
                for key in ('comment', 'comments', 'data'):
                    val = value.get(key)
                    if isinstance(val, list):
                        candidates.extend(val)
                    elif isinstance(val, dict):
                        candidates.append(val)
                if not candidates:
                    candidates = [value]

            for item in candidates:
                if not isinstance(item, dict):
                    continue
                username = extract_username(first_value(item.get('from'), item.get('user'), item.get('sender')))
                text = extract_text(item)
                if not text:
                    text = extract_text(first_value(item.get('comment'), item.get('message')))
                if not username and not text:
                    continue
                created = first_value(
                    item.get('created_time'),
                    item.get('timestamp'),
                    value.get('timestamp') if isinstance(value, dict) else None,
                )
                if isinstance(created, (int, float)):
                    created_at = datetime.fromtimestamp(created, tz=timezone.utc).isoformat()
                else:
                    created_at = str(created or datetime.now(timezone.utc).isoformat())
                if username and not username.startswith('@'):
                    username = '@' + username
                found.append({
                    'event_key': event_key_for(item, ei, ci),
                    'username': username or '@desconhecido',
                    'text': text or '(comentário sem texto)',
                    'created_at': created_at,
                    'raw_json': json.dumps(item, ensure_ascii=False),
                })
    return found


def insert_comments(comments):
    if not comments:
        return
    conn = db()
    for c in comments:
        conn.execute(
            'INSERT OR IGNORE INTO comments (event_key, username, text, created_at, raw_json) VALUES (?, ?, ?, ?, ?)',
            (c['event_key'], c['username'], c['text'], c['created_at'], c['raw_json'])
        )
    conn.execute(
        'DELETE FROM comments WHERE id NOT IN (SELECT id FROM comments ORDER BY id DESC LIMIT ?)',
        (MAX_COMMENTS,)
    )
    conn.commit()
    conn.close()


class Handler(BaseHTTPRequestHandler):
    server_version = 'MaluStoreLive/1.0'

    def _send(self, status, body=b'', content_type='text/plain; charset=utf-8'):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'SAMEORIGIN')
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, status, data):
        self._send(status, json.dumps(data, ensure_ascii=False).encode('utf-8'), 'application/json; charset=utf-8')

    def _read_json(self):
        length = int(self.headers.get('Content-Length', '0'))
        raw = self.rfile.read(length) if length else b'{}'
        return raw, json.loads(raw.decode('utf-8') or '{}')

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/health':
            self._json(200, {'ok': True, 'service': 'malu-store-live', 'time': datetime.now(timezone.utc).isoformat()})
            return

        if parsed.path == '/webhook':
            qs = parse_qs(parsed.query)
            mode = (qs.get('hub.mode') or [''])[0]
            token = (qs.get('hub.verify_token') or [''])[0]
            challenge = (qs.get('hub.challenge') or [''])[0]
            if mode == 'subscribe' and hmac.compare_digest(token, VERIFY_TOKEN):
                self._send(200, challenge.encode('utf-8'))
            else:
                self._send(403, 'Verificação inválida'.encode('utf-8'))
            return

        if parsed.path == '/api/comments':
            try:
                qs = parse_qs(parsed.query)
                limit = int((qs.get('limit') or ['200'])[0])
                limit = min(max(limit, 1), 1000)
            except ValueError:
                limit = 200
            conn = db()
            rows = conn.execute(
                'SELECT id, username, text, created_at FROM comments ORDER BY id DESC LIMIT ?',
                (limit,)
            ).fetchall()
            conn.close()
            self._json(200, [dict(r) for r in rows])
            return

        if parsed.path == '/' or parsed.path == '/index.html':
            try:
                body = (STATIC_DIR / 'index.html').read_bytes()
                self._send(200, body, 'text/html; charset=utf-8')
            except FileNotFoundError:
                self._send(404, b'index.html nao encontrado')
            return

        # Optional static files in future.
        self._send(404, b'Not found')

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == '/webhook':
            try:
                raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                if not verify_signature(raw, self.headers.get('X-Hub-Signature-256', '')):
                    self._send(403, b'Assinatura invalida')
                    return
                payload = json.loads(raw.decode('utf-8') or '{}')
                comments = extract_comments(payload)
                insert_comments(comments)
                self._json(200, {'ok': True, 'received': len(comments)})
            except Exception as exc:
                self._json(400, {'ok': False, 'error': str(exc)})
            return

        if parsed.path == '/api/test-comment':
            try:
                _, data = self._read_json()
                username = str(data.get('username', '')).strip()
                text = str(data.get('text', '')).strip()
                if not username or not text:
                    self._json(400, {'ok': False, 'error': 'username e text sao obrigatorios'})
                    return
                if not username.startswith('@'):
                    username = '@' + username
                now = datetime.now(timezone.utc).isoformat()
                key = 'manual:' + hashlib.sha256(f'{username}|{text}|{now}'.encode()).hexdigest()
                insert_comments([{
                    'event_key': key,
                    'username': username,
                    'text': text,
                    'created_at': now,
                    'raw_json': '{}',
                }])
                self._json(200, {'ok': True})
            except Exception as exc:
                self._json(400, {'ok': False, 'error': str(exc)})
            return

        self._send(404, b'Not found')

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path == '/api/comments':
            conn = db()
            conn.execute('DELETE FROM comments')
            conn.commit()
            conn.close()
            self._json(200, {'ok': True})
            return
        self._send(404, b'Not found')

    def log_message(self, fmt, *args):
        print(f'[{datetime.now().isoformat(timespec="seconds")}] {self.address_string()} - {fmt % args}')


init_db()
port = int(os.getenv('PORT', '5000'))
server = ThreadingHTTPServer(('0.0.0.0', port), Handler)
print(f'Malu Store Live rodando na porta {port}')
server.serve_forever()
