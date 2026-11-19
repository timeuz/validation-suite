import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

from app.core.exceptions import AppError

ALLOWED_PORTS = {80, 443, 8080, 8443}


def _blocked(ip) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not ip.is_global or ip.is_multicast


async def resolve_public_ips(host: str, port: int) -> list[str]:
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise AppError(422, "dns_resolution_failed", f"Cannot resolve host '{host}'.")
    ips = {i[4][0].split("%")[0] for i in infos}
    if not ips:
        raise AppError(422, "dns_resolution_failed", f"No address for host '{host}'.")
    if any(_blocked(ipaddress.ip_address(ip)) for ip in ips):
        raise AppError(400, "ssrf_blocked", "Target resolves to a non-public address.")
    return sorted(ips)


async def validate_url(url: str) -> tuple[str, list[str]]:
    """Retorna (url, ips públicos). Conecte nos IPs devolvidos para evitar DNS rebinding (TOCTOU)."""
    p = urlparse(url)
    if p.scheme not in {"http", "https"} or not p.hostname:
        raise AppError(400, "invalid_url", "Only http(s) URLs with a host are allowed.")
    if p.username or p.password:
        raise AppError(400, "invalid_url", "Credentials in URL are not allowed.")
    port = p.port or (443 if p.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise AppError(400, "ssrf_blocked", f"Port {port} is not allowed.")
    try:
        lit = ipaddress.ip_address(p.hostname)
    except ValueError:
        return url, await resolve_public_ips(p.hostname, port)
    if _blocked(lit):
        raise AppError(400, "ssrf_blocked", "Target is a non-public address.")
    return url, [str(lit)]
