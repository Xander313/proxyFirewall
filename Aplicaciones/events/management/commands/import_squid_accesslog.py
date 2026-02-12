import os
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from django.core.management.base import BaseCommand
from django.db import transaction

from Aplicaciones.control.models import HttpMethod, Url
from Aplicaciones.events.models import Request, Verdict, CacheStatus

SQUID_RE = re.compile(
    r"^(?P<ts>\d+\.\d+)\s+"
    r"(?P<elapsed>\d+)\s+"
    r"(?P<client_ip>\S+)\s+"
    r"(?P<status>\S+)\s+"
    r"(?P<bytes>\d+)\s+"
    r"(?P<method>\S+)\s+"
    r"(?P<url>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"(?P<hier>\S+)\s+"
    r"(?P<mime>\S+)"
)


def split_squid_status(status: str):
    left = status
    code = None
    if "/" in status:
        left, right = status.split("/", 1)
        try:
            code = int(right)
        except Exception:
            code = None
    return left, code


def parse_url(raw: str):
    p = urlparse(raw)
    scheme = p.scheme or "http"
    host = p.hostname or raw
    port = p.port or (443 if scheme == "https" else 80)
    path = p.path or "/"
    query = p.query or ""
    return scheme, host, port, path, query


class Command(BaseCommand):
    help = "Importa líneas nuevas del access.log de Squid y las guarda en la tabla requests"

    def add_arguments(self, parser):
        parser.add_argument("--logfile", default="/var/log/squid/access.log")
        parser.add_argument("--statefile", default="storage/accesslog.offset")
        parser.add_argument("--limit", type=int, default=5000)

    def handle(self, *args, **opts):
        logfile = opts["logfile"]
        statefile = opts["statefile"]
        limit = opts["limit"]

        state_dir = os.path.dirname(statefile)
        if state_dir:
            os.makedirs(state_dir, exist_ok=True)

        offset = 0
        if os.path.exists(statefile):
            try:
                offset = int(open(statefile, "r").read().strip() or "0")
            except Exception:
                offset = 0

        try:
            st = os.stat(logfile)
            # si el log rotó y el offset quedó mayor al tamaño, reset
            if offset > st.st_size:
                offset = 0
        except FileNotFoundError:
            self.stderr.write(self.style.ERROR(f"No existe logfile: {logfile}"))
            return
        except PermissionError as exc:
            self.stderr.write(self.style.ERROR(f"Sin permisos para leer {logfile}: {exc}"))
            return

        with open(logfile, "r", errors="ignore") as f:
            f.seek(offset)
            lines = []
            for _ in range(limit):
                line = f.readline()
                if not line:
                    break
                lines.append(line.strip())
            new_offset = f.tell()

        if not lines:
            self.stdout.write("No hay nuevas líneas.")
            return

        inserted = 0
        skipped = 0

        with transaction.atomic():
            for line in lines:
                m = SQUID_RE.match(line)
                if not m:
                    skipped += 1
                    continue

                ts_float = float(m.group("ts"))
                ts = datetime.fromtimestamp(ts_float, tz=timezone.utc)

                elapsed_ms = int(m.group("elapsed"))
                client_ip = m.group("client_ip")
                status = m.group("status")
                bytes_out = int(m.group("bytes"))
                method_txt = m.group("method").upper()
                url_raw = m.group("url")

                left, http_status = split_squid_status(status)

                verdict = Verdict.ALLOW
                cache_status = None
                block_reason = ""

                if "DENIED" in left:
                    verdict = Verdict.DENY
                    block_reason = left

                if "HIT" in left:
                    cache_status = CacheStatus.HIT
                elif "MISS" in left:
                    cache_status = CacheStatus.MISS
                elif "BYPASS" in left:
                    cache_status = CacheStatus.BYPASS
                elif "EXPIRED" in left:
                    cache_status = CacheStatus.EXPIRED
                elif "REVALIDATED" in left:
                    cache_status = CacheStatus.REVALIDATED

                method_obj, _ = HttpMethod.objects.get_or_create(method=method_txt)

                scheme, host, port, path, query = parse_url(url_raw)
                url_obj, _ = Url.objects.get_or_create(
                    scheme=scheme, host=host, port=port, path=path, query=query
                )

                Request.objects.create(
                    ts=ts,
                    client_ip=client_ip,
                    client_port=0,
                    user=None,
                    method=method_obj,
                    url=url_obj,
                    dest_ip=None,
                    dest_port=port,
                    protocol=None,
                    http_status=http_status,
                    bytes_in=0,
                    bytes_out=bytes_out,
                    elapsed_ms=elapsed_ms,
                    cache_status=cache_status,
                    verdict=verdict,
                    block_reason=block_reason,
                )
                inserted += 1

        with open(statefile, "w") as sf:
            sf.write(str(new_offset))

        self.stdout.write(self.style.SUCCESS(
            f"Insertados: {inserted} | Saltados(no parse): {skipped} | Offset: {new_offset}"
        ))
