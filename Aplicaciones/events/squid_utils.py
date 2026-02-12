"""Utilerías ligeras para integrar con Squid y chequear DB.

Contiene:
- squid_status(): devuelve un dict con metadatos sobre archivos de Squid
- db_status(): chequeo simple de conexión a la DB

Diseñado para ser seguro al importar en tiempo de arranque y tolerante a
errores de permisos/IO (important cuando Django corre sin permisos para /etc).
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, List

from django.conf import settings


def db_status() -> Dict[str, Any]:
    """Verifica una conexión simple a la BD.

    Retorna: { 'ok': bool, 'msg': str }
    """
    try:
        # Import aquí para evitar problemas durante algunas fases de importación
        from django.db import connections

        conn = connections["default"]
        # abrir cursor forzará la conexión (si no hay permisos/reachability fallará)
        conn.cursor()
        return {"ok": True, "msg": "OK"}
    except Exception as exc:  # pragma: no cover - runtime environment dependent
        return {"ok": False, "msg": str(exc)}


def _safe_exists(path: str) -> bool:
    try:
        return os.path.exists(path)
    except Exception:
        return False


def squid_status() -> Dict[str, Any]:
    """Construye un objeto con información sobre la integración con Squid.

    Campos esperados por la plantilla:
    - config_path, config_exists
    - blocked_list_path, blocked_exists, blocked_count, blocked_mtime, blocked_sample
    - errors (lista), allow_read (bool)
    """
    info: Dict[str, Any] = {
        "config_path": getattr(settings, "SQUID_CONFIG_PATH", "/etc/squid/squid.conf"),
        "config_exists": False,
        "blocked_list_path": getattr(settings, "SQUID_BLOCKED_LIST", "/etc/squid/lists/blocked_domains.lst"),
        "blocked_exists": False,
        "blocked_count": 0,
        "blocked_mtime": None,
        "blocked_sample": [],
        "errors": [],
        "allow_read": getattr(settings, "SQUID_ALLOW_READ", False),
    }

    # Si la lectura está deshabilitada, devolvemos info mínima.
    if not info["allow_read"]:
        return info

    # comprobar archivo de config
    try:
        info["config_exists"] = _safe_exists(info["config_path"])
    except Exception as exc:  # pragma: no cover - plataforma dependiente
        info["errors"].append(f"config check error: {exc}")

    # comprobar lista de bloqueados
    blocked_path = info["blocked_list_path"]
    try:
        if _safe_exists(blocked_path):
            info["blocked_exists"] = True
            try:
                st = os.stat(blocked_path)
                info["blocked_mtime"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))
            except Exception as exc:  # pragma: no cover - permission/time issues
                info["errors"].append(f"stat error: {exc}")

            try:
                # intentamos leer de forma tolerante (ignorando errores de encoding)
                entries: List[str] = []
                with open(blocked_path, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        s = line.strip()
                        if not s:
                            continue
                        # permitir comentarios en la lista
                        if s.startswith("#"):
                            continue
                        entries.append(s)

                info["blocked_count"] = len(entries)
                # devolver una muestra corta
                info["blocked_sample"] = entries[:20]
            except PermissionError as exc:  # pragma: no cover - env dependent
                info["errors"].append(f"permission error reading blocked list: {exc}")
            except FileNotFoundError:
                info["blocked_exists"] = False
            except Exception as exc:  # pragma: no cover
                info["errors"].append(f"read error: {exc}")
        else:
            info["blocked_exists"] = False
    except Exception as exc:  # pragma: no cover
        info["errors"].append(f"blocked check error: {exc}")

    return info
