# Estandar de `rule.condition` (JSONB)

Este formato es obligatorio para reglas en `control_rule.condition`.

## Estructura

```json
{
  "version": 1,
  "note": "Justificacion tecnica de la regla",
  "match": {
    "zones": [1, 2],
    "url_categories": [3],
    "urls": ["facebook.com", "instagram.com"],
    "http_methods": ["GET", "POST"],
    "services": [
      {"protocol": "TCP", "port": 443}
    ]
  },
  "time": {
    "days": ["MON", "TUE", "WED", "THU", "FRI"],
    "start": "07:00",
    "end": "13:00",
    "tz": "America/Guayaquil"
  }
}
```

## Reglas de validacion

- `version`: debe ser `1`.
- `note`: texto obligatorio, explica el criterio tecnico.
- `match`: objeto obligatorio con al menos un criterio.
- Claves permitidas en `match`:
  - `zones`: lista de `zone_id`.
  - `url_categories`: lista de `category_id`.
  - `urls`: lista de dominios/URLs.
  - `http_methods`: lista de strings (`GET`, `POST`, etc.).
  - `services`: lista de objetos `{protocol, port}` con `protocol in [TCP, UDP]` y `port in [1..65535]`.
- `time` (opcional): si se usa, debe incluir `days`, `start`, `end`, `tz`.
  - `days` usa solo `MON..SUN`.
  - `start` y `end` en formato `HH:MM` 24h.

## Ejemplo de demostracion (tribunal)

- Regla: bloquear redes sociales en horario de clase.
- `action`: `DENY`.
- Justificacion (`note`): preservar ancho de banda academico y reducir distracciones.
