from django.db import models
from django.db.models import Q
from django.db.models.functions import Upper
from django.utils import timezone
from django.core.exceptions import ValidationError
import re


# -------------------------
# Soft Delete Base
# -------------------------
class SoftDeleteQuerySet(models.QuerySet):
    def delete(self):
        deleted_at = timezone.now()
        updated = self.update(is_delete=True, deleted_at=deleted_at)
        return updated, {self.model._meta.label: updated}

    def hard_delete(self):
        return super().delete()

    def alive(self):
        return self.filter(is_delete=False)

    def dead(self):
        return self.filter(is_delete=True)


class SoftDeleteManager(models.Manager):
    def get_queryset(self):
        return SoftDeleteQuerySet(self.model, using=self._db).filter(is_delete=False)


class SoftDeleteModel(models.Model):
    is_delete = models.BooleanField(default=False, db_index=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    objects = SoftDeleteManager()
    all_objects = SoftDeleteQuerySet.as_manager()

    class Meta:
        abstract = True

    def delete(self, using=None, keep_parents=False):
        self.is_delete = True
        self.deleted_at = timezone.now()
        self.save(update_fields=["is_delete", "deleted_at"])

    def hard_delete(self, using=None, keep_parents=False):
        return super().delete(using=using, keep_parents=keep_parents)

    def restore(self):
        self.is_delete = False
        self.deleted_at = None
        self.save(update_fields=["is_delete", "deleted_at"])


# -------------------------
# Enums
# -------------------------
class AuthType(models.TextChoices):
    LOCAL = "LOCAL", "LOCAL"
    LDAP = "LDAP", "LDAP"
    OIDC = "OIDC", "OIDC"
    SAML = "SAML", "SAML"
    OTHER = "OTHER", "OTHER"


class NetProtocol(models.TextChoices):
    TCP = "TCP", "TCP"
    UDP = "UDP", "UDP"


class Verdict(models.TextChoices):
    ALLOW = "ALLOW", "ALLOW"
    DENY = "DENY", "DENY"


class RuleAction(models.TextChoices):
    ALLOW = "ALLOW", "ALLOW"
    DENY = "DENY", "DENY"
    ALERT = "ALERT", "ALERT"
    LOG_ONLY = "LOG_ONLY", "LOG_ONLY"


# -------------------------
# Models
# -------------------------
class User(SoftDeleteModel):
    user_id = models.BigAutoField(primary_key=True)
    username = models.CharField(max_length=150)
    auth_type = models.CharField(max_length=10, choices=AuthType.choices)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "users"
        constraints = [
            models.UniqueConstraint(
                fields=["username"],
                condition=Q(is_delete=False),
                name="users_username_active_uniq",
            )
        ]

    def __str__(self):
        return self.username


class HttpMethod(SoftDeleteModel):
    method_id = models.BigAutoField(primary_key=True)
    method = models.CharField(max_length=16)

    class Meta:
        db_table = "http_method"
        constraints = [
            models.CheckConstraint(
                condition=Q(method=Upper("method")),
                name="http_method_uppercase_check",
            ),
            models.UniqueConstraint(
                fields=["method"],
                condition=Q(is_delete=False),
                name="http_method_method_active_uniq",
            ),
        ]

    def __str__(self):
        return self.method


class UrlCategory(SoftDeleteModel):
    category_id = models.BigAutoField(primary_key=True)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, default="")

    class Meta:
        db_table = "url_category"
        constraints = [
            models.UniqueConstraint(
                fields=["name"],
                condition=Q(is_delete=False),
                name="url_category_name_active_uniq",
            )
        ]

    def __str__(self):
        return self.name


class Url(SoftDeleteModel):
    url_id = models.BigAutoField(primary_key=True)
    scheme = models.CharField(max_length=10)
    host = models.CharField(max_length=255)
    port = models.PositiveIntegerField()
    path = models.TextField()
    query = models.TextField(blank=True, default="")
    category = models.ForeignKey(
        UrlCategory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        db_column="category_id",
        related_name="urls",
    )

    class Meta:
        db_table = "url"
        constraints = [
            models.UniqueConstraint(
                fields=["scheme", "host", "port", "path", "query"],
                condition=Q(is_delete=False),
                name="url_scheme_host_port_path_query_active_uniq",
            )
        ]

    def __str__(self):
        return f"{self.scheme}://{self.host}:{self.port}{self.path}"


class Policy(SoftDeleteModel):
    policy_id = models.BigAutoField(primary_key=True)
    name = models.CharField(max_length=150)
    type = models.CharField(max_length=50)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "policy"
        constraints = [
            models.UniqueConstraint(
                fields=["name"],
                condition=Q(is_delete=False),
                name="policy_name_active_uniq",
            )
        ]

    def __str__(self):
        return self.name


# -------------------------
# Rule.condition Standard + Validation (JSONB)
# -------------------------
DAYS = {"MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"}


def _is_time_hhmm(value: str) -> bool:
    return bool(re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", str(value)))


def validate_rule_condition(condition: dict):
    if not isinstance(condition, dict):
        raise ValidationError("condition debe ser un objeto JSON (dict).")

    # version
    if condition.get("version") != 1:
        raise ValidationError("condition.version debe ser 1.")

    # note (justificación)
    note = condition.get("note")
    if not isinstance(note, str) or not note.strip():
        raise ValidationError("condition.note es obligatorio y debe ser texto.")

    # match
    match = condition.get("match")
    if not isinstance(match, dict):
        raise ValidationError("condition.match es obligatorio y debe ser un objeto JSON.")

    allowed_match_keys = {"zones", "url_categories", "urls", "http_methods", "services"}
    unknown = set(match.keys()) - allowed_match_keys
    if unknown:
        raise ValidationError(
            f"condition.match contiene claves no permitidas: {sorted(unknown)}"
        )

    # al menos 1 criterio
    has_any = any(match.get(k) for k in allowed_match_keys)
    if not has_any:
        raise ValidationError(
            "condition.match debe tener al menos un criterio (zones/url_categories/urls/http_methods/services)."
        )

    # tipos
    if "zones" in match and not isinstance(match["zones"], list):
        raise ValidationError("condition.match.zones debe ser lista de zone_id.")
    if "url_categories" in match and not isinstance(match["url_categories"], list):
        raise ValidationError("condition.match.url_categories debe ser lista de category_id.")
    if "urls" in match and not isinstance(match["urls"], list):
        raise ValidationError("condition.match.urls debe ser lista de strings (dominios/urls).")
    if "http_methods" in match:
        if not isinstance(match["http_methods"], list) or not all(
            isinstance(x, str) for x in match["http_methods"]
        ):
            raise ValidationError("condition.match.http_methods debe ser lista de strings (GET/POST...).")
    if "services" in match:
        if not isinstance(match["services"], list):
            raise ValidationError("condition.match.services debe ser lista.")
        for s in match["services"]:
            if not isinstance(s, dict):
                raise ValidationError("Cada item de services debe ser objeto {protocol, port}.")
            if s.get("protocol") not in {"TCP", "UDP"}:
                raise ValidationError("services.protocol debe ser TCP o UDP.")
            port = s.get("port")
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ValidationError("services.port debe ser entero 1..65535.")

    # time (opcional)
    if "time" in condition and condition["time"] is not None:
        t = condition["time"]
        if not isinstance(t, dict):
            raise ValidationError("condition.time debe ser un objeto JSON.")

        days = t.get("days")
        start = t.get("start")
        end = t.get("end")
        tz = t.get("tz")

        if not isinstance(days, list) or not days:
            raise ValidationError("condition.time.days debe ser lista no vacía.")
        if any(d not in DAYS for d in days):
            raise ValidationError("condition.time.days inválido (use MON..SUN).")

        if not _is_time_hhmm(start) or not _is_time_hhmm(end):
            raise ValidationError("condition.time.start y end deben tener formato HH:MM.")

        if tz is None or not isinstance(tz, str) or not tz.strip():
            raise ValidationError("condition.time.tz es obligatorio (ej: America/Guayaquil).")


class Rule(SoftDeleteModel):
    rule_id = models.BigAutoField(primary_key=True)
    policy = models.ForeignKey(
        Policy,
        on_delete=models.CASCADE,
        db_column="policy_id",
        related_name="rules",
    )
    condition = models.JSONField()
    action = models.CharField(max_length=10, choices=RuleAction.choices)
    priority = models.IntegerField()
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "rule"
        constraints = [
            models.UniqueConstraint(
                fields=["policy", "priority"],
                condition=Q(is_delete=False),
                name="rule_policy_priority_active_uniq",
            )
        ]

    def __str__(self):
        return f"{self.policy.name}#{self.priority}:{self.action}"

    def clean(self):
        super().clean()
        validate_rule_condition(self.condition)

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)


class Zone(SoftDeleteModel):
    zone_id = models.BigAutoField(primary_key=True)
    zone_name = models.CharField(max_length=100)
    description = models.TextField(blank=True, default="")

    class Meta:
        db_table = "zone"
        constraints = [
            models.UniqueConstraint(
                fields=["zone_name"],
                condition=Q(is_delete=False),
                name="zone_zone_name_active_uniq",
            )
        ]

    def __str__(self):
        return self.zone_name


class Service(SoftDeleteModel):
    service_id = models.BigAutoField(primary_key=True)
    protocol = models.CharField(max_length=3, choices=NetProtocol.choices)
    port = models.PositiveIntegerField()
    name = models.CharField(max_length=100)

    class Meta:
        db_table = "service"
        constraints = [
            models.UniqueConstraint(
                fields=["protocol", "port"],
                condition=Q(is_delete=False),
                name="service_protocol_port_active_uniq",
            )
        ]

    def __str__(self):
        return f"{self.name} ({self.protocol}/{self.port})"
