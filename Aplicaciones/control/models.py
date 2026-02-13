from django.db import models
from django.db.models import Q
from django.db.models.functions import Upper
from django.utils import timezone
from django.core.exceptions import ValidationError


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
    ALLOW = "ALLOW", "PERMITIR"
    DENY = "DENY", "BLOQUEAR"
    ALERT = "ALERT", "ALERTAR"
    LOG_ONLY = "LOG_ONLY", "SOLO_REGISTRO"


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
# Rule schedule constants
# -------------------------
DAYS = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")
DAYS_SET = set(DAYS)


class Rule(SoftDeleteModel):
    rule_id = models.BigAutoField(primary_key=True)
    policy = models.ForeignKey(
        Policy,
        on_delete=models.CASCADE,
        db_column="policy_id",
        related_name="rules",
    )
    url_category = models.ForeignKey(
        UrlCategory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        db_column="url_category_id",
        related_name="rules",
    )
    note = models.TextField(default="")
    schedule_days = models.CharField(max_length=64, blank=True, default="")
    schedule_start = models.TimeField(null=True, blank=True)
    schedule_end = models.TimeField(null=True, blank=True)
    schedule_tz = models.CharField(max_length=80, blank=True, default="America/Guayaquil")
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

    @property
    def schedule_days_list(self):
        if not self.schedule_days:
            return []
        return [d for d in self.schedule_days.split(",") if d]

    @schedule_days_list.setter
    def schedule_days_list(self, values):
        clean = [str(v).strip().upper() for v in (values or []) if str(v).strip()]
        self.schedule_days = ",".join(clean)

    def clean(self):
        super().clean()
        if not self.note or not self.note.strip():
            raise ValidationError("La nota de la regla es obligatoria.")

        if not self.url_category_id:
            raise ValidationError("Debes seleccionar una categoria URL.")

        days = self.schedule_days_list
        has_schedule = bool(days or self.schedule_start or self.schedule_end)
        if has_schedule:
            if not days or not self.schedule_start or not self.schedule_end or not self.schedule_tz:
                raise ValidationError(
                    "Para horario debes completar dias, hora inicio, hora fin y zona horaria."
                )

            invalid_days = [d for d in days if d not in DAYS_SET]
            if invalid_days:
                raise ValidationError(
                    f"Dias de horario invalidos: {', '.join(invalid_days)}. Usa MON..SUN."
                )

            if self.schedule_start >= self.schedule_end:
                raise ValidationError("La hora de inicio debe ser menor a la hora fin.")

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
