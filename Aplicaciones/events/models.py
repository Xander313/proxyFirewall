from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.db.models import Q

from Aplicaciones.control.models import (
    HttpMethod,
    NetProtocol,
    Rule,
    RuleAction,
    Service,
    SoftDeleteModel,
    Url,
    User,
    Verdict,
    Zone,
)


class CacheStatus(models.TextChoices):
    HIT = "HIT", "HIT"
    MISS = "MISS", "MISS"
    BYPASS = "BYPASS", "BYPASS"
    EXPIRED = "EXPIRED", "EXPIRED"
    REVALIDATED = "REVALIDATED", "REVALIDATED"


class LogLevel(models.TextChoices):
    DEBUG = "DEBUG", "DEBUG"
    INFO = "INFO", "INFO"
    WARN = "WARN", "WARN"
    ERROR = "ERROR", "ERROR"
    CRITICAL = "CRITICAL", "CRITICAL"


class Request(SoftDeleteModel):
    request_id = models.BigAutoField(primary_key=True)
    ts = models.DateTimeField()
    client_ip = models.GenericIPAddressField(protocol="both", unpack_ipv4=True)
    client_port = models.PositiveIntegerField()
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        db_column="user_id",
        related_name="requests",
    )
    method = models.ForeignKey(
        HttpMethod,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        db_column="method_id",
        related_name="requests",
    )
    url = models.ForeignKey(
        Url,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        db_column="url_id",
        related_name="requests",
    )
    dest_ip = models.GenericIPAddressField(
        protocol="both", unpack_ipv4=True, null=True, blank=True
    )
    dest_port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(
        max_length=3,
        choices=NetProtocol.choices,
        null=True,
        blank=True,
    )
    http_status = models.PositiveIntegerField(null=True, blank=True)
    bytes_in = models.BigIntegerField(default=0)
    bytes_out = models.BigIntegerField(default=0)
    elapsed_ms = models.PositiveIntegerField(null=True, blank=True)
    cache_status = models.CharField(
        max_length=11,
        choices=CacheStatus.choices,
        null=True,
        blank=True,
    )
    verdict = models.CharField(max_length=5, choices=Verdict.choices, default=Verdict.ALLOW)
    block_reason = models.TextField(blank=True, default="")

    class Meta:
        db_table = "requests"

    def __str__(self):
        return f"Request {self.request_id} [{self.verdict}]"


class RuleMatch(SoftDeleteModel):
    match_id = models.BigAutoField(primary_key=True)
    request = models.ForeignKey(
        Request,
        on_delete=models.CASCADE,
        db_column="request_id",
        related_name="rule_matches",
    )
    rule = models.ForeignKey(
        Rule,
        on_delete=models.CASCADE,
        db_column="rule_id",
        related_name="matches",
    )
    action = models.CharField(max_length=10, choices=RuleAction.choices)
    matched_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "rule_match"

    def __str__(self):
        return f"Match {self.match_id}: rule={self.rule_id} action={self.action}"


class SecurityAlert(SoftDeleteModel):
    alert_id = models.BigAutoField(primary_key=True)
    request = models.ForeignKey(
        Request,
        on_delete=models.CASCADE,
        db_column="request_id",
        related_name="security_alerts",
    )
    engine = models.CharField(max_length=100)
    severity = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(10)]
    )
    signature = models.CharField(max_length=255)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "security_alert"

    def __str__(self):
        return f"Alert {self.alert_id} sev={self.severity}"


class FirewallEvent(SoftDeleteModel):
    fw_id = models.BigAutoField(primary_key=True)
    request = models.ForeignKey(
        Request,
        on_delete=models.CASCADE,
        db_column="request_id",
        related_name="firewall_events",
    )
    ts = models.DateTimeField()
    src_zone = models.ForeignKey(
        Zone,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        db_column="src_zone_id",
        related_name="source_firewall_events",
    )
    dst_zone = models.ForeignKey(
        Zone,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        db_column="dst_zone_id",
        related_name="destination_firewall_events",
    )
    service = models.ForeignKey(
        Service,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        db_column="service_id",
        related_name="firewall_events",
    )
    action = models.CharField(max_length=10, choices=RuleAction.choices)
    nat_info = models.JSONField(null=True, blank=True)

    class Meta:
        db_table = "firewall_event"

    def __str__(self):
        return f"FW {self.fw_id}: {self.action}"


class CacheEntry(SoftDeleteModel):
    cache_id = models.BigAutoField(primary_key=True)
    url = models.ForeignKey(
        Url,
        on_delete=models.CASCADE,
        db_column="url_id",
        related_name="cache_entries",
    )
    size = models.BigIntegerField()
    last_accessed = models.DateTimeField()
    expiration_time = models.DateTimeField()

    class Meta:
        db_table = "cache_entry"
        constraints = [
            models.UniqueConstraint(
                fields=["url"],
                condition=Q(is_delete=False),
                name="cache_entry_url_active_uniq",
            )
        ]

    def __str__(self):
        return f"Cache {self.cache_id} for URL {self.url_id}"


class ErrorLog(SoftDeleteModel):
    error_id = models.BigAutoField(primary_key=True)
    request = models.ForeignKey(
        Request,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        db_column="request_id",
        related_name="error_logs",
    )
    ts = models.DateTimeField()
    level = models.CharField(max_length=8, choices=LogLevel.choices, default=LogLevel.ERROR)
    message = models.TextField()
    component = models.CharField(max_length=100)

    class Meta:
        db_table = "error_log"

    def __str__(self):
        return f"Error {self.error_id} [{self.level}]"
