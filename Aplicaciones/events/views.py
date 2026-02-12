import json
from django.shortcuts import render
from django.db.models import Count
from django.utils import timezone
from datetime import timedelta

from .models import Request, CacheEntry
from .squid_utils import squid_status, db_status
from django.contrib.auth.decorators import login_required




@login_required
def dashboard(request):
    total_requests = Request.objects.count()
    total_blocked = Request.objects.filter(verdict="DENY").count()

    blocked_pct = 0.0
    if total_requests > 0:
        blocked_pct = (total_blocked / total_requests) * 100.0

    # Última hora (evidencia “en vivo”)
    last_hour = timezone.now() - timedelta(hours=1)
    last_hour_requests = Request.objects.filter(ts__gte=last_hour).count()

    top_blocked_sites_qs = (
        Request.objects.filter(verdict="DENY", url__isnull=False)
        .values("url__host")
        .annotate(count=Count("pk"))
        .order_by("-count")[:10]
    )
    top_blocked_sites = [{"host": r["url__host"], "count": r["count"]} for r in top_blocked_sites_qs]

    top_ips_qs = (
        Request.objects.values("client_ip")
        .annotate(count=Count("pk"))
        .order_by("-count")[:10]
    )
    top_ips = [{"ip": r["client_ip"], "count": r["count"]} for r in top_ips_qs]

    cache_stats_qs = Request.objects.values("cache_status").annotate(count=Count("pk"))
    cache_stats = {r["cache_status"] or "UNKNOWN": r["count"] for r in cache_stats_qs}

    cache_entries_count = CacheEntry.objects.count()
    dbinfo = db_status()

    recent_requests = list(Request.objects.select_related("url").order_by("-ts")[:12])

    context = {
        "total_requests": total_requests,
        "total_blocked": total_blocked,
        "blocked_pct": blocked_pct,
        "last_hour_requests": last_hour_requests,
        "top_blocked_sites": top_blocked_sites,
        "top_ips": top_ips,
        "cache_stats": cache_stats,
        "cache_entries_count": cache_entries_count,
        "chart_data": json.dumps(
            {
                "top_blocked_sites": top_blocked_sites,
                "top_ips": top_ips,
                "cache_stats": cache_stats,
            }
        ),
        "squid_status": squid_status(),
        "db_status": dbinfo,
        "recent_requests": recent_requests,
    }
    return render(request, "events/dashboard.html", context)
