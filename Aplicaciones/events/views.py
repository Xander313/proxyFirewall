import json
from django.shortcuts import render
from django.db.models import Count

from .models import Request, CacheEntry
from .squid_utils import squid_status, db_status


def dashboard(request):
	"""Dashboard para evidencias: bloqueos, sitios más bloqueados, IPs/usuarios activos, caché."""
	total_requests = Request.objects.count()
	total_blocked = Request.objects.filter(verdict="DENY").count()

	# Top sitios bloqueados (por host)
	top_blocked_sites_qs = (
		Request.objects.filter(verdict="DENY", url__isnull=False)
		.values("url__host")
		.annotate(count=Count("pk"))
		.order_by("-count")[:10]
	)
	top_blocked_sites = [
		{"host": r["url__host"], "count": r["count"]} for r in top_blocked_sites_qs
	]

	# Top IPs (más actividad)
	top_ips_qs = (
		Request.objects.values("client_ip")
		.annotate(count=Count("pk"))
		.order_by("-count")[:10]
	)
	top_ips = [{"ip": r["client_ip"], "count": r["count"]} for r in top_ips_qs]

	# Cache stats (HIT/MISS/other)
	cache_stats_qs = (
		Request.objects.values("cache_status").annotate(count=Count("pk"))
	)
	cache_stats = {r["cache_status"] or "UNKNOWN": r["count"] for r in cache_stats_qs}

	# Simple cache entries summary
	cache_entries_count = CacheEntry.objects.count()

	# DB status check
	dbinfo = db_status()

	context = {
		"total_requests": total_requests,
		"total_blocked": total_blocked,
		"top_blocked_sites": top_blocked_sites,
		"top_ips": top_ips,
		"cache_stats": cache_stats,
		"cache_entries_count": cache_entries_count,
		# JSON para las gráficas en el template
		"chart_data": json.dumps(
			{
				"top_blocked_sites": top_blocked_sites,
				"top_ips": top_ips,
				"cache_stats": cache_stats,
			}
		),
		"squid_status": squid_status(),
		"db_status": dbinfo,
		# recent requests for table
		"recent_requests": list(Request.objects.select_related('url').order_by('-ts')[:12]),
	}
	return render(request, "events/dashboard.html", context)
