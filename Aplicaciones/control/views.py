from django.shortcuts import render


def control_index(request):
    return render(request, "control/control_index.html")
