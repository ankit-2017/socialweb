from django.shortcuts import *
from django.http import *
from .models import *
from django.db.models import Q


class mfn():
    def forall(request):
        user = request.user
        noti=notification.objects.filter( Q(notiuser=request.user) | Q(to_user=request.user)).order_by('-dat2')[:6]
