
from django.conf.urls import include,url
from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from app2.views import *
from app2.views import ResetPasswordRequestView,PasswordResetConfirmView

urlpatterns = [
	url(r'^myform/$',form),
    url('^reset_password', include('django.contrib.auth.urls')),
	url(r'^del1/(\d+)/$',del1),
	url(r'^$',login_page),
    url(r'^admin/', admin.site.urls),
    url(r'^myblog/dashboard/delete/(\d+)/$',delete1),
    url(r'^myblog/dashboard/delete_reply/(\d+)/$',delete_reply),
    url(r'^search/$',search),
    url(r'^home/$',home),
    url(r'^myblog/search_status/',search_status, name='searchh'),
    url(r'^myblog/dashboard/$',dashboard),
    #for login
    url(r'^auth-check/$',login,name="check"),
    url(r'^myblog/$',myblog),
    url(r'^myblog/profile/(\d+)/$',profile),#user profile updations
    url(r'^logout/$',logout),
    url(r'^reset_password/verify/(?P<uidb64>[0-9A-Za-z]+)-(?P<token>.+)/$',
            PasswordResetConfirmView.as_view(),name='reset_password_confirm'),

    url(r'^forgot1/$',ResetPasswordRequestView.as_view()),
    url(r'^myblog/profile_detail/(\d+)/$',profile_detail), # user (\w+) for slug field
    url(r'^myblog/reply/(\d+)/$',reply),
    url(r'^myblog/showall/$',showall),
    url(r'^myblog/helpful/(\d+)/$',helpful),
    url(r'^myblog/like/', like1, name='like'),
    url(r'^myblog/dashboard/rply_message/',message1),
    url(r'^myblog/dashboard/message/$',message1),
    url(r'^myblog/dashboard/message/delete_message/(\d+)/$',delete_msg),
    url(r'^myblog/dashboard/delete_shared/(\d+)/$',delete_shared),
    url(r'^myblog/dashboard/add_friend/(\d+)/$',add_friend),
    url(r'myblog/dashboard/accept/(\d+)/$',accept),
    url(r'myblog/dashboard/reject/(\d+)/$',reject),
    url(r'^myblog/dashboard/friends/$',friends),
    url(r'^myblog/dashboard/fdash/(\d+)/(\w+)/$',fdashboard),
    url(r'^myblog/to_share/(\d+)/$',shared_post),
    url(r'^myblog/now_share/(\d+)/(\d+)/$',now_share),
    url(r'^accounts/', include('allauth.urls')),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


