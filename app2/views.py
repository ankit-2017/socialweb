from django.shortcuts import *
from django.http import *
from datetime import *
from .models import *
from .forms import *
from django.conf import settings
from django.contrib import auth
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.contrib import messages

from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.db.models import Q
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template import loader
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from mysite.settings import EMAIL_HOST_USER
from django.views.generic import *
from .forms import PasswordResetRequestForm, SetPasswordForm
from django.contrib.auth import  REDIRECT_FIELD_NAME
from django.template import RequestContext
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ObjectDoesNotExist
try:
    from django.utils import simplejson as json
except ImportError:
    import json


def home(request):
	data=student.objects.all()
	clg=collage.objects.all().order_by('-event_date')

	return render(request,'event.html',{'abc':data,'event':clg})


def del1(request,d):
	data2=student.objects.get(id=d)
	data2.delete()
	return HttpResponseRedirect('/')

def form(request):
	if request.method=='POST':
		form=myform(request.POST)
		if form.is_valid():
			form.save()
			return HttpResponseRedirect('/')
	else:
		form=myform()

	return render(request,'contact.html',{'form':form})


def search(request):
	bl=blog1.objects.all().order_by('-dat')
	if request.method=='POST':
		sq=request.POST['tx']
		if sq :

			start=User.objects.filter(comment__icontains=sq)

			if start:
				return render(request,'search.html',{'result':start})
			else:
				return render(request,'error.html')
		else:
			return HttpResponseRedirect('/')


	return render(request,'search.html',{'blg':bl})

def search_title(request):
	if request.method=='POST':
		sq=request.POST['srch']
		if sq :
			start=blog1.objects.filter(user1__first_name__icontains=sq)
			if start:

				return render(request,'searchpost.html',{'bl':start})
			else:
				return render(request,'error.html')
		else:
			return HttpResponseRedirect('/myblog/')

def delete1(request,d):
	data3=blog1.objects.get(id=d)
	data3.delete()
	return HttpResponseRedirect('/myblog/dashboard/')

def login_page(request):
	if request.user.is_authenticated:
		return HttpResponseRedirect('/myblog/')
	else:
		if request.method=='POST':
			form=regform(request.POST)
			if form.is_valid():
				username=form.cleaned_data['username']
				first_name=form.cleaned_data['first_name']
				last_name=form.cleaned_data['last_name']
				email=form.cleaned_data['email']
				password=form.cleaned_data['password']
				User.objects.create_user(username=username,first_name=first_name,last_name=last_name,email=email,password=password)
				user=auth.authenticate(username=username,password=password)
				auth.login(request,user)
				return HttpResponseRedirect('/myblog/')

		else:
			form=regform()


		return render(request,'login1.html',{'form2':form})


def login(request):
	form = regform()
	if request.user.is_authenticated:
		return HttpResponseRedirect('/myblog/')

	else:
		#redirect_to = redirect_field_name
		r = request.GET.get('next')
		print(r)
		if r is None:
			r = '/myblog/'
		if request.method=='POST':
			username = request.POST['username']
			password = request.POST['password']

			user = auth.authenticate(username=username, password=password)
			if user is not None:
				auth.login(request, user)
				print(r)
				return HttpResponseRedirect(r)
			else:
				messages.error(request, "Username and password not matched")

	return render(request, 'login1.html', {'form2': form})

@login_required(login_url='/auth-check/')
def myblog(request):
	if request.user.is_authenticated:

		#lk_id = request.POST['valu']
		#print(lk_id)
		user = request.user
		detl = message.objects.filter(reciver=user).order_by('-dat2')[:6]
		new_msg_count = new_message.objects.filter(reciver=user)
		for k in new_msg_count:
			k.delete()


		noti = notification.objects.filter(Q(notiuser=request.user) | Q(to_user=request.user)).order_by('-dat2')[:6]
		friend_request = friend.objects.filter(Q(to_friend=request.user) & Q(friend_or_not=False)).order_by('-dat2')
		friends = friend.objects.filter(
			(Q(friend_or_not=True) & Q(sender=request.user)) | (Q(friend_or_not=True) & Q(to_friend=request.user)))

		form = replyform()
		detail = blog1.objects.all().order_by('-dat')
		like_all = forlike.objects.all()
		for j in detail:
			try:
				lk1 = forlike.objects.filter(withblog=j.id,like_user=request.user)
				like_count = forlike.objects.filter(withblog=j.id,like='Liked').count()
				j.like3 = lk1
				j.like_count = like_count
			except forlike.DoesNotExist:
				print('no like found')




		#noti=notification.objects.get(notiuser=request.user)
		for one in detail:
			reply= replytocomment.objects.filter(replyblog=one).order_by('-dat1')[:4]
			number_of_reply = str(replytocomment.objects.filter(replyblog=one).count())
			one.reply= reply
			one.number_of_reply=number_of_reply

		if request.method=='POST':
				form1=blogg(request.POST,request.FILES)
				if form1.is_valid():
					fil1=form1.save(commit=False)
					fil1.user1=request.user
					fil1.save()
					user2=request.user
					msg = "%s posted something" %user2
					rlp = notification(notiuser=request.user, notif=msg)
					rlp.save()
					return HttpResponseRedirect('/myblog/')
				else:
					messages.error(request,'form not submited')
		else:
			form1 = blogg()
		return render(request,'blog.html',{'bl':detail,'form1':form1,'rform':form,
										   'detl':detl, 'count_new':new_msg_count,'noti':noti,'fr':friend_request,
										   'friends':friends })
	else:
		messages.error(request, "Anonymous User!  Login with correct credentials")
		return HttpResponseRedirect('/')

@login_required(login_url='/auth-check/')
def profile(request, d):
	user= request.user
	if request.method == 'POST':
		form=profile1(request.POST,request.FILES)
		if form.is_valid():
			user.first_name = form.cleaned_data['first_name']
			user.last_name = form.cleaned_data['last_name']
			user.email = form.cleaned_data['email']
			user.profile.dob = form.cleaned_data['dob']
			user.profile.profile_pic= form.cleaned_data['profile_pic']
			user.profile.mobile_number = form.cleaned_data['mobile_number']
			user.profile.job_title = form.cleaned_data['job_title']
			user.profile.location = form.cleaned_data['location']
			user.profile.collage = form.cleaned_data['collage']
			user.save()
			msg = "You Updated your profile"
			rlp = notification(notiuser=request.user, notif=msg)
			rlp.save()
			return HttpResponseRedirect('/myblog/')
	else:
		form = profile1(instance=user, initial={'dob':user.profile.dob,
			'mobile_number':user.profile.mobile_number,'job_title':user.profile.job_title,
				'location':user.profile.location, 'collage':user.profile.collage})
	return render(request,'profile.html',{'form':form})

def logout(request):
	auth.logout(request)
	return HttpResponseRedirect('/')
# code for password reset

class ResetPasswordRequestView(FormView):
    # code for template is given below the view's code
    template_name = "account/test_template.html"
    success_url = '/admin/'
    form_class = PasswordResetRequestForm

    @staticmethod
    def validate_email_address(email):

        try:
            validate_email(email)
            return True
        except ValidationError:
            return False

    def reset_password(self, user, request):
        c = {
            'email': user.email,
            'domain': request.META['HTTP_HOST'],
            'site_name': 'your site',
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'user': user,
            'token': default_token_generator.make_token(user),
            'protocol': 'http',
        }
        subject_template_name = 'registration/password_reset_subject.txt'
        # copied from
        # django/contrib/admin/templates/registration/password_reset_subject.txt
        # to templates directory
        email_template_name = 'registration/password_reset_email.html'
        # copied from
        # django/contrib/admin/templates/registration/password_reset_email.html
        # to templates directory
        subject = loader.render_to_string(subject_template_name, c)
        # Email subject *must not* contain newlines
        subject = ''.join(subject.splitlines())
        email = loader.render_to_string(email_template_name, c)
        send_mail(subject, email, EMAIL_HOST_USER,
                  [user.email], fail_silently=False)

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        try:
            if form.is_valid():
                data = form.cleaned_data["email_or_username"]
            # uses the method written above
            if self.validate_email_address(data) is True:
                '''
                If the input is an valid email address, then the following code will lookup for users associated with that email address. If found then an email will be sent to the address, else an error message will be printed on the screen.
                '''
                associated_users = User.objects.filter(
                    Q(email=data) | Q(username=data))
                if associated_users.exists():
                    for user in associated_users:
                        self.reset_password(user, request)

                    result = self.form_valid(form)
                    messages.success(
                        request, 'An email has been sent to {0}. Please check its inbox to continue reseting password.'.format(data))
                    return result
                result = self.form_invalid(form)
                messages.error(
                    request, 'No user is associated with this email address')
                return result
            else:
                '''
                If the input is an username, then the following code will lookup for users associated with that user. If found then an email will be sent to the user's address, else an error message will be printed on the screen.
                '''
                associated_users = User.objects.filter(username=data)
                if associated_users.exists():
                    for user in associated_users:
                        self.reset_password(user, request)
                    result = self.form_valid(form)
                    messages.success(
                        request, "Email has been sent to {0}'s email address. Please check its inbox to continue reseting password.".format(data))
                    return result
                result = self.form_invalid(form)
                messages.error(
                    request, 'This username does not exist in the system.')
                return result
            messages.error(request, 'Invalid Input')
        except Exception as e:
            print(e)
        return self.form_invalid(form)


class PasswordResetConfirmView(FormView):
    template_name = "account/test_template.html"
    success_url = '/admin/'
    form_class = SetPasswordForm

    def post(self, request, uidb64=None, token=None, *arg, **kwargs):
        """
        View that checks the hash in a password reset link and presents a
        form for entering a new password.
        """
        UserModel = get_user_model()
        form = self.form_class(request.POST)
        assert uidb64 is not None and token is not None  # checked by URLconf
        try:
            uid = urlsafe_base64_decode(uidb64)
            user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            if form.is_valid():
                new_password = form.cleaned_data['new_password2']
                user.set_password(new_password)
                user.save()
                messages.success(request, 'Password has been reset.')
                return self.form_valid(form)
            else:
                messages.error(
                    request, 'Password reset has not been unsuccessful.')
                return self.form_invalid(form)
        else:
            messages.error(
                request, 'The reset password link is no longer valid.')
            return self.form_invalid(form)

@login_required(login_url='/auth-check/')
def profile_detail(request, d):
	if request.user.is_authenticated:

		detail= User.objects.get(id=d)
		#al = blog1.objects.filter(slug__icontains=slug)
		#al= al.exclude(id=d)

		#others = blog1.objects.order_by('-dat')
		#others = others.exclude(id=d)[:4]

		return render(request,'profile_detail.html',{'detail':detail})
	else:
		messages.error(request, "Anonymous User!  Login with correct credentials")
		return redirect('%s?next=%s' %(settings.LOGIN_URL1,request.path))

def reply(request, d):
	blg=blog1.objects.get(id=d)
	form1=blogg()
	d = blog1.objects.all().order_by('-dat')
	if request.method=='POST':
		form=replyform(request.POST)
		if form.is_valid():
			unsave=form.save(commit=False)
			unsave.replyuser=request.user
			unsave.replyblog=blg
			unsave.save()
			msg = " %s commented on %s %s's post" %(request.user ,blg.user1.first_name,blg.user1.last_name)
			rlp =notification(notiuser=request.user,to_user=blg.user1,notif=msg)
			rlp.save()
			return HttpResponseRedirect('/myblog/')
	else:
		form=replyform()
	return render(request,'blog.html',{'bl':d,'form1':form1,'rform':form})

def showall(request):
	detail = blog1.objects.all().order_by('-dat')

	for one in detail:
		reply = replytocomment.objects.filter(replyblog=one).order_by('-dat1')
		number_of_reply = str(replytocomment.objects.filter(replyblog=one).count())
		one.reply = reply
		one.number_of_reply = number_of_reply

	if request.method == 'POST':
		form1 = blogg(request.POST, request.FILES)
		if form1.is_valid():
			fil1 = form1.save(commit=False)
			fil1.user1 = request.user
			fil1.save()
			return HttpResponseRedirect('/myblog/')
		else:
			messages.error(request, 'form not submited')
	else:
		form1 = blogg()
		form = replyform()
	return render(request, 'blog.html', {'bl': detail, 'form1': form1, 'rform': form})


def helpful(request,d):
	obj=blog1.objects.get(id=d)
	obj.helpful +=1
	obj.save(update_fields=['helpful'])
	msg = "%s found %s %s's post helpful" %(request.user,obj.user1.first_name ,obj.user1.last_name)
	nt = notification(notiuser=request.user,to_user=obj.user1,notif=msg)
	nt.save()
	return HttpResponseRedirect('/myblog/')

@login_required(login_url='/auth-check/')
def dashboard(request):
	if request.user.is_authenticated:

		user=request.user
		udetail = blog1.objects.filter(user1=user)
		shared1 = shared.objects.filter(to_frnd=request.user).order_by('-dat2')
		detl = message.objects.filter(reciver=user).order_by('-dat2')[:6]
		new_msg_count = new_message.objects.filter(reciver=user)
		for k in new_msg_count:
			k.delete()
		obj = User.objects.filter(
			Q(profile__job_title__icontains=request.user.profile.job_title) | Q(profile__location__icontains=request.user.profile.location)

			)
		obj = obj.exclude(username=request.user)
		usrnm = friend.objects.filter(friend_or_not=True)
		for ur in usrnm:
			obj = obj.exclude(username=ur.sender)
			obj = obj.exclude(username=ur.to_friend)

		#noti=notification.objects.filter( Q(notiuser=request.user) | Q(to_user=request.user)).order_by('-dat2')[:6]
		friend_request = friend.objects.filter(Q(to_friend=request.user) & Q(friend_or_not=False)).order_by('-dat2')
		friends = friend.objects.filter(
			(Q(friend_or_not=True) & Q(sender=request.user)) | (Q(friend_or_not=True) & Q(to_friend=request.user)))
		for one in udetail:
			reply = replytocomment.objects.filter(replyblog=one).order_by('-dat1')[:4]
			number_of_reply = str(replytocomment.objects.filter(replyblog=one).count())
			one.reply = reply
			one.number_of_reply = number_of_reply

		return render(request,  'dashboard.html',
					  {'udetail':udetail, 'detl':detl, 'count_new':new_msg_count,'obj1':obj,
					   'fr':friend_request, 'friends':friends,'sh':shared1})
	else:
		messages.error(request,"Annonymous User!  Login with correct cridentials")
		return redirect('%s?next=%s' % (settings.LOGIN_URL1, request.path))

def delete_reply(request, d):
	rpl = replytocomment.objects.get(id=d)
	rpl.delete()
	return  HttpResponseRedirect('/myblog/dashboard/')


@login_required(login_url='/auth-check/')
def message1(request):
	if request.user.is_authenticated:

		user = request.user
		detl = message.objects.filter(reciver=user).order_by('-dat2')


		if request.method == 'POST':
			uid = request.POST['hdn']
			rcv = User.objects.get(id=uid)
			form1 = msg_form(request.POST)
			form2 = new_msg_form(request.POST)
			if form1.is_valid:
				usr = form1.save(commit=False)
				usr.msg_user = request.user
				usr.reciver = rcv.username
				usr.save()

				nm = new_message(new_msg_user=request.user, reciver=rcv.username, new_msg=form1.cleaned_data['msg'])
				nm.save()
				return  HttpResponseRedirect('/myblog/dashboard/message/')

		else:
			form1 = msg_form()
		return render(request, 'message.html', {'detl':detl, 'form1':form1})
	else:
		messages.error(request, "Anonymous User!  Login with correct credentials")
		return redirect('%s?next=%s' % (settings.LOGIN_URL1, request.path))


def delete_msg(request, d):
	msg_delete = message.objects.get(id=d)
	msg_delete.delete()
	return HttpResponseRedirect('/myblog/dashboard/message/')



@login_required(login_url='/auth-check/')
def add_friend(request, d):
	if request.user.is_authenticated:

		to = User.objects.get(id=d)
		fobj = friend.objects.filter(Q(to_friend__username=to) & Q(sender=request.user))
		ald = friend.objects.filter(Q(sender__username=to.username) & Q(to_friend=request.user))

		if fobj:
			messages.error(request,"You already sent friend request to %s %s" %(to.first_name, to.last_name))
			return HttpResponseRedirect('/myblog/dashboard/')
		elif ald:
			messages.error(request,"You have already a friend request from %s %s" %(to.first_name, to.last_name))
			return HttpResponseRedirect('/myblog/dashboard/')
		else:
			req=friend(sender=request.user,to_friend=to)
			req.save()
			msg = " %s %s send Friend Request to %s %s " % (request.user.first_name,request.user.last_name,to.first_name, to.last_name)
			rlp = notification(notiuser=request.user, to_user=to, notif=msg)
			rlp.save()
			messages.success(request,"Friend request is sent to %s %s" %(to.first_name, to.last_name))
			return HttpResponseRedirect('/myblog/dashboard/')
	else:
		messages.error(request,"Anonymous User!  Login with correct credentials")
		return HttpResponseRedirect('/')

def accept(request, d):
	if request.user.is_authenticated:

		acc = friend.objects.get(id =d)
		acc.friend_or_not=True
		acc.save()
		messages.success(request,"%s %s and %s %s are now Friend" %(acc.sender.first_name,acc.sender.last_name,
																	acc.to_friend.first_name,acc.to_friend.last_name))
		msg = " %s %s are now friend %s %s " % (
		request.user.first_name, request.user.last_name, acc.sender.first_name, acc.sender.last_name)
		rlp = notification(notiuser=request.user, to_user=acc.sender, notif=msg)
		rlp.save()

		#return render(request, 'dashboard.html', {'ms': ms2})
		return HttpResponseRedirect('/myblog/dashboard/')
	else:
		messages.error(request, "Anonymous User!  Login with correct credentials")
		return HttpResponseRedirect('/')

def reject(request, d):
	acc = friend.objects.get(id =d)
	acc.delete()
	ms3=" friend request of %s %s  is rejected" %(acc.sender.first_name,acc.sender.last_name)
	return render(request, 'dashboard.html', {'ms': ms3})



@login_required(login_url='/auth-check/')
def friends(request):
	if request.user.is_authenticated:

		if friend.objects.filter(to_friend=request.user):
			fobj = friend.objects.filter(Q(to_friend=request.user) & Q(friend_or_not=True))
			return render(request, 'all_friend.html', {'to_friend': fobj})
		elif friend.objects.filter(sender=request.user):
			fobj1 = friend.objects.filter(Q(sender=request.user) & Q(friend_or_not=True))

			return render(request, 'all_friend.html', {'sender': fobj1})
	else:
		messages.error(request, "Anonymous User!  Login with correct credentials")
		return redirect('%s?next=%s' % (settings.LOGIN_URL1, request.path))

@login_required(login_url='/auth-check/')
def fdashboard(request, d,username):
	if request.user.is_authenticated:

		fd = User.objects.get(username=username)
		fd1 = blog1.objects.filter(user1__username=username)

		return render(request,'friend_dashboard.html', {'fdash':fd, 'u_post':fd1})
	else:
		messages.error(request, "Anonymous User!  Login with correct credentials")


def search_status(request):

	if request.method == "GET":
		search_text = request.GET['srch']
		if search_text is not None and search_text != u"":
			search_text = request.GET['srch']

			status = User.objects.filter(Q(first_name__istartswith = search_text) |
										 Q(last_name__istartswith = search_text) |
										 Q(username__istartswith= search_text) |
										 Q(email__istartswith=search_text)
										 )
		else:
			status = []

	return render(request, 'search-result.html', {'stats':status} )


@login_required(login_url='/auth-check/')
def shared_post(request, d):
	if request.user.is_authenticated:

		s_comment = blog1.objects.get(id=d)

		if friend.objects.filter(to_friend=request.user):
			fobj = friend.objects.filter(Q(to_friend=request.user) & Q(friend_or_not=True))
			return render(request, 'to_share.html', {'to_friend': fobj,'scom':s_comment})
		elif friend.objects.filter(sender=request.user):
			fobj1 = friend.objects.filter(Q(sender=request.user) & Q(friend_or_not=True))

			return render(request, 'to_share.html', {'sender': fobj1, 'scom':s_comment})

		share_id =d
	else:
		return redirect('%s?next=%s' % (settings.LOGIN_URL1, request.path))


	#return render(request, 'to_share.html', {'scom':s_comment})

def now_share(request,d,n):
	all1 = blog1.objects.get(id=n)
	u = User.objects.get(id=d)


	inst=shared(s_user=request.user,to_frnd=u,s_comment=all1.comment)
	inst.save()
	messages.success(request,"Post shared to %s %s" %(u.first_name.upper(), u.last_name.upper()) )

	if friend.objects.filter(to_friend=request.user):
		fobj = friend.objects.filter(Q(to_friend=request.user) & Q(friend_or_not=True))
		return render(request, 'to_share.html', {'to_friend': fobj, 'scom': all1})
	elif friend.objects.filter(sender=request.user):
		fobj1 = friend.objects.filter(Q(sender=request.user) & Q(friend_or_not=True))

		return render(request, 'to_share.html', {'sender': fobj1, 'scom': all1})
@csrf_exempt
def like1(request):

		d = request.POST['valu']
		lk = blog1.objects.get(id=d)
		user2=lk.user1
		print(user2)
		try:
			if forlike.objects.get(withblog=d,like_user=request.user,to_like=user2):
				try:
					obj2 = forlike.objects.get(withblog=d,like_user=request.user,to_like=user2,like='Liked')
					obj2.like=''
					obj2.save(update_fields=['like'])
				except forlike.DoesNotExist:
					obj3 = forlike.objects.get(withblog=d, like_user=request.user, to_like=user2,like='')
					obj3.like = 'Liked'
					obj3.save(update_fields=['like'])

		except forlike.DoesNotExist:
			sv = forlike(like_user=request.user,to_like=user2, withblog=d, like='Liked')
			sv.save()

		try:
			obj = forlike.objects.filter(withblog=d,like='Liked').count()
		except forlike.DoesNotExist:
			print('no like found')

		obj1 = forlike.objects.get(withblog=d,like_user=request.user,to_like=user2)
		ctx = {'like1':obj1.like,'lcount':obj}


		return HttpResponse(json.dumps(ctx), content_type='application/json')

def delete_shared(request, d):
	dt = shared.objects.get(id=d)
	dt.delete()
	return  HttpResponseRedirect('/myblog/dashboard/')






