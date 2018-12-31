from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
#from django.core.validators import FileExtensionValidator
from django.core.exceptions import ValidationError
from django.contrib import messages

	
class collage(models.Model):
	clg_name=models.CharField(max_length=200)
	type_of_event=models.CharField(max_length=100)
	event1=models.CharField(max_length=100)
	event2=models.CharField(max_length=100)
	event3=models.CharField(max_length=100,null=True,blank=True)
	event4=models.CharField(max_length=100,null=True,blank=True)
	event5=models.CharField(max_length=100,null=True,blank=True)
	event6=models.CharField(max_length=100,null=True,blank=True)
	Adress=models.CharField(max_length=200)
	event_date=models.DateTimeField(auto_now=True)

	def __str__(self):
		return self.clg_name

class forlike(models.Model):
	like_user=models.ForeignKey(User,blank=True,on_delete=models.CASCADE,related_name='like_user')
	to_like = models.ForeignKey(User, blank=True,on_delete=models.CASCADE, related_name='to_like')
	withblog = models.IntegerField( blank=True, null=True, default=0)
	like = models.CharField(max_length=10, blank=True)
	dat5 = models.DateTimeField(auto_now=True)

	def __str__(self):
		return self.like_user.username


class blog1(models.Model):

	def validate_size(image):
		filesize= image.file.size
		MB_limit = 1.0
		if filesize > MB_limit*1024*1024 :
			raise ValidationError( 'exceed max file size %sMB' %str(MB_limit))


	user1=models.ForeignKey(User,blank=True,null=True, related_name='user1', on_delete=models.CASCADE)
	#likemod = models.ForeignKey(forlike, blank=True, null=True)
	comment=models.TextField()
	image=models.ImageField(upload_to='user_images',blank=True)

	#image = models.ImageField(upload_to='user_images', blank=True,
							  #validators=[FileExtensionValidator(allowed_extensions=['jpg', 'png']), validate_size])

	helpful =models.IntegerField(blank=True,null=True, default=0)
	like_acc = models.ForeignKey(forlike, blank=True, null=True, related_name='like_acc', on_delete=models.CASCADE)
	slug= models.SlugField(max_length=250, null=True)
	not_helpful=models.IntegerField(null=True,blank=True)
	dat=models.DateTimeField(auto_now=True)

	def __str__(self):
		return self.user1.username

class profile(models.Model):

	def validate_size(user_profile_pic):
		filesize=profile_pic.file.size
		allow = 1.0
		if filesize > allow*1024*1024:
			raise ValidationError("Profile image size should be less than 1 MB ")

	user=models.OneToOneField(User, on_delete=models.CASCADE)
	dob=models.DateField(blank=True,null=True)
	profile_pic=models.ImageField(upload_to='user_images',blank=True,null=True)
	mobile_number=models.CharField(max_length=10)
	job_title = models.CharField(max_length=250, null=True)
	location = models.CharField(max_length=250,null=True)
	collage = models.CharField(max_length=250,null=True)

class replytocomment(models.Model):
	replyuser= models.ForeignKey(User,blank=True,null=True, on_delete=models.CASCADE)
	replyblog=models.ForeignKey(blog1,blank=True,null=True, on_delete=models.CASCADE)
	reply=models.CharField(max_length=500,null=True, blank=True)
	dat1 = models.DateTimeField(auto_now=True)

	def __str__(self):
		return self.reply

class message(models.Model):
	msg_user = models.ForeignKey(User, blank=True, null=True, on_delete=models.CASCADE)
	reciver = models.CharField(blank=True, null=True, max_length=100)
	msg = models.TextField(max_length=500, blank=True, null=True)
	dat2 = models.DateTimeField(auto_now=True)

	def __str__(self):
		return  self.msg

class new_message(models.Model):
	new_msg_user = models.ForeignKey(User, blank=True, null=True, on_delete=models.CASCADE)
	reciver = models.CharField(blank=True, null=True, max_length=100)
	new_msg = models.TextField(max_length=500, blank=True, null=True)
	dat2 = models.DateTimeField(auto_now=True)

	def __str__(self):
		return self.new_msg

class notification(models.Model):
	notiuser=models.ForeignKey(User,blank=True,null=True,related_name='notiuser', on_delete=models.CASCADE)
	to_user = models.ForeignKey(User,blank=True,null=True,related_name='to_user',on_delete=models.CASCADE)
	notif=models.CharField(blank=True,null=True,max_length=200)
	dat2=models.DateTimeField(auto_now=True)

	def __str__(self):
		return self.notif

class friend(models.Model):
	sender=models.ForeignKey(User,blank=True,null=True, related_name='sender', on_delete=models.CASCADE)
	to_friend = models.ForeignKey(User,blank=True,null=True, related_name='to_friend', on_delete=models.CASCADE)
	friend_or_not=models.BooleanField(default=False)
	dat2=models.DateTimeField(auto_now=True)

	def __str__(self):
		return self.sender.username

class shared(models.Model):
	s_user=models.ForeignKey(User,blank=True,null=True, related_name='s_user', on_delete=models.CASCADE)
	to_frnd = models.ForeignKey(User, blank=True, null=True, related_name='to_frnd', on_delete=models.CASCADE)
	s_comment = models.CharField(blank=True,null=True, max_length=500)
	dat2=models.DateTimeField(auto_now=True)

	def __str__(self):
		return self.s_user.username


def create_profile(sender, **kwargs):
	if kwargs['created']:
			profile.objects.create(user=kwargs['instance'])

def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()

post_save.connect(create_profile, sender=User)
post_save.connect(save_user_profile,sender=User)

# Create your models here.
