from django import forms
from .models import *
from django.contrib.auth.models import User
from django.db.models.signals import post_save
import os
#from django.core.validators import FileExtensionValidator
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
import django.contrib.auth.password_validation



class blogg(forms.ModelForm):

	comment=forms.CharField(widget=forms.Textarea(attrs={'class':'form-control','placeholder':'Comment here','rows':4}),
							max_length=500,required=True)
	image=forms.FileField(
		help_text="Upload a image",
		required=False)

	#image = forms.FileField(validators=[FileExtensionValidator(allowed_extensions=['jpg', 'png', 'jpeg'])],
							#help_text="Upload a image",
							#required=False)

	class Meta:
		model=blog1
		fields=['comment','image']
class replyform(forms.ModelForm):
	reply = forms.CharField(
		widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Reply to comment'}),
		max_length=500, required=True)

	class Meta:
		model=replytocomment
		fields=['reply']

# custom validation on username
class regform(forms.ModelForm):
	username=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Enter username'}),
													max_length=50,required=True)
	first_name=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'First name'}),
								max_length=30,required=True)
	last_name=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control','placeholder':'Last name'}),
							max_length=30,required=False)
	email=forms.CharField(widget=forms.EmailInput(attrs={'class':'form-control','placeholder':'Enter Email address'}),
									max_length=50,
									required=True)
	password=forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control','placeholder':'Choose a password'}),
									max_length=50,
									required=True)

	confirm_password=forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control','placeholder':'Confirm password'}),
									max_length=50,
									required=True)
	error_msg = {
		'password_mismatch': ("Password and confirm password didn't matched")
	}


	def clean_username(self):
		username=self.cleaned_data['username']
		try:
			match=User.objects.get(username=username)
		except:
			return self.cleaned_data['username']
		raise forms.ValidationError('Username already Registered')

	def clean_email(self):
		email=self.cleaned_data['email']
		try:
			email_match=validate_email('email')
		except:
			return self.cleaned_data['email']
		return forms.ValidationError("Email is not in correct format")


	def clean_confirm_password(self):

		pas=self.cleaned_data['password']
		cpas=self.cleaned_data['confirm_password']

		if pas and cpas:
			if pas !=cpas :
				raise forms.ValidationError(
					self.error_msg['password_mismatch'],
					code="password_mismatch",
				)
		return cpas
	class Meta:
		model=User
		fields=['username','first_name','last_name','email','password','confirm_password',]


class profile1(forms.ModelForm):
	def mobile_validate(mobile_number):
		length=len(mobile_number)
		allow_len=10
		if length > allow_len :
			raise ValidationError("mobile number should be of 10 digit")



	dob=forms.DateField(widget=forms.DateInput(attrs={'class':'form-control'}),required=True)
	#profile_pic=forms.FileField(required=False,validators=[FileExtensionValidator(allowed_extensions=['jpg','png'])])

	profile_pic = forms.FileField(required=False,
								  )

	mobile_number=forms.CharField(widget=forms.NumberInput(attrs={'class':'form-control','placeholder':'Enter mobile number'}),
										max_length=10,required=True,validators=[mobile_validate])
	job_title = forms.CharField(widget=forms.TextInput(attrs={'class':'form-control'}))
	location = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
	collage = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
	class Meta:
		model=User
		fields=['first_name','last_name','email','dob','profile_pic','mobile_number','job_title','location','collage']
        
class msg_form(forms.ModelForm):
	msg = forms.CharField(widget=forms.Textarea(attrs={'class':'form-control','rows':2,'placeholder':'Reply to message'}),required=True)

	class Meta:
		model = message
		fields = ['msg']

class new_msg_form(forms.ModelForm):
	new_msg = forms.CharField(
		widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 2, 'placeholder': 'Reply to message'}),
		)

	class Meta:
		model = new_message
		fields = ['new_msg']
        
        
#form for geting user email address
class PasswordResetRequestForm(forms.Form):
	email_or_username =  forms.CharField(label=("Email Or Username"),max_length=100)

# form for reset password
class SetPasswordForm(forms.Form):
    """
    A form that lets a user change set their password without entering the old
    password
    """
    error_messages = {
        'password_mismatch': ("The two password fields didn't match."),
        }
    new_password1 = forms.CharField(label=("New password"),
                                    widget=forms.PasswordInput)
    new_password2 = forms.CharField(label=("New password confirmation"),
                                    widget=forms.PasswordInput)
    def cleaned_password2(self):
        password1=self.cleaned_data.get("new_password1")
        password2= self.cleaned_data.get("new_password2")
        if password1 and password2:
            if password1 != password2 :
                raise forms.ValidationError(
                       self.error_messages['password_mismatched'],
                       code= 'password_mismatched',
                       )
        return password2






