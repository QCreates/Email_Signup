from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.urls import reverse
from .tokens import account_activation_token
from sib_api_v3_sdk import Configuration, ApiClient, TransactionalEmailsApi, SendSmtpEmail  # Import these
from sib_api_v3_sdk.rest import ApiException  # For error handling with Brevo
from django.conf import settings
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException

User = get_user_model()

class SignupForm(UserCreationForm):
    first_name = forms.CharField(required=True)
    last_name = forms.CharField(required=True)
    email = forms.EmailField(required=True)
    terms = forms.BooleanField(required=False, error_messages={'required': 'You must accept the terms and conditions'})

    class Meta:
        model = User
        fields = ["email", "first_name", "last_name", "password1", "password2", "terms"]

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super(SignupForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.add_input(Submit('submit', 'Sign Up'))

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if "+" in email:
            raise ValidationError("Aliases (emails containing '+') are not allowed.")
        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        user.username = user.email
        user.is_active = False  # Deactivate account until email is confirmed
        if commit:
            user.save()
            self.send_verification_email(user)
        return user

    def send_verification_email(self, user):
        """Send an email with a verification link to the user."""
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = account_activation_token.make_token(user)
        activation_link = self.request.build_absolute_uri(reverse('activate', args=[uid, token]))

        # Render email content
        subject = 'Activate Your Account'
        message = render_to_string('users/activation_email.html', {
            'user': user,
            'activation_link': activation_link,
        })

        # Brevo API Configuration
        configuration = Configuration()
        configuration.api_key['api-key'] = settings.BREVO_API_KEY

        api_instance = TransactionalEmailsApi(ApiClient(configuration))
        sender = {"name": "Students Hub Verification", "email": settings.DEFAULT_FROM_EMAIL}
        to = [{"email": user.email, "name": f"{user.first_name} {user.last_name}"}]

        email = SendSmtpEmail(
            to=to,
            html_content=message,
            subject=subject,
            sender=sender
        )

        try:
            api_instance.send_transac_email(email)
            print("Verification email sent successfully.")
        except ApiException as e:
            print(f"Exception when sending email: {e}")


class LoginForm(forms.Form):
    email = forms.EmailField(required=True)
    password = forms.CharField(widget=forms.PasswordInput)