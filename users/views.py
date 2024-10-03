# users/views.py

from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib import messages
from .forms import SignupForm, LoginForm
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.models import User
from .tokens import account_activation_token
from django.utils.encoding import force_str
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.conf import settings

# Home page
def index(request):
    return render(request, "users/index.html")

# Signup view
def user_signup(request):
    if request.method == "POST":
        form = SignupForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            # Check if the email already exists
            if User.objects.filter(email=email).exists():
                messages.error(request, "This email is already registered.")
                return redirect("signup")

            form.request = request  # Pass the request to the form
            user = form.save()
            messages.success(request, "Please confirm your email to complete registration.")
            return redirect("login")
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = SignupForm()
    return render(request, "users/signup.html", {"form": form})

# Login view
def user_login(request):
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get("email")
            password = form.cleaned_data.get("password")

            user = authenticate(request, email=email, password=password)
            if user is not None:
                if not user.is_active:
                    messages.error(request, "Your account is not verified. Please check your email.")
                    return redirect("login")
                login(request, user)
                return redirect("home")
            else:
                messages.error(request, "Invalid email or password")
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = LoginForm()
    return render(request, "users/login.html", {"form": form})

# Logout view
def user_logout(request):
    logout(request)
    return redirect("home")

# Profile view
@login_required
def profile(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important!
            messages.success(request, 'Your password was successfully updated!')
            return redirect('profile')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'users/profile.html', {'form': form})

def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        
        # Specify the backend explicitly
        backend = 'django.contrib.auth.backends.ModelBackend'
        login(request, user, backend=backend)  # Pass backend to login

        return redirect('home')  # Redirect to a success page after login
    else:
        return render(request, 'account/activation_invalid.html')  # Activation failed page