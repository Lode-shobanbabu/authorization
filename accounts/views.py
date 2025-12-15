from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator


def register_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST.get('confirm_password')

        if password != confirm_password:
            messages.error(request, "Passwords do not match")
            return redirect('register')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken")
            return redirect('register')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already registered")
            return redirect('register')

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            is_active=False
        )
        user.save()

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        link = f"http://127.0.0.1:8000/verify-email/{uid}/{token}/"

        send_mail(
            'Verify Email',
            f'Click to verify your account:\n{link}',
            settings.EMAIL_HOST_USER,
            [email],
        )

        messages.success(request, "Check email to verify account")
        return redirect('login')

    return render(request, 'register.html')


def verify_email(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        messages.error(request, "Invalid link")
        return redirect('login')

    if default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Email verified")
    else:
        messages.error(request, "Invalid or expired link")

    return redirect('login')



def login_view(request):
    if request.method == 'POST':
        username_or_email = request.POST.get('username')
        password = request.POST.get('password')

        # Step 1: Find user by email OR username
        try:
            user_obj = User.objects.get(email=username_or_email)
        except User.DoesNotExist:
            try:
                user_obj = User.objects.get(username=username_or_email)
            except User.DoesNotExist:
                messages.error(request, "Invalid username/email or password")
                return redirect('login')

        # Step 2: Block inactive users BEFORE authentication
        if not user_obj.is_active:
            messages.error(
                request,
                "Your account is not activated yet. Please check your email and complete the verification to continue."
            )
            return redirect('login')

        # Step 3: Authenticate password
        user = authenticate(
            request,
            username=user_obj.username,
            password=password
        )

        if user is None:
            messages.error(request, "Invalid username/email or password")
            return redirect('login')

        # Step 4: Login verified user
        login(request, user)
        messages.success(request, "Login successful")
        return redirect('dashboard')

    return render(request, 'login.html')


@login_required
def dashboard(request):
    return render(request, 'dashboard.html')


def logout_view(request):
    logout(request)
    return redirect('login')


def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        if not email:
            messages.error(request, "Email is required")
            return redirect('forgot_password')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, "Email not registered")
            return redirect('forgot_password')

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        link = f"http://127.0.0.1:8000/reset-password/{uid}/{token}/"

        send_mail(
            'Reset Password',
            f'Click the link to reset your password:\n{link}',
            settings.EMAIL_HOST_USER,
            [user.email],
        )

        messages.success(request, "Reset link sent to your email")
        return redirect('login')

    return render(request, 'forgot_password.html')



# ===================== RESET PASSWORD =====================
def reset_password(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        messages.error(request, "Invalid link")
        return redirect('login')

    if not default_token_generator.check_token(user, token):
        messages.error(request, "Invalid or expired link")
        return redirect('login')

    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if not password or not confirm_password:
            messages.error(request, "All fields are required")
            return redirect(request.path)

        if password != confirm_password:
            messages.error(request, "Passwords do not match")
            return redirect(request.path)

        user.set_password(password)
        user.is_active = True   # IMPORTANT
        user.save()

        messages.success(request, "Password reset successfully")
        return redirect('login')

    return render(request, 'reset_password.html')

