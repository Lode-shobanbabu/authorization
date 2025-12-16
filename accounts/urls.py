from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('logout/', views.logout_view, name='logout'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('reset-password/<uidb64>/<token>/', views.reset_password, name='reset_password'),
    path('verify-email/<uidb64>/<token>/', views.verify_email, name='verify_email'),

    # services 
     path('services/', views.services_list, name='services'),
    path('services/create/', views.create_service, name='create_service'),
    path('services/update/<int:id>/', views.update_service, name='update_service'),
    path('services/delete/<int:id>/', views.delete_service, name='delete_service'),
]
