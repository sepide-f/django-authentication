from django.urls import path
from .views import post_list, PasswordReset, ResetPasswordAPI
from users.views import LoginView, UserRegistrationView, profile

urlpatterns = [
    path("login/", LoginView.as_view(), name='login'),
    path("register/", UserRegistrationView.as_view(), name='register'),
    path("profile/<int:userid>/", profile, name="profile"),
    path("<int:pk>/", post_list, name="post_list"),
    path("", PasswordReset.as_view(), name="request-password-reset", ),
    path("password-reset/<str:encoded_pk>/<str:token>/", ResetPasswordAPI.as_view(), name="reset-password", ),
]
