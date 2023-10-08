from django.urls import path
from django_rest_passwordreset.views import reset_password_request_token, reset_password_confirm

from backend.views import RegisterUserAccount, ConfirmEmailAccount, AccountDetails

app_name = 'backend'
urlpatterns = [
    path('user/register', RegisterUserAccount.as_view(), name='user-register'),
    path('user/register/confirm', ConfirmEmailAccount.as_view(), name='email-confirm'),
    path('user/details', AccountDetails.as_view(), name='account-details'),
]
