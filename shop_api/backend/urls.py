from django.urls import path
from django_rest_passwordreset.views import reset_password_request_token, reset_password_confirm

from backend.views import RegisterUserAccount, ConfirmEmailAccount, AccountDetails, LoginAccount, CategoryView, \
    ShopView, ProductInfoView

app_name = 'backend'

urlpatterns = [
    path('user/register', RegisterUserAccount.as_view(), name='user-register'),
    path('user/register/confirm', ConfirmEmailAccount.as_view(), name='email-confirm'),
    path('user/details', AccountDetails.as_view(), name='account-details'),
    path('user/login', LoginAccount.as_view(), name='login-account'),
    path('categories', CategoryView.as_view(), name='categories'),
    path('shops/<int:shop_id>/', ShopView.as_view(), name='shops'),
    path('products', ProductInfoView.as_view(), name='products')

]
