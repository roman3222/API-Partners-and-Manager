from django.urls import path
from django_rest_passwordreset.views import reset_password_request_token, reset_password_confirm

from backend.views import RegisterUserAccount, ConfirmEmailAccount, AccountDetails, LoginAccount, CategoryView, \
    ShopView, ProductInfoView, CartView, PartnerShop, ContactView, OrderView, PartnerOrders, PasswordReset, \
    PasswordResetConfirm

app_name = 'backend'

urlpatterns = [
    path('user/register', RegisterUserAccount.as_view(), name='user-register'),
    path('user/register/confirm', ConfirmEmailAccount.as_view(), name='email-confirm'),
    path('user/details', AccountDetails.as_view(), name='account-details'),
    path('user/login', LoginAccount.as_view(), name='login-account'),
    path('categories', CategoryView.as_view(), name='categories'),
    path('shops', ShopView.as_view(), name='shops'),
    path('products', ProductInfoView.as_view(), name='products'),
    path('user/cart', CartView.as_view(), name='cart'),
    path('partner/shop', PartnerShop.as_view(), name='partner_shop'),
    path('user/contacts', ContactView.as_view(), name='user_contact'),
    path('user/order', OrderView.as_view(), name='user_order'),
    path('partner/orders', PartnerOrders.as_view(), name='partner_orders'),
    path('password_reset', PasswordReset.as_view(), name='password_reset'),
    path('password_reset/confirm', PasswordResetConfirm.as_view(), name='reset_confirm'),

]
