from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.dispatch import receiver, Signal
from django_rest_passwordreset.signals import reset_password_token_created

from backend.models import ConfirmEmailToken, User, Order

new_user_registered = Signal()

new_order = Signal()


@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, **kwargs):
    subject = f'Password Reset Token for {reset_password_token.user}'
    text_content = reset_password_token.key
    from_email = settings.EMAIL_HOST_USER
    to = [reset_password_token.user.email]
    msg = EmailMultiAlternatives(
        subject, text_content,
        from_email, to
    )
    msg.send()


@receiver(new_user_registered)
def new_user_registered_signal(sender, user_id, **kwargs):
    """
    Сигнал отправки письма с подтверждением почты
    """
    token, _ = ConfirmEmailToken.objects.get_or_create(user_id=user_id)

    subject = f'Email confirmation token for {token.user.email}'
    text_content = token.key
    from_email = settings.EMAIL_HOST_USER
    to = [token.user.email]

    msg = EmailMultiAlternatives(
        subject, text_content,
        from_email, [to]
    )
    msg.send()


@receiver(new_order)
def new_order_signal(sender, user_id, **kwargs):
    """
    Сигнал отправки письма при изменении статуса заказа
    """
    user = User.objects.get(id=user_id)
    order = Order.objects.get(user=user)
    order_state = order.state

    subject = 'Обновление статуса заказа'
    text_content = f'Заказ для {user} {order_state}'
    from_email = settings.EMAIL_HOST_USER
    to = [user.email]

    msg = EmailMultiAlternatives(
        subject, text_content,
        from_email, [to]
    )
    msg.send()
