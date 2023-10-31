from django.dispatch import receiver, Signal
from django_rest_passwordreset.signals import reset_password_token_created

from backend.models import User, Order
from backend.tasks import send_email_confirmation, send_reset_password, send_state_order

new_user_registered = Signal()

new_order = Signal()


@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, **kwargs):
    send_reset_password.delay(reset_password_token.user.email, reset_password_token.key)


@receiver(new_user_registered)
def new_user_registered_signal(sender, user_id, **kwargs):
    """
    Сигнал отправки письма с подтверждением почты
    """
    send_email_confirmation.delay(user_id)


@receiver(new_order)
def new_order_signal(sender, user_id, **kwargs):
    """
     Сигнал отправки письма при изменении статуса заказа
     """
    user = User.objects.get(id=user_id)
    order = Order.objects.get(user=user)

    send_state_order.delay(user.username, order.state, user.email)

