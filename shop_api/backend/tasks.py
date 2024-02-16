from celery import shared_task
from django.conf import settings

from django.core.mail import EmailMultiAlternatives
from backend.models import ConfirmEmailToken


@shared_task()
def send_email_confirmation(user_id):
    token, _ = ConfirmEmailToken.objects.get_or_create(user_id=user_id)

    subject = f"Email confirmation token for {token.user.email}"
    text_content = token.key
    from_email = settings.EMAIL_HOST_USER
    to = [token.user.email]

    msg = EmailMultiAlternatives(subject, text_content, from_email, to)
    msg.send()


@shared_task()
def send_reset_password(email, reset_password_token_key):
    subject = f"Password Reset Token for"
    text_content = reset_password_token_key
    from_email = settings.EMAIL_HOST_USER
    to = [email]
    msg = EmailMultiAlternatives(subject, text_content, from_email, to)
    msg.send()


@shared_task()
def send_state_order(user, order_state, email):
    subject = "Обновление статуса заказа"
    text_content = f"Заказ для {user} {order_state}"
    from_email = settings.EMAIL_HOST_USER
    to = [email]
    msg = EmailMultiAlternatives(subject, text_content, from_email, to)
    msg.send()
