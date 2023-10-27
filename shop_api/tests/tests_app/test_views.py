import pytest
from model_bakery import baker
import json
from django.urls import reverse

from backend.models import ConfirmEmailToken, Category, Shop, ProductInfo, Cart, CartItem, Product, Parameter, \
    ProductParameter, Contacts, Order, OrderItem, User, UserManager


class TestUser:

    def test_register(self, api_client):
        user = baker.prepare(User)
        data_json = {
            'username': user.username,
            'email': user.email,
            'password': user.password,
            'first_name': user.first_name,
            'last_name': user.last_name,
        }
