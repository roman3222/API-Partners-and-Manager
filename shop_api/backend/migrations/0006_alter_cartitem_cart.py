# Generated by Django 4.2.5 on 2023-10-14 05:39

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0005_alter_cartitem_cart_alter_cartitem_product_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='cartitem',
            name='cart',
            field=models.ForeignKey(blank=True, on_delete=django.db.models.deletion.CASCADE, related_name='cart_item', to='backend.cart', verbose_name='Корзина'),
        ),
    ]