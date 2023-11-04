from rest_framework import serializers

from backend.models import User, Shop, Category, Product, ProductInfo, ProductParameter, Cart, CartItem, \
    Order, OrderItem, Contacts

from rest_framework.authtoken.models import Token


class ContactsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contacts
        fields = ('id', 'city', 'street', 'house', 'structure', 'building', 'apartment', 'user', 'phone')
        read_only_fields = ('id',)
        extra_kwargs = {
            'user': {'write_only': True}
        }


class UserSerializer(serializers.ModelSerializer):
    contacts = ContactsSerializer(read_only=True, many=True)

    class Meta:
        model = User
        fields = ('id', 'username', 'first_name', 'last_name', 'email', 'company', 'position', 'contacts', 'is_active',
                  'type', 'password')
        read_only_fields = ('id', 'is_active')


class ShopSerializer(serializers.ModelSerializer):
    class Meta:
        model = Shop
        fields = ('id', 'name', 'state', 'user', 'url')
        read_only_fields = ('id',)


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ('id', 'name', 'shops')
        read_only_fields = ('id',)


class ProductSerializer(serializers.ModelSerializer):
    category = CategorySerializer(read_only=True)

    class Meta:
        model = Product
        fields = ('id', 'category', 'name')


class ProductParameterSerializer(serializers.ModelSerializer):
    parameter = serializers.StringRelatedField()

    class Meta:
        model = ProductParameter
        fields = ('parameter', 'value')


class ProductInfoSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    product_parameters = ProductParameterSerializer(read_only=True, many=True)

    class Meta:
        model = ProductInfo
        fields = (
            'id', 'external_id',
            'model', 'product',
            'product_parameters', 'shop',
            'quantity', 'price',
            'price_rrc',
        )
        read_only_fields = ('id', 'external_id',)


class CartSerializer(serializers.ModelSerializer):
    # product_info = ProductInfoSerializer(read_only=True, many=True)

    class Meta:
        model = Cart
        fields = ('user',)


class CartItemSerializer(serializers.ModelSerializer):
    cart = CartSerializer(read_only=True)
    total_price = serializers.IntegerField(required=False)

    class Meta:
        model = CartItem
        fields = ('id', 'cart', 'quantity', 'total_price', 'created_time', 'product_info')
        read_only_fields = ('id',)


class OrderItemSerializer(serializers.ModelSerializer):
    product_info = ProductInfoSerializer(read_only=True)

    class Meta:
        model = OrderItem
        fields = ('id', 'order', 'product_info', 'quantity', 'price')
        read_only_fields = ('id',)
        extra_kwargs = {
            'order': {'write_only': True}
        }


class OrderItemCreateSerializer(OrderItemSerializer):
    product_info = ProductInfoSerializer(read_only=True)


class OrderSerializer(serializers.ModelSerializer):
    ordered_items = OrderItemCreateSerializer(read_only=True, many=True)
    contact = ContactsSerializer(read_only=True)
    cart = CartSerializer(read_only=True)
    total_sum = serializers.IntegerField(read_only=False)

    class Meta:
        model = Order
        fields = ('id', 'ordered_items', 'state', 'dt', 'cart', 'contact', 'total_sum')
        read_only_fields = ('id',)


class ConfirmEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
    token = serializers.CharField()


class LoginUserSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()


class TokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = Token
        fields = ('key',)
        read_only_fields = ('key',)


class CartSchemaSerializer(serializers.Serializer):
    product_info = serializers.IntegerField()
    quantity = serializers.IntegerField()


class CartItemSchemaSerializer(serializers.Serializer):
    item_id = serializers.IntegerField()
    quantity = serializers.IntegerField()


class LoadPartnerSerializer(serializers.Serializer):
    url = serializers.URLField()
