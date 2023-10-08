from rest_framework import serializers

from backend.models import User, Shop, Category, Product, ProductInfo, Parameter, ProductParameter, Cart, CartItem, \
    Order, OrderItem, Contacts


class ContactsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contacts
        fields = ('id', 'city', 'street', 'house', 'structure', 'building', 'apartment', 'user', 'phone')
        read_only_fields = ('id',)
        extra_kwargs = {
            'user': {'write_only': True}
        }


class UserSerializer(serializers.ModelSerializer):
    contacts = ContactsSerializer(read_only=True)

    class Meta:
        model = User
        fields = ('id', 'username', 'first_name', 'last_name', 'email', 'company', 'position', 'contacts')
        read_only_fields = ('id',)


class ShopSerializer(serializers.ModelSerializer):
    class Meta:
        model = Shop
        fields = ('id', 'name', 'state')
        read_only_fields = ('id',)


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ('id', 'name')
        read_only_fields = ('id',)


class ProductSerializer(serializers.ModelSerializer):
    category = CategorySerializer(read_only=True, many=True)

    class Meta:
        model = Product
        fields = ('category', 'name')


class ProductParameterSerializer(serializers.ModelSerializer):
    parameter = serializers.StringRelatedField()

    class Meta:
        model = ProductParameter
        fields = ('parameter', 'value')


class ProductInfoSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    product_parameter = ProductParameterSerializer(read_only=True)

    class Meta:
        model = ProductInfo
        fields = (
            'id', 'external_id',
            'model', 'product',
            'product_parameter', 'shop',
            'quantity', 'price',
            'price_rrc',
        )
        read_only_fields = ('id', 'external_id',)


class CartSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    products = ProductSerializer(read_only=True, many=True)

    class Meta:
        model = Cart
        fields = ('user', 'products')


class CartItemSerializer(serializers.ModelSerializer):
    cart = CartSerializer(read_only=True, many=True)
    product_info = ProductInfoSerializer(read_only=True, many=True)

    class Meta:
        model = CartItem
        fields = ('cart', 'product_info', 'quantity', 'created_time')


class OrderItemSerializer(serializers.ModelSerializer):
    cart_items = CartItemSerializer(read_only=True)
    product_info = ProductInfoSerializer(read_only=True)
    sum_price = serializers.IntegerField()

    class Meta:
        model = OrderItem
        fields = ('id', 'product_info', 'quantity', 'price', 'order', 'sum_price', 'cart_items')
        read_only_fields = ('id',)
        extra_kwargs = {
            'order': {'write_only': True}
        }

    def to_representation(self, instance):
        data = super().to_representation(instance)
        context = self.context

        if 'cart_items' in context:
            data.pop('order')
        else:
            data.pop('cart_items')

        return data


class OrderSerializer(serializers.ModelSerializer):
    ordered_items = OrderItemSerializer(read_only=True, many=True)
    contacts = ContactsSerializer(read_only=True)

    class Meta:
        model = Order
        fields = (
            'id', 'state',
            'ordered_items', 'contacts',
            'dt',
        )
        read_only_fields = ('id',)
