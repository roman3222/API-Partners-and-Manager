from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView

from requests import get
from backend.models import ConfirmEmailToken, Category, Shop, ProductInfo, Cart, CartItem, Product, Parameter, \
    ProductParameter, Contacts, Order, OrderItem
from backend.serializers import UserSerializer, CategorySerializer, ShopSerializer, ProductInfoSerializer, \
    CartItemSerializer, CartSerializer, ContactsSerializer, OrderSerializer, OrderItemSerializer
from backend.signals import new_user_registered, new_order_signal
from rest_framework.authentication import authenticate
from rest_framework.authtoken.models import Token
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Q, Sum, F
from yaml import load as load_yaml, Loader
from django.core.validators import URLValidator
from django.db import transaction


class RegisterUserAccount(APIView):
    """
    Регистрацция нового пользователя
    """

    def post(self, request, *args, **kwargs):
        errors = {}
        if {'first_name', 'last_name', 'email', 'password', 'company', 'position', 'username', 'type'}.issubset(
                request.data):

            try:
                validate_password(request.data['password'])
            except ValidationError as password_error:
                error_array = []
                for item in password_error:
                    error_array.append(item)
                errors['password'] = error_array
            else:
                user_serializer = UserSerializer(data=request.data)
                if user_serializer.is_valid():
                    user = user_serializer.save()
                    user.set_password(request.data['password'])
                    user.type = request.data['type']
                    user.save()
                    new_user_registered.send(sender=self.__class__, user_id=user.id)
                    token = Token.objects.create(user=user)

                    if user.type == 'buyer':
                        cart = Cart.objects.create(user=user)

                    return JsonResponse({'Status': True, 'Created': user.username, 'Token': str(token)})

                else:
                    errors['user'] = user_serializer.errors
        if errors:
            return JsonResponse({'Status': False, 'Errors': errors})

        return JsonResponse({'Status': False, 'Errors': 'All the necessary arguments are not stated'})


class ConfirmEmailAccount(APIView):
    """
    Подтверждение электронной почты
    """

    def post(self, request, *args, **kwargs):
        if {'email', 'token'}.issubset(request.data):
            token = ConfirmEmailToken.objects.filter(user__email=request.data['email'],
                                                     key=request.data['token']).first()
            if token:
                token.user.is_active = True
                token.user.save()
                token.delete()
                return JsonResponse({'Status': True, 'Message': 'Email confirmed'})
            else:
                return JsonResponse({'Status': False, 'Errors': 'Incorrect email or token'})
        return JsonResponse({'Status': False, 'Errors': 'All the necessary arguments are not stated'})


class AccountDetails(APIView):
    """
    Класс для работы с данными пользователя
    """

    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'log in required'}, status=403)
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if 'password' in request.data:
            errors = {}
            try:
                validate_password(request.data['password'])
            except ValidationError as password_error:
                error_array = []
                for item in password_error:
                    error_array.append(item)
                return JsonResponse({'Status': False, 'Errors': {'password': error_array}})
            else:
                request.user.set_password(request.data['password'])
        user_serializer = UserSerializer(request.user, data=request.data, partial=True)
        if user_serializer.is_valid():
            user_serializer.save()
            return JsonResponse({'Status': True})
        else:
            return JsonResponse({'Status': False, 'Errors': user_serializer.errors})


class LoginAccount(APIView):
    """
    Класс для авторизации пользователя
    """

    def post(self, request, *args, **kwargs):
        if {'email', 'password'}.issubset(request.data):
            user = authenticate(request, username=request.data['email'], password=request.data['password'])

            if user is not None:
                if user.is_active:
                    token, _ = Token.objects.get_or_create(user=user)

                    return JsonResponse({'Status': True, 'Token': token.key})

            return JsonResponse({'Status': False, 'Errors': 'User not found or e-mail unconfirmed'})

        return JsonResponse({'Status': False, 'Errors': 'All the necessary arguments are not stated'})


class CategoryView(APIView):
    """
    Класс для просмотра категорий
    """
    category = Category.objects.all()
    serializer_class = CategorySerializer


class ShopView(ListAPIView):
    """
    Класс для просмотра списка магазинов
    """

    shops = Shop.objects.filter(state=True)
    serializer_class = ShopSerializer


class ProductInfoView(APIView):
    """
    Класс для поиска товаров
    """

    def get(self, request, *args, **kwargs):
        query = Q(shop__state=True)
        shop_id = request.query_params.get('shop_id')
        category_id = request.query_params.get('category_id')

        if shop_id:
            query = query & Q(shop_id=shop_id)

        if category_id:
            query = query & Q(product__category_id=category_id)

        queryset = ProductInfo.objects.filter(
            query).select_related(
            'shop', 'product__category').prefetch_related(
            'product_parameters__parameter').distinct()

        serializer = ProductInfoSerializer(queryset, many=True)

        return Response(serializer.data)


class CartView(APIView):
    """
    Класс для работы с корозиной пользователя
    """

    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in is required'}, status=403)

        try:
            cart = Cart.objects.get(user=request.user)
        except ObjectDoesNotExist:
            return Response({'error': 'Cart not found'}, status=404)

        cart_items = CartItem.objects.filter(cart=cart).annotate(
            total_price=Sum(F('quantity') * F('product_info__price'))
        )

        serializer = CartItemSerializer(cart_items, many=True)

        return Response({'cart_items': serializer.data})

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in is required'}, status=403)

        serializer = CartItemSerializer(data=request.data, many=True)
        if serializer.is_valid():
            cart_item_data = serializer.validated_data
            cart_items = []

            for item_data in cart_item_data:
                product_info_id = item_data['product_info']
                quantity = item_data['quantity']

                try:
                    cart = Cart.objects.get(user=request.user)
                except ObjectDoesNotExist:
                    return JsonResponse({'Status': False, 'Errors': 'cart not found'}, status=404)

                try:
                    product_info = ProductInfo.objects.get(id=product_info_id.id)
                except ObjectDoesNotExist:
                    return JsonResponse({'Status': False, 'error': 'Product Info not found'}, status=404)

                cart_item, created = CartItem.objects.get_or_create(
                    cart=cart,
                    product_info=product_info,
                    defaults={'quantity': quantity}
                )
                cart_items.append(cart_item)

                if not created:
                    cart_item.quantity += quantity
                    cart_item.save()

            serializer_item = CartItemSerializer(cart_items, many=True).data

            return JsonResponse({'Status': True, 'cart_item': serializer_item})

        return JsonResponse({'Status': False, 'Errors': serializer.errors}, status=400)

    def patch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in is required'}, status=403)

        item_id = request.data['item_id']

        cart = Cart.objects.get(user=request.user)

        try:
            cart_item = CartItem.objects.get(cart=cart, id=item_id)
        except ObjectDoesNotExist:
            return JsonResponse({'Status': False, 'Errors': 'cart item not found'}, status=404)

        quantity = request.data['quantity']
        cart_item.quantity = quantity
        cart_item.save()

        item_serializer = CartItemSerializer(cart_item, partial=True)

        return JsonResponse({'Status': True, 'updates': item_serializer.data})

    def delete(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in is required'}, status=403)

        item_ids = request.data.get('item_id', [])
        if not isinstance(item_ids, list):
            item_ids = [item_ids]

        if not item_ids:
            return JsonResponse({'Status': False, 'Errors': 'No item ids provided'}, status=400)

        cart = Cart.objects.get(user=request.user)

        deleted_items_ids = []

        for items_id in item_ids:
            try:
                cart_item = CartItem.objects.get(cart=cart, id=items_id)
                cart_item.delete()
                deleted_items_ids.append(items_id)
            except ObjectDoesNotExist:
                pass

        return JsonResponse({'Status': True, 'deleted_items': deleted_items_ids})


class PartnerUpdate(APIView):
    """
    Класс обновления прайса поставщиков
    """

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in is required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Errors': 'Only for partners'})

        url = request.get('url')
        if url:
            validate_url = URLValidator()
            try:
                validate_url(url)
            except ValidationError as errors:
                return JsonResponse({'Status': False, 'Errors': errors})
        else:
            stream = get(url).content
            data = load_yaml(stream, Loader=Loader)

            shop, _ = Shop.objects.get_or_create(name=data['shop'], user_id=request.user.id)

            for category in data['categories']:
                category_obj, _ = Category.objects.get_or_create(id=category.id, name=category['name'])
                category_obj.shops.add(shop.id)
                category_obj.save()
            ProductInfo.objects.filter(shop_id=shop.id).delete()

            for item in data['goods']:
                product, _ = Product.objects.get_or_create(name=item['name'], category_id=item['category'])

                product_info = ProductInfo.objects.create(product_id=product.id,
                                                          external_id=item['id'],
                                                          model=item['model'],
                                                          price=item['price'],
                                                          price_rrc=item['price_rrc'],
                                                          quantity=item['quantity'],
                                                          shop_id=shop.id)

                for name, value in item['parameters'].items():
                    parameter_obj, _ = Parameter.objects.get_or_create(name=name)
                    ProductParameter.objects.create(product_info_id=product_info.id,
                                                    parameter_id=parameter_obj.id,
                                                    value=value)

                    return JsonResponse({'Status': True})

                return JsonResponse({'Status': False, 'Errors': 'All the necessary arguments are not stated'})


class PartnerShop(APIView):
    """
    Класс для работы поставщика со своим магазином
    """

    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in is required'}, status=403)

        if not request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Errors': 'Only for partners'}, status=403)

        shop = request.user.shop
        serializer_shop = ShopSerializer(shop)

        return Response(serializer_shop.data)

    def post(self, request, *args, **kwargs):
        if 'name' in request.data:
            if not request.user.is_authenticated:
                return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)

            if request.user.type != 'shop':
                return JsonResponse({'Status': False, 'Errors': 'Only for partners'}, status=403)

            shop_data = request.data
            shop_data['user'] = request.user.id
            shop = ShopSerializer(data=shop_data)
            if shop.is_valid():
                shop.save()
                return JsonResponse({'Status': True, 'Message': shop.data})
            else:
                return JsonResponse({'Status': False, 'Errors': shop.errors})

        return JsonResponse({'Status': False, 'Errors': 'The name of the store is not specified'})

    def patch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Errors': 'Only for partners'}, status=403)

        try:
            shop = Shop.objects.get(user=request.user)
            serializer_shop = ShopSerializer(shop, data=request.data, partial=True)
        except ObjectDoesNotExist as error:
            return JsonResponse({'Status': False, 'Errors': error})

        try:
            serializer_shop.is_valid()
            serializer_shop.save()
            return JsonResponse({'Status': True, 'updates': serializer_shop.data})
        except ValidationError as error:
            return JsonResponse({'Status': False, 'Errors': error})

    def delete(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)

        try:
            shop = Shop.objects.get(user=request.user)
        except ObjectDoesNotExist as error:
            return JsonResponse({'Status': False, 'Errors': error})

        shop.delete()

        return JsonResponse({'Status': True})


class ContactView(APIView):
    """
    Класс для работы с контактами покупателей
    """

    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'log in is required'}, status=403)

        contacts = Contacts.objects.filter(user_id=request.user)

        contacts_serializer = ContactsSerializer(contacts, many=True)

        return Response(contacts_serializer.data)

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'log in is required'}, status=403)

        if {'city', 'street', 'phone'}.issubset(request.data):
            shop_data = request.data
            shop_data['user'] = request.user.id

            contact_serializer = ContactsSerializer(data=shop_data)
            if contact_serializer.is_valid():
                contact_serializer.save()
                return JsonResponse({'Status': True, 'your contacts': contact_serializer.data})
            else:
                return JsonResponse({'Status': False, 'Error': contact_serializer.errors})

        return JsonResponse({'Status': False, 'Error': 'All the necessary arguments are not stated'})

    def delete(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        item_list = request.data.get('items', [])
        if not isinstance(item_list, list):
            item_list = [item_list]

        query = Q()
        objects_del = False

        for contact_id in item_list:
            if isinstance(contact_id, int):
                query = query | Q(user_id=request.user.id, id=contact_id)
                objects_del = True

        if objects_del:
            deleted_count = Contacts.objects.filter(query).delete()[0]
            return JsonResponse({'Status': True, 'Удалено объектов': deleted_count})

        return JsonResponse({'Status': False, 'Errors': 'All the necessary arguments are not stated'})

    def put(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        try:
            contact = Contacts.objects.get(user=request.user)
        except ObjectDoesNotExist as error:
            return JsonResponse({'Status': False, 'Error': error})

        contact_serializer = ContactsSerializer(contact, data=request.data, partial=True)
        if contact_serializer.is_valid():
            contact_serializer.save()
            return JsonResponse({'Status': True, 'updates': contact_serializer.data})

        return JsonResponse({'Status': False, 'Error': contact_serializer.errors})


class OrderView(APIView):
    """
    Класс для получения и размещения заказа пользователями
    """

    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        order = Order.objects.filter(
            user=request.user
        ).prefetch_related('ordered_items__product_info__product__category',
                           'ordered_items__product_info__product_parameters__parameter').select_related(
                           'contacts').annotate(total_sum=Sum(F('ordered_items__quantity') * F(
                            'ordered_items__product_info__price'))).distinct()

        serializer = OrderSerializer(order, many=True)

        return JsonResponse({'Status': True, 'Order': serializer.data})

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if {'contact', 'cart_item'}.issubset(request.data):
            cart = Cart.objects.prefetch_related('products_info').get(user=request.user)
            cart_item_ids = request.data.get('cart_item', [])
            contact_id = request.data['contact']

            cart_items = CartItem.objects.select_related('product_info').filter(
                cart=cart,
                id__in=cart_item_ids
            )

            with transaction.atomic():
                order = Order.objects.create(
                    user=request.user,
                    cart=cart,
                    contacts_id=contact_id,
                    state='new'
                )

                order_items = [
                    OrderItem(
                        order=order,
                        product_info=cart_item.product_info,
                        quantity=cart_item.quantity,
                        price=cart_item.product_info.price
                    )

                    for cart_item in cart_items

                ]

                cart_items.delete()
                cart_items.save()

                OrderItem.objects.bulk_create(order_items)

            new_order_signal(sender=self.__class__, user_id=request.user.id)
            serializer = OrderItemSerializer(order_items, many=True).data

            return JsonResponse({'Status': True, 'result': serializer})

        return JsonResponse({'Status': False, 'Errors': 'All the necessary arguments are not stated'})
