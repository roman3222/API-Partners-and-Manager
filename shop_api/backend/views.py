import string

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from requests import get
from backend.models import ConfirmEmailToken, Category, Shop, ProductInfo, Cart, CartItem, Product, Parameter, \
    ProductParameter, Contacts, Order, OrderItem, User
from backend.serializers import UserSerializer, CategorySerializer, ShopSerializer, ProductInfoSerializer, \
    CartItemSerializer, ContactsSerializer, OrderSerializer, OrderItemSerializer, ConfirmEmailSerializer, \
    LoginUserSerializer, TokenSerializer, CartSchemaSerializer, CartItemSchemaSerializer, \
    LoadPartnerSerializer
from backend.signals import new_user_registered, password_reset_token_created, new_order_signal
from rest_framework.authentication import authenticate
from rest_framework.authtoken.models import Token
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Q, Sum, F
from yaml import load as load_yaml, Loader
from django.core.validators import URLValidator
from django.db import transaction
from django_rest_passwordreset.models import ResetPasswordToken
from django_rest_passwordreset.views import ResetPasswordRequestToken
from django_rest_passwordreset.views import ResetPasswordConfirm
from django.contrib.auth import get_user_model
from rest_framework.permissions import AllowAny
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiResponse, OpenApiParameter, OpenApiExample


@extend_schema(tags=['Users'])
@extend_schema_view(
    post=extend_schema(
        request=UserSerializer,
        responses={
            status.HTTP_200_OK: OpenApiResponse(response=UserSerializer,
                                                description='Created'),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(description='Bad request(something invalid)')
        },
        summary='Отправить данные для регистрации'
    )
)
class RegisterUserAccount(APIView):
    """
    Регистрацция нового пользователя
    """
    permission_classes = [AllowAny]

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
                    # user.type = request.data['type']
                    user.save()
                    new_user_registered.send(sender=self.__class__, user_id=user.id)

                    if user.type == 'buyer':
                        cart = Cart.objects.create(user=user)

                    return JsonResponse({'Status': True, 'Created': user_serializer.data})

                else:
                    errors['user'] = user_serializer.errors
        if errors:
            return JsonResponse({'Status': False, 'Errors': errors}, status=400)

        return JsonResponse({'Status': False, 'Error': 'All the necessary arguments are not stated'}, status=400)


@extend_schema(tags=['Users'])
@extend_schema_view(
    post=extend_schema(
        request=ConfirmEmailSerializer,
        description='В теле запроса необходимо передать email и token',
        responses={
            status.HTTP_200_OK: OpenApiResponse(description="Email confirmed"),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(description="Bad request(something invalid)"),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(response=None)
        },
        summary="Подтверждение электронной почты пользователя"
    )
)
class ConfirmEmailAccount(APIView):
    """
    Подтверждение электронной почты
    """
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        if {'email', 'token'}.issubset(request.data):
            token = ConfirmEmailToken.objects.filter(user__email=request.data['email'],
                                                     key=request.data['token']).first()
            if token:
                token.user.is_active = True
                token.user.save()
                token.delete()
                return JsonResponse({'Status': True, 'Message': 'Email confirmed'}, status=200)

            return JsonResponse({'Status': False, 'Errors': 'Incorrect email or token'}, status=400)

        return JsonResponse({'Status': False, 'Errors': 'All the necessary arguments are not stated'}, status=400)


@extend_schema(tags=['Users'])
@extend_schema_view(
    get=extend_schema(
        summary='Получить информацию о своём профиле',
        responses={
            status.HTTP_200_OK: OpenApiResponse(description='User data'),
            status.HTTP_401_UNAUTHORIZED: OpenApiResponse(description='Токен не передан или токен неверный'),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(response=None)
        }
    ),
    post=extend_schema(
        summary='Изменить данные профиля',
        request=UserSerializer,
        responses={
            status.HTTP_200_OK: OpenApiResponse(response=UserSerializer,
                                                description='Confirmed Update'),
            status.HTTP_401_UNAUTHORIZED: OpenApiResponse(description='Токен не передан или токен неверный'),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(description='Bad request(something invalid)')

        }
    )
)
class AccountDetails(APIView):
    """
    Класс для работы с данными пользователя
    """

    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'log in required'}, status=401)

        queryset = User.objects.get(id=request.user.id)
        serializer = UserSerializer(queryset)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if 'password' in request.data:
            password = request.data['password']

            errors = {}

            try:
                validate_password(password)
            except ValidationError as password_error:
                error_array = []
                for item in password_error:
                    error_array.append(item)
                return JsonResponse({'Status': False, 'Errors': {'password': error_array}}, status=400)
            else:
                request.user.set_password(request.data['password'])
        user_serializer = UserSerializer(request.user, data=request.data, partial=True)
        if user_serializer.is_valid():
            user_serializer.save()
            return JsonResponse({'Status': True, 'Data': user_serializer.data})
        else:
            return JsonResponse({'Status': False, 'Errors': user_serializer.errors}, status=400)


@extend_schema(tags=['Users'])
@extend_schema_view(
    post=extend_schema(
        summary='Log in',
        request=LoginUserSerializer,
        responses={
            status.HTTP_200_OK: OpenApiResponse(response=TokenSerializer,
                                                description='Your Token'),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(description='Bad request(something invalid'),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(description='User not found')

        }
    )
)
class LoginAccount(APIView):
    """
    Класс для авторизации пользователя
    """
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        if {'email', 'password'}.issubset(request.data):
            user = authenticate(request, username=request.data['email'], password=request.data['password'])

            if user is not None:
                if user.is_active:
                    token, _ = Token.objects.get_or_create(user=user)

                    return JsonResponse({'Status': True, 'Token': token.key}, status=200)

            return JsonResponse({'Status': False, 'Errors': 'User not found or e-mail unconfirmed'}, status=404)

        return JsonResponse({'Status': False, 'Errors': 'All the necessary arguments are not stated'}, status=400)


@extend_schema(tags=['Categories'])
@extend_schema_view(
    get=extend_schema(
        summary='Получить список категорий',
        responses={
            status.HTTP_200_OK: OpenApiResponse(CategorySerializer,
                                                description='Status: True'),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(response=None)
        }
    )
)
class CategoryView(APIView):
    """
    Класс для просмотра категорий
    """
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        category = Category.objects.all()
        serializer = CategorySerializer(category, many=True)
        return Response(serializer.data)


@extend_schema(tags=['Shops'])
@extend_schema_view(
    get=extend_schema(
        summary='Получить список магазинов',
        responses={
            status.HTTP_200_OK: OpenApiResponse(ShopSerializer,
                                                description='OK'),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(description='None')
        }
    )
)
class ShopView(APIView):
    """
    Класс для просмотра списка магазинов
    """
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        shops = Shop.objects.filter(state=True)
        serializer = ShopSerializer(shops, many=True)
        return Response(serializer.data)


@extend_schema(tags=['Products'])
@extend_schema_view(
    get=extend_schema(
        summary='Получить информацию о  продуктах',
        parameters=[
            OpenApiParameter(
                name='shop_id',
                location=OpenApiParameter.QUERY,
                required=False,
                type=int
            ),
            OpenApiParameter(
                name='category_id',
                location=OpenApiParameter.QUERY,
                required=False,
                type=int
            )
        ],

        responses={
            status.HTTP_200_OK: OpenApiResponse(ProductInfoSerializer,
                                                description='OK'),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(response=None),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(description='Bad request(something invalid)'),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(description='Not found')
        }
    )
)
class ProductInfoView(APIView):
    """
    Класс для поиска товаров
    """
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        query = Q(shop__state=True)
        shop_id = request.query_params.get('shop_id')
        category_id = request.query_params.get('category_id')

        if shop_id:
            query = query & Q(shop_id=shop_id)

        if category_id:
            query = query & Q(product__category_id=category_id)

        try:
            queryset = ProductInfo.objects.filter(
                query).select_related(
                'shop', 'product__category').prefetch_related(
                'product_parameters__parameter').distinct()
        except ObjectDoesNotExist as error:
            return JsonResponse({'Status': False, 'Error': error}, status=404)

        serializer = ProductInfoSerializer(queryset, many=True)

        return Response(serializer.data)


@extend_schema(tags=['Cart User'])
@extend_schema_view(
    get=extend_schema(
        summary='Получить список продуктов в корзине',
        responses={
            status.HTTP_200_OK: OpenApiResponse(CartItemSerializer,
                                                description='OK'),
            status.HTTP_401_UNAUTHORIZED: OpenApiResponse(description='Check Token Authorization'),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(description='Cart not found')
        }
    ),
    post=extend_schema(
        summary='Добавить продукты в корзину',
        request=CartSchemaSerializer,
        responses={
            status.HTTP_200_OK: OpenApiResponse(CartItemSerializer,
                                                description='OK'),
            status.HTTP_401_UNAUTHORIZED: OpenApiResponse(description='Check Token Authorization'),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(description='Not found')
        },
        examples=[
            OpenApiExample(
                "Post Example",
                description='Body for example',
                value=
                [
                    {"product_info": 3, "quantity": 10},
                    {"product_info": 2, "quantity": 15}
                ],
            ),
        ],
    ),
    patch=extend_schema(
        summary='Изменить количество продуктов в корзине',
        request=CartItemSchemaSerializer,
        responses={
            status.HTTP_200_OK: OpenApiResponse(CartItemSerializer,
                                                description='OK'),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(description='Not found'),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(description='Bad request(something invalid)'),
            status.HTTP_401_UNAUTHORIZED: OpenApiResponse(description='Check your Token Authorization'),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(response=None)
        }
    ),
    delete=extend_schema(
        summary='Удалить продукты из корзины',
        responses={
            status.HTTP_204_NO_CONTENT: OpenApiResponse(description='OK'),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(description='Bad request(something invalid)'),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(description='Not found'),
            status.HTTP_401_UNAUTHORIZED: OpenApiResponse(description='Check your Token Authorization')
        },
        parameters=[
            OpenApiParameter(
                name='item_id',
                location=OpenApiParameter.QUERY,
                description='id cart_item',
                required=True,
                type=int
            )
        ]

    ),
)
class CartView(APIView):
    """
    Класс для работы с корозиной пользователя
    """

    def get(self, request, *args, **kwargs):
        """
        Список продуктов в корзине
        """
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
        """
        Добавить продукты в корзину
        """
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
        """
        Изменить количество
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in is required'}, status=401)

        item_id = request.data['item_id']

        cart = Cart.objects.get(user=request.user)

        try:
            cart_item = CartItem.objects.get(cart=cart, id=item_id)
        except ObjectDoesNotExist:
            return JsonResponse({'Status': False, 'Errors': 'cart item not found'}, status=404)

        quantity = request.data['quantity']
        if quantity < 1:
            cart_item.delete()
            return JsonResponse({'Status': True, 'message': 'Cart item was delete'}, status=201)

        else:
            cart_item.quantity = quantity
            cart_item.save()

            item_serializer = CartItemSerializer(cart_item, partial=True)

            return JsonResponse({'Status': True, 'updates': item_serializer.data})

    def delete(self, request, *args, **kwargs):
        """
        Удалить продукты из корзины
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in is required'}, status=401)

        cart = Cart.objects.get(user=request.user)

        item_id = request.query_params.get('item_id')

        try:
            cart_item = CartItem.objects.get(cart=cart, id=item_id)
            cart_item.delete()
        except ObjectDoesNotExist as error:
            return JsonResponse({'Status': False, 'Error': error}, status=404)

        return JsonResponse({'Status': True}, status=204)


@extend_schema(tags=['Partner'])
@extend_schema_view(
    post=extend_schema(
        summary='Загрузка данных',
        request=LoadPartnerSerializer(),
        responses={
            status.HTTP_200_OK: OpenApiResponse(description='OK'),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(description='Bad request(something invalid)'),
            status.HTTP_401_UNAUTHORIZED: OpenApiResponse(description='Check your Token Authorization'),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(response=None)
        }
    )
)
class PartnerUpdate(APIView):
    """
    Класс обновления прайса поставщиков
    """

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in is required'}, status=401)

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


@extend_schema(tags=['Partner'])
@extend_schema_view(
    get=extend_schema(
        summary='Получить данные магазина',
        responses={
            status.HTTP_200_OK: OpenApiResponse(ShopSerializer,
                                                description='OK'),
            status.HTTP_401_UNAUTHORIZED: OpenApiResponse(description='Check your Token Authorization'),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(description='Not found')
        }
    ),
    post=extend_schema(
        summary='Создать магазин',
        request=ShopSerializer,
        responses={
            status.HTTP_200_OK: OpenApiResponse(ShopSerializer,
                                                description='Created'),
            status.HTTP_401_UNAUTHORIZED: OpenApiResponse(description='Check your Token Authorization'),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(description='Bad request(something invalid)')
        }
    ),
    patch=extend_schema(
        summary='Изменить поля магазина',
        request=ShopSerializer(),
        description='Поля для изменения: '
                    'name - название магазина; '
                    'url - ссылка; '
                    'state - статус приёма заказов;',
        responses={
            status.HTTP_200_OK: OpenApiResponse(ShopSerializer,
                                                description='Update'),
            status.HTTP_401_UNAUTHORIZED: OpenApiResponse(description='Check your Token Authorization'),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(description='Bad request(something invalid)'),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(description='Not found'),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(response=None)
        }

    ),
    delete=extend_schema(
        summary='Удалить магазин',
        description='Требует быть авторизованным пользователем без передачи query параметров и json в теле запроса',
        responses={
            status.HTTP_204_NO_CONTENT: OpenApiResponse(description='OK'),
            status.HTTP_401_UNAUTHORIZED: OpenApiResponse(description='Check your Token Authorization'),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(description='Shop is not found')
        }

    )
)
class PartnerShop(APIView):
    """
    Класс для работы поставщика со своим магазином
    """

    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in is required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Errors': 'Only for partners'}, status=403)

        shop = request.user.shop
        serializer_shop = ShopSerializer(shop)

        return Response(serializer_shop.data)

    def post(self, request, *args, **kwargs):
        if 'name' in request.data:
            if not request.user.is_authenticated:
                return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=401)

            if request.user.type != 'shop':
                return JsonResponse({'Status': False, 'Errors': 'Only for partners'}, status=401)

            shop_data = request.data
            shop_data['user'] = request.user.id
            shop = ShopSerializer(data=shop_data)
            if shop.is_valid():
                shop.save()
                return JsonResponse({'Status': True, 'Message': shop.data})
            else:
                return JsonResponse({'Status': False, 'Errors': shop.errors}, status=400)

        return JsonResponse({'Status': False, 'Errors': 'The name of the store is not specified'}, status=400)

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
            return JsonResponse({'Status': True, 'updates': serializer_shop.data}, status=200)
        except ValidationError as error:
            return JsonResponse({'Status': False, 'Errors': error})

    def delete(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=401)

        try:
            shop = Shop.objects.get(user=request.user)
        except ObjectDoesNotExist as error:
            return JsonResponse({'Status': False, 'Errors': error}, status=404)

        shop.delete()

        return JsonResponse({'Status': True}, status=204)


@extend_schema(tags=['Contacts'])
@extend_schema_view(
    get=extend_schema(
        summary='Получить контактные данные',
        responses={
            status.HTTP_200_OK: OpenApiResponse(ContactsSerializer,
                                                description='OK'),
            status.HTTP_401_UNAUTHORIZED: OpenApiResponse(description='Check your Token Authorization'),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(response=None)
        }
    ),
    post=extend_schema(
        summary='Создать контактные данные',
        description='Обязательные поля: city; street; phone;',
        request=ContactsSerializer,
        responses={
            status.HTTP_200_OK: OpenApiResponse(ContactsSerializer,
                                                description='OK'),
            status.HTTP_401_UNAUTHORIZED: OpenApiResponse(description='Check your Token Authorization'),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(description='Bad request (something invalid)'),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(response=None)
        }
    ),
    put=extend_schema(
        summary='Изменить контактные данные',
        request=ContactsSerializer,
        parameters=[
            OpenApiParameter(
                name='contact_id',
                location=OpenApiParameter.QUERY,
                description='id your contact',
                required=True,
                type=int
            )
        ],
        responses={
            status.HTTP_200_OK: OpenApiResponse(ContactsSerializer,
                                                description='Update'),
            status.HTTP_401_UNAUTHORIZED: OpenApiResponse(description='Check your Token Authorization'),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(description='Bad request (something invalid)'),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(description='Contact not found'),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(response=None)
        }

    ),
    delete=extend_schema(
        summary='Удалить контакт/ты',
        parameters=[
            OpenApiParameter(
                name='contact_id',
                location=OpenApiParameter.QUERY,
                description='id contact for delete',
                required=True,
                type=int
            )
        ],
        responses={
            status.HTTP_200_OK: OpenApiResponse(description='Deleted'),
            status.HTTP_401_UNAUTHORIZED: OpenApiResponse(description='Check your Token Authorization'),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(description='Contact not found'),
            status.HTTP_500_INTERNAL_SERVER_ERROR: OpenApiResponse(response=None)
        }
    )
)
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
            return JsonResponse({'Status': False, 'Error': 'log in is required'}, status=401)

        if {'city', 'street', 'phone'}.issubset(request.data):
            shop_data = request.data
            shop_data['user'] = request.user.id

            contact_serializer = ContactsSerializer(data=shop_data)
            if contact_serializer.is_valid():
                contact_serializer.save()
                return JsonResponse({'Status': True, 'your contacts': contact_serializer.data}, status=200)
            else:
                return JsonResponse({'Status': False, 'Error': contact_serializer.errors}, status=400)

        return JsonResponse({'Status': False, 'Error': 'All the necessary arguments are not stated'}, status=400)

    def delete(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=401)

        contact_id = request.query_params.get('contact_id')

        try:
            contact = Contacts.objects.get(user=request.user.id, id=contact_id)
        except ObjectDoesNotExist as error:
            return JsonResponse({'Status': False, 'Error': error}, status=404)

        contact.delete()

        return JsonResponse({'Status': True}, status=204)

    def put(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=401)

        contact_id = request.query_params.get('contact_id')

        try:
            contact = Contacts.objects.get(user=request.user, id=contact_id)
        except ObjectDoesNotExist as error:
            return JsonResponse({'Status': False, 'Error': error}, status=404)

        contact_serializer = ContactsSerializer(contact, data=request.data, partial=True)
        if contact_serializer.is_valid():
            contact_serializer.save()
            return JsonResponse({'Status': True, 'updates': contact_serializer.data})

        return JsonResponse({'Status': False, 'Error': contact_serializer.errors}, status=400)


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

            # Используем контекстный менеджер transaction для выполнения транзакций(всё или ничего)
            with transaction.atomic():
                order = Order.objects.create(
                    user=request.user,
                    cart=cart,
                    contacts_id=contact_id,
                    state='new'
                )

                order_items = []
                updated_product_infos = []

                for cart_item in cart_items:
                    order_item = OrderItem(
                        order=order,
                        product_info=cart_item.product_info,
                        quantity=cart_item.quantity,
                        price=cart_item.product_info.price
                    )
                    order_items.append(order_item)

                    # Обновляем ProductInfo(quantity)
                    updated_product_info = ProductInfo.objects.get(id=cart_item.product_info.id)
                    updated_product_info.quantity = F('quantity') - cart_item.quantity
                    updated_product_infos.append(updated_product_info)

                # Сохраняем OrderItem и обновленные ProductInfo
                OrderItem.objects.bulk_create(order_items)
                ProductInfo.objects.bulk_update(updated_product_infos, ['quantity'])

                # Удаляем позиции из CartItem которые были добавлены в OrderItem
                cart_items.delete()

            new_order_signal(sender=self.__class__, user_id=request.user.id)
            serializer = OrderItemSerializer(order_items, many=True).data

            return JsonResponse({'Status': True, 'result': serializer})

        return JsonResponse({'Status': False, 'Errors': 'All the necessary arguments are not stated'})


class PartnerOrders(APIView):
    """
    Класс для получения заказов поставщиками
    """

    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Only for shops'}, status=403)

        order = Order.objects.filter(
            ordered_items__product_info__shop__user_id=request.user.id).prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').select_related('contacts').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

        serializer = OrderSerializer(order, many=True)
        return Response(serializer.data)

    def patch(self, request, *args, **kwargs):
        """
        Для изменения статуса заказа
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Only for partners'}, status=403)

        if {'order', 'state'}.issubset(request.data):
            state = request.data['state']

            try:
                order = Order.objects.get(id=request.data['order'])
                user_id = order.user.id

                order = Order.objects.filter(
                    id=request.data['order'],
                    ordered_items__product_info__shop__user_id=request.user.id,
                ).update(state=state)
            except ObjectDoesNotExist:
                return JsonResponse({'Status': False, 'Error': 'Order not found'}, status=404)

            new_order_signal(sender=self.__class__, user_id=user_id)

            return JsonResponse({'Status': True, 'state': state})

        else:
            return JsonResponse({'Status': False, 'Error': 'All the necessary arguments are not stated'})


class PasswordReset(ResetPasswordRequestToken):
    """
    Класс для сброса пароля пользователя
    """

    def create(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in is required'})

        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = get_user_model().objects.filter(email=email).first()
            except ObjectDoesNotExist as error:
                return JsonResponse({'Status': False, 'Error': error})

            password_reset_token_created.send(sender=self.__class__, instance=user)

        return JsonResponse({'Status': False, 'Error': serializer.errors})


class PasswordResetConfirm(ResetPasswordConfirm):
    """
    Класс для подтверждения сброса пароля
    """

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            value_token = serializer.validated_data['token']
            password = serializer.validated_data['password']
            password_confirm = request.data['password_confirm']

            if not password == password_confirm:
                return JsonResponse({'Status': False, 'Error': 'Поле password не совпадает с полем password_confirm'})

            try:
                token = ResetPasswordToken.objects.get(key=value_token)
            except ObjectDoesNotExist as error:
                return JsonResponse({'Status': False, 'Error': error})

            if token:
                user = token.user
                user.set_password(password)
                user.save()
                token.delete()

                return JsonResponse({'Status': True, 'message': 'Password has been reset successfully.'})

            return JsonResponse({'Status': False, 'Error': 'The token has expired.'}, status=400)
