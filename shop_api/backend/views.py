from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from rest_framework.response import Response
from rest_framework.views import APIView

from backend.models import ConfirmEmailToken, Category, Shop, ProductInfo
from backend.serializers import UserSerializer, CategorySerializer, ShopSerializer, ProductInfoSerializer
from backend.signals import new_user_registered
from rest_framework.authentication import authenticate
from rest_framework.authtoken.models import Token
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Q, Sum, F


class RegisterUserAccount(APIView):
    """
    Регистрацция нового пользователя
    """

    def post(self, request, *args, **kwargs):
        errors = {}
        if {'first_name', 'last_name', 'email', 'password', 'company', 'position', 'username'}.issubset(request.data):

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
                    user.save()
                    new_user_registered.send(sender=self.__class__, user_id=user.id)
                    return JsonResponse({'Status': True, 'Created': user.username})
                else:
                    errors['user'] = user_serializer.errors
        if errors:
            return JsonResponse({'Status': False, 'Errors': errors})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


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
                return JsonResponse({'Status': False, 'Errors': 'Неправильно указан email или token'})
        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


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

            return JsonResponse({'Status': False, 'Errors': 'Пользователь не найден или электронная почта '
                                                            'не подтверждена'})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class CategoryView(APIView):
    """
    Класс для просмотра категорий
    """
    def get(self, request):
        category = Category.objects.all()
        serializer_class = CategorySerializer(category, many=True)
        return JsonResponse({'Status': True, 'list_categories': serializer_class.data})


class ShopView(APIView):
    """
    Класс для просмотра списка магазинов
    """
    def get(self, request):
        shops = Shop.objects.all()
        serializers_shop = ShopSerializer(shops, many=True)
        return JsonResponse({'Status': True, 'list_shops': serializers_shop.data})

    def post(self, request, *args, **kwargs):
        if 'name' in request.data:
            if not request.user.is_authenticated:
                return JsonResponse({'Status': False, 'Errors': 'Log in required'})

            if request.user.type != 'shop':
                return JsonResponse({'Status': False, 'Errors': 'Только для поставщиков'})

            shop_data = request.data
            shop_data['user'] = request.user.id
            shop = ShopSerializer(data=shop_data)
            if shop.is_valid():
                shop.save()
                return JsonResponse({'Status': True, 'Message': shop.data})
            else:
                return JsonResponse({'Status': False, 'Errors': shop.errors})

        return JsonResponse({'Status': False, 'Errors': 'Не указано название магазина'})

    def put(self, request, shop_id):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in is required'})

        try:
            shop = Shop.objects.get(id=shop_id)
        except ObjectDoesNotExist:
            return JsonResponse({'Status': False, 'Errors': 'Магазин не найден'})

        if shop.user != request.user:
            return JsonResponse({
                'Status':False,
                'Errors': 'У вас нет прав доступа к этому магазину'
            }, status=403)

        shop_data = request.data
        shop_serializer = ShopSerializer(shop, data=shop_data, partial=True)

        if shop_serializer.is_valid():
            shop_serializer.save()
            return JsonResponse({'Status': True, 'Message': 'Магазин обновлен', 'shop': shop_serializer.data})
        else:
            return JsonResponse({'Status': False, 'Errors': shop_serializer.errors})


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









