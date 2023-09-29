from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from backend.models import User, Shop, Category, Product, ProductInfo, Parameter, ProductParameter, Cart, CartItem, \
    Order, OrderItem, Contacts, ConfirmEmailToken


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    """
    Панель управления пользователями
    """
    model = User
    fieldsets = (
        (None, {'fields': ('email', 'password', 'type')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'company', 'position')}),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    list_display = ('email', 'first_name', 'last_name', 'is_staff', 'is_active')
    list_filter = ('is_active', 'email_confirmed', 'is_staff', 'is_superuser', 'type')
    search_fields = ('email',)


@admin.register(Shop)
class ShopAdmin(admin.ModelAdmin):
    """
    Панель управления магазином
    """

    list_display = ('user', 'name', 'url', 'state')
    list_editable = ('state',)
    list_filter = ('state',)
    search_fields = ('name', 'url')
    fieldsets = (
        (None, {'fields': ('name', 'url', 'state')}),
    )


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    """
    Панель управления категориями
    """
    fieldsets = (
        (None, {'fields': ('name', 'shops')}),
    )
    list_display = ('name', 'get_shop_names')
    list_filter = ('shops', 'name')
    search_fields = ('name', 'shops')

    def get_shop_names(self, obj):
        """
        Метод возвращает имена магазинов в виде строки
        """
        return ','.join([shop.name for shop in obj.shops.all()])

    get_shop_names.shorts_descriptions = 'shops'


class CartProductInline(admin.TabularInline):
    model = CartItem
    extra = 1


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    """
    Панель управления продуктами
    """
    fieldsets = (
        (None, {'fields': ('name', 'category')}),
    )
    list_display = ('category', 'name')
    list_filter = ('category', 'name')
    search_fields = ('name',)
    inlines = [CartProductInline]


@admin.register(ProductInfo)
class ProductInfoAdmin(admin.ModelAdmin):
    """
    Панель управления информацией о продукте
    """

    fieldsets = (
        (None, {'fields': ('external_id', 'model', 'product', 'shop', 'quantity', 'price', 'price_rrc')}),
    )
    list_display = (
        'external_id', 'model',
        'product', 'shop',
        'quantity', 'price',
        'price_rrc',
    )
    list_filter = ('shop', 'price', 'price_rrc')
    search_fields = ('model',)


@admin.register(Parameter)
class ParameterAdmin(admin.ModelAdmin):
    """
    Панель управления параметрами продукта
    """

    fieldsets = (
        (None, {'fields': ('name',)}),
    )
    list_display = ('name',)
    search_fields = ('name',)


@admin.register(ProductParameter)
class ProductParameterAdmin(admin.ModelAdmin):
    """
    Панель управления параметрами продукта
    """

    fieldsets = (
        (None, {'fields': ('product_info', 'parameter', 'value')}),
    )
    list_display = ('product_info', 'parameter', 'value')
    list_filter = ('parameter',)


@admin.register(Contacts)
class ContactsAdmin(admin.ModelAdmin):
    """
    Панель управления контактами пользователей
    """
    fieldsets = (
        (None, {'fields': (
            'user', 'city',
            'street', 'house',
            'structure', 'building',
            'apartment', 'phone',
        )}),
    )
    list_display = (
        'user', 'city',
        'street', 'house',
        'structure', 'building',
        'apartment', 'phone'
    )
    search_fields = ('user', 'phone')


@admin.register(Cart)
class CartAdmin(admin.ModelAdmin):
    """
    Панель управления корзиной
    """

    fieldsets = (
        (None, {'fields': ('user',)}),
    )
    list_display = ('user',)

    # def get_product_names(self, obj):
    #     return ','.join([product.name for product in obj.products.all()])
    #
    # get_product_names.shorts_descriptions = 'products'
