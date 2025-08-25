from django.db import models


class Role(models.Model):
    name = models.CharField(max_length=50, unique=True, verbose_name='Название роли')

    class Meta:
        verbose_name = 'Роль'
        verbose_name_plural = 'Роли'

    def __str__(self):
        return self.name


class User(models.Model):
    first_name = models.CharField(max_length=50, verbose_name='Имя')
    last_name = models.CharField(max_length=50, verbose_name='Фамилия')
    patronymic = models.CharField(max_length=50, blank=True, verbose_name='Отчество')
    email = models.EmailField(unique=True, verbose_name='Email')
    password = models.CharField(max_length=128, verbose_name='Пароль')
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, verbose_name='Роль')
    is_active = models.BooleanField(default=True, verbose_name='Активен?')

    class Meta:
        verbose_name = 'Пользователь'
        verbose_name_plural = 'Пользователи'

    def __str__(self):
        return self.email


class BusinessResource(models.Model):
    name = models.CharField(max_length=50, unique=True, verbose_name='Название ресурса')

    class Meta:
        verbose_name = 'Ресурс'
        verbose_name_plural = 'Ресурсы'

    def __str__(self):
        return self.name


class AccessRule(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE, verbose_name='Роль')
    resource = models.ForeignKey(BusinessResource, on_delete=models.CASCADE, verbose_name='Ресурс')
    read_permission = models.BooleanField(default=False, verbose_name='Разрешение на чтение')
    read_all_permission = models.BooleanField(default=False, verbose_name='Разрешение на чтение всего')
    create_permission = models.BooleanField(default=False, verbose_name='Разрешение на создание')
    update_permission = models.BooleanField(default=False, verbose_name='Разрешение на редактирование')
    delete_permission = models.BooleanField(default=False, verbose_name='Разрешение на удаление')

    class Meta:
        verbose_name = 'Разрешение'
        verbose_name_plural = 'Разрешения'

    def __str__(self):
        return f'{self.role.name} - {self.resource.name}'
