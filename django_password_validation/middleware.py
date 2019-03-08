import importlib
import logging

from django.core.exceptions import MiddlewareNotUsed
from .validators import validate_password, password_changed


LOG = logging.getLogger('django_password_validation')


def inject_password_validation_into_django_password_form():
    from django.contrib.auth.forms import SetPasswordForm
    __real_clean_password2 = SetPasswordForm.clean_new_password2

    def clean_new_password2(self):
        password2 = self.cleaned_data.get('new_password2')
        validate_password(password2, self.user)
        return __real_clean_password2(self)

    SetPasswordForm.clean_new_password2 = clean_new_password2


def inject_password_validation_into_django_user_model():
    from django.contrib.auth.models import User
    __real_save = User.save

    def save(self, *args, **kwargs):
        LOG.info("User.save() => django_password_validation.password_change()")
        __real_save(self, *args, **kwargs)
        if self.password is not None:
            password_changed(self.password, self)

    User.save = save


class DjangoPasswordValidationMiddleware:
    def __init__(self):
        inject_password_validation_into_django_password_form()
        inject_password_validation_into_django_user_model()
        raise MiddlewareNotUsed
