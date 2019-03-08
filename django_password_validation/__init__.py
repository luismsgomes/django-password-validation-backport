# code in django_password_validation_backport.validators was backported from
# django.contrib.auth.password_validation (Django 1.9)
__version__ = "0.1.3"

from .validators import \
    get_default_password_validators, \
    get_password_validators, \
    validate_password, \
    password_changed, \
    password_validators_help_texts, \
    password_validators_help_text_html, \
    MinimumLengthValidator, \
    UserAttributeSimilarityValidator, \
    CommonPasswordValidator, \
    NumericPasswordValidator

from .middleware import \
    DjangoPasswordValidationMiddleware