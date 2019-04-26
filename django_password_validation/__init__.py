# code in django_password_validation_backport.validators was backported from
# 0.1.5: added unit tests; minor fixes
# 0.1.4: django.contrib.auth.password_validation (Django 1.9)
__version__ = "0.1.5"

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
    NumericPasswordValidator, \
    AtLeastOneDigitValidator, \
    AtLeastOnePunctuationCharacterValidator, \
    AtLeastOneUppercaseCharacterValidator, \
    AtLeastOneLowercaseCharacterValidator, \
    NoRepeatsValidator

from .middleware import \
    DjangoPasswordValidationMiddleware