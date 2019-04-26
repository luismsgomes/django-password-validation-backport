# Password validators backported from django.contrib.auth.password_validation (Django 1.9)
#
# Changelog:
#
# 0.2.0: major bugfix
# 0.1.6: added simple character-based validators:
#    AtLeastOneDigitValidator
#    AtLeastOnePunctuationCharacterValidator
#    AtLeastOneUppercaseCharacterValidator
#    AtLeastOneLowercaseCharacterValidator
#    NoRepeatsValidator
# 0.1.5: added unit tests; minor fixes
# 0.1.4: updated list of common passwords from Django 2.2
# 0.1.3: first public release with 4 validators:
#    MinimumLengthValidator
#    UserAttributeSimilarityValidator
#    CommonPasswordValidator
#    NumericPasswordValidator

__version__ = "0.2.0"

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