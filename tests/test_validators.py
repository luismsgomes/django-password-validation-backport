# encoding: utf8
import os

from django.conf import settings
settings.configure()

settings.INSTALLED_APPS=[
    'test_validators',
]
settings.MIDDLEWARE=[
    'django_password_validation.DjangoPasswordValidationMiddleware',
]
settings.DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'db.sqlite3',
    },
}

import django
django.setup()

from django.contrib.auth.models import User
from django_password_validation import (
    CommonPasswordValidator,
    MinimumLengthValidator,
    NumericPasswordValidator,
    UserAttributeSimilarityValidator,
    AtLeastOneDigitValidator,
    AtLeastOnePunctuationCharacterValidator,
    AtLeastOneUppercaseCharacterValidator,
    AtLeastOneLowercaseCharacterValidator,
    NoRepeatsValidator,
    get_default_password_validators,
    get_password_validators,
    password_changed,
    password_validators_help_text_html,
    password_validators_help_texts,
    validate_password,
)
from django.core.exceptions import ValidationError
from django.db import models
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils.html import conditional_escape


@override_settings(AUTH_PASSWORD_VALIDATORS=[
    {'NAME': 'django_password_validation.CommonPasswordValidator'},
    {'NAME': 'django_password_validation.MinimumLengthValidator', 'OPTIONS': {
        'min_length': 12,
    }},
])
class PasswordValidationTest(SimpleTestCase):
    def test_get_default_password_validators(self):
        get_default_password_validators.cache_clear()
        validators = get_default_password_validators()
        get_default_password_validators.cache_clear()
        self.assertEqual(len(validators), 2)
        self.assertEqual(validators[0].__class__.__name__, 'CommonPasswordValidator')
        self.assertEqual(validators[1].__class__.__name__, 'MinimumLengthValidator')
        self.assertEqual(validators[1].min_length, 12)

    def test_get_password_validators_custom(self):
        validator_config = [{'NAME': 'django_password_validation.CommonPasswordValidator'}]
        validators = get_password_validators(validator_config)
        self.assertEqual(len(validators), 1)
        self.assertEqual(validators[0].__class__.__name__, 'CommonPasswordValidator')

        self.assertEqual(get_password_validators([]), [])

    def test_validate_password(self):
        self.assertIsNone(validate_password('sufficiently-long'))
        msg_too_short = 'This password is too short. It must contain at least 12 characters.'

        with self.assertRaises(ValidationError) as cm:
            validate_password('django4242')
        self.assertEqual(cm.exception.messages, [msg_too_short])
        self.assertEqual(cm.exception.error_list[0].code, 'password_too_short')

        with self.assertRaises(ValidationError) as cm:
            validate_password('password')
        self.assertEqual(cm.exception.messages, ['This password is too common.', msg_too_short])
        self.assertEqual(cm.exception.error_list[0].code, 'password_too_common')

        self.assertIsNone(validate_password('password', password_validators=[]))

    def test_password_changed(self):
        self.assertIsNone(password_changed('password'))

    def test_password_changed_with_custom_validator(self):
        class Validator:
            def password_changed(self, password, user):
                self.password = password
                self.user = user

        user = object()
        validator = Validator()
        password_changed('password', user=user, password_validators=(validator,))
        self.assertIs(validator.user, user)
        self.assertEqual(validator.password, 'password')

    def test_password_validators_help_texts(self):
        help_texts = password_validators_help_texts()
        self.assertEqual(len(help_texts), 2)
        self.assertIn('12 characters', help_texts[1])

        self.assertEqual(password_validators_help_texts(password_validators=[]), [])

    def test_password_validators_help_text_html(self):
        help_text = password_validators_help_text_html()
        self.assertEqual(help_text.count('<li>'), 2)
        self.assertIn('12 characters', help_text)

    def test_password_validators_help_text_html_escaping(self):
        class AmpersandValidator:
            def get_help_text(self):
                return 'Must contain &'
        help_text = password_validators_help_text_html([AmpersandValidator()])
        self.assertEqual(help_text, '<ul><li>Must contain &amp;</li></ul>')
        # help_text is marked safe and therefore unchanged by conditional_escape().
        self.assertEqual(help_text, conditional_escape(help_text))

    @override_settings(AUTH_PASSWORD_VALIDATORS=[])
    def test_empty_password_validator_help_text_html(self):
        self.assertEqual(password_validators_help_text_html(), '')

class MinimumLengthValidatorTest(SimpleTestCase):
    def test_validate(self):
        expected_error = "This password is too short. It must contain at least %d characters."
        self.assertIsNone(MinimumLengthValidator().validate('12345678'))
        self.assertIsNone(MinimumLengthValidator(min_length=3).validate('123'))

        with self.assertRaises(ValidationError) as cm:
            MinimumLengthValidator().validate('1234567')
        self.assertEqual(cm.exception.messages, [expected_error % 8])
        self.assertEqual(cm.exception.error_list[0].code, 'password_too_short')

        with self.assertRaises(ValidationError) as cm:
            MinimumLengthValidator(min_length=3).validate('12')
        self.assertEqual(cm.exception.messages, [expected_error % 3])

    def test_help_text(self):
        self.assertEqual(
            MinimumLengthValidator().get_help_text(),
            "Your password must contain at least 8 characters."
        )

class UserAttributeSimilarityValidatorTest(TestCase):

    def test_validate(self):
        user = User(
            username='testclient', password='password', email='testclient@example.com',
            first_name='Test', last_name='Client',
        )
        expected_error = "The password is too similar to the %s."

        self.assertIsNone(UserAttributeSimilarityValidator().validate('testclient'))

        with self.assertRaises(ValidationError) as cm:
            UserAttributeSimilarityValidator().validate('testclient', user=user),
        self.assertEqual(cm.exception.messages, [expected_error % "username"])
        self.assertEqual(cm.exception.error_list[0].code, 'password_too_similar')

        with self.assertRaises(ValidationError) as cm:
            UserAttributeSimilarityValidator().validate('example.com', user=user),
        self.assertEqual(cm.exception.messages, [expected_error % "email address"])

        with self.assertRaises(ValidationError) as cm:
            UserAttributeSimilarityValidator(
                user_attributes=['first_name'],
                max_similarity=0.3,
            ).validate('testclient', user=user)
        self.assertEqual(cm.exception.messages, [expected_error % "first name"])
        # max_similarity=1 doesn't allow passwords that are identical to the
        # attribute's value.
        with self.assertRaises(ValidationError) as cm:
            UserAttributeSimilarityValidator(
                user_attributes=['first_name'],
                max_similarity=1,
            ).validate(user.first_name, user=user)
        self.assertEqual(cm.exception.messages, [expected_error % "first name"])
        # max_similarity=0 rejects all passwords.
        with self.assertRaises(ValidationError) as cm:
            UserAttributeSimilarityValidator(
                user_attributes=['first_name'],
                max_similarity=0,
            ).validate('XXX', user=user)
        self.assertEqual(cm.exception.messages, [expected_error % "first name"])
        # Passes validation.
        self.assertIsNone(
            UserAttributeSimilarityValidator(user_attributes=['first_name']).validate('testclient', user=user)
        )

    def test_validate_property(self):
        user = User(
            username='foobar', password='password', email='testclient@example.com',
            first_name='Test', last_name='Client',
        )
        with self.assertRaises(ValidationError) as cm:
            UserAttributeSimilarityValidator().validate('foobar', user=user),
        self.assertEqual(cm.exception.messages, ['The password is too similar to the username.'])

    def test_help_text(self):
        self.assertEqual(
            UserAttributeSimilarityValidator().get_help_text(),
            "Your password can't be too similar to your other personal information."
        )

class CommonPasswordValidatorTest(SimpleTestCase):
    def test_validate(self):
        expected_error = "This password is too common."
        self.assertIsNone(CommonPasswordValidator().validate('a-safe-password'))

        with self.assertRaises(ValidationError) as cm:
            CommonPasswordValidator().validate('godzilla')
        self.assertEqual(cm.exception.messages, [expected_error])

    def test_validate_custom_list(self):
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'common-passwords-custom.txt')
        validator = CommonPasswordValidator(password_list_path=path)
        expected_error = "This password is too common."
        self.assertIsNone(validator.validate('a-safe-password'))

        with self.assertRaises(ValidationError) as cm:
            validator.validate('from-my-custom-list')
        self.assertEqual(cm.exception.messages, [expected_error])
        self.assertEqual(cm.exception.error_list[0].code, 'password_too_common')

    def test_validate_django_supplied_file(self):
        validator = CommonPasswordValidator()
        for password in validator.passwords:
            self.assertEqual(password, password.lower())

    def test_help_text(self):
        self.assertEqual(
            CommonPasswordValidator().get_help_text(),
            "Your password can't be a commonly used password."
        )


class NumericPasswordValidatorTest(SimpleTestCase):
    def test_validate(self):
        expected_error = "This password is entirely numeric."
        self.assertIsNone(NumericPasswordValidator().validate('a-safe-password'))

        with self.assertRaises(ValidationError) as cm:
            NumericPasswordValidator().validate('42424242')
        self.assertEqual(cm.exception.messages, [expected_error])
        self.assertEqual(cm.exception.error_list[0].code, 'password_entirely_numeric')

    def test_help_text(self):
        self.assertEqual(
            NumericPasswordValidator().get_help_text(),
            "Your password can't be entirely numeric."
        )


class AtLeastOneDigitTest(SimpleTestCase):
    def test_validate(self):
        expected_error = "This password does not contain a digit."
        self.assertIsNone(AtLeastOneDigitValidator().validate('abc123'))

        with self.assertRaises(ValidationError) as cm:
            AtLeastOneDigitValidator().validate('abcdefg')
        self.assertEqual(cm.exception.messages, [expected_error])
        self.assertEqual(cm.exception.error_list[0].code, 'password_without_digit')

    def test_help_text(self):
        self.assertEqual(
            AtLeastOneDigitValidator().get_help_text(),
            "Your password must contain at least one digit."
        )


class AtLeastOnePunctuationCharacterTest(SimpleTestCase):
    def test_validate(self):
        expected_error = "This password does not contain a punctuation character."
        self.assertIsNone(AtLeastOnePunctuationCharacterValidator().validate('a safe-password'))

        with self.assertRaises(ValidationError) as cm:
            AtLeastOnePunctuationCharacterValidator().validate('123abc')
        self.assertEqual(cm.exception.messages, [expected_error])
        self.assertEqual(cm.exception.error_list[0].code, 'password_without_punctuation')

    def test_help_text(self):
        self.assertEqual(
            AtLeastOnePunctuationCharacterValidator().get_help_text(),
            "Your password must contain at least one punctuation character."
        )


class AtLeastOneUppercaseCharacterTest(SimpleTestCase):
    def test_validate(self):
        expected_error = "This password does not contain an uppercase character."
        self.assertIsNone(AtLeastOneUppercaseCharacterValidator().validate('A good password'))

        with self.assertRaises(ValidationError) as cm:
            AtLeastOneUppercaseCharacterValidator().validate('a bad password')
        self.assertEqual(cm.exception.messages, [expected_error])
        self.assertEqual(cm.exception.error_list[0].code, 'password_without_uppercase')

    def test_help_text(self):
        self.assertEqual(
            AtLeastOneUppercaseCharacterValidator().get_help_text(),
            "Your password must contain at least one uppercase character."
        )


class AtLeastOneLowercaseCharacterTest(SimpleTestCase):
    def test_validate(self):
        expected_error = "This password does not contain a lowercase character."
        self.assertIsNone(AtLeastOneLowercaseCharacterValidator().validate('a-safe-password'))

        with self.assertRaises(ValidationError) as cm:
            AtLeastOneLowercaseCharacterValidator().validate('42424242')
        self.assertEqual(cm.exception.messages, [expected_error])
        self.assertEqual(cm.exception.error_list[0].code, 'password_without_lowercase')

    def test_help_text(self):
        self.assertEqual(
            AtLeastOneLowercaseCharacterValidator().get_help_text(),
            "Your password must contain at least one lowercase character."
        )


class NoRepeatsTest(SimpleTestCase):
    def test_validate(self):
        expected_error = "This password contains a character repeated more than 2 times in a row."
        self.assertIsNone(NoRepeatsValidator().validate('a-safe-password'))

        with self.assertRaises(ValidationError) as cm:
            NoRepeatsValidator().validate('is this is a baaad password?')
        self.assertEqual(cm.exception.messages, [expected_error])
        self.assertEqual(cm.exception.error_list[0].code, 'password_contains_repeats')

    def test_help_text(self):
        self.assertEqual(
            NoRepeatsValidator().get_help_text(),
            "Your password can't contain a character repeated more than 2 times in a row."
        )
