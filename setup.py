from setuptools import setup
from os import path
import re


def packagefile(*relpath):
    return path.join(path.dirname(__file__), *relpath)


def read(*relpath):
    with open(packagefile(*relpath)) as f:
        return f.read()


def get_version(*relpath):
    match = re.search(
        r'''^__version__ = ['"]([^'"]*)['"]''',
        read(*relpath),
        re.M
    )
    if not match:
        raise RuntimeError('Unable to find version string.')
    return match.group(1)


setup(
    name='django-password-validation-backport',
    version=get_version('django_password_validation', '__init__.py'),
    description='Ported password validation code from Django 1.9.',
    long_description=read('README.rst'),
    url='https://github.com/luismsgomes/django-password-validation-backport',
    author='Luis Gomes',
    author_email='luismsgomes@gmail.com',
    license='MIT',
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='backport',
    install_requires=[
    ],
    package_dir={'': '.'},
    packages=['django_password_validation'],
    package_data={
        'django_password_validation': ['*.gz'],
    },
    include_package_data=True,
)
