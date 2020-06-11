import os
from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.md')).read()

setup(
    name='formsg',
    version='0.1.2',
    packages=['formsg'],
    description='A Python SDK for handling FormSG webhooks.',
    long_description=README,
    long_description_content_type='text/markdown',
    author='5 Health Inc',
    author_email='hello@botmd.io',
    url='https://github.com/fivehealth/formsg-python-sdk',
    license='MIT License',
    install_requires=[
        'pynacl>=1.4.0',
    ],
    python_requires='>=3',
    keywords='django cache',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Programming Language :: Python :: 3',
        'Framework :: Django',
        'Framework :: Flask',
        'License :: OSI Approved :: MIT License',
    ],
)
