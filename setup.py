from setuptools import setup

setup(name='deep_security',
      version='0.001b',
      description='Deep Security Python Interface',
      url='https://github.com/jeffthorne/deep_security',
      author='Jeff Thorne',
      author_email='jthorne@u.washington.edu',
      license='MIT',
      packages=['deep_security', 'deep_security.models', 'deep_security.utilities'],
      install_requires=['suds-py3 >= 1.2.0.0', 'requests >= 2.9.1'],
      zip_safe=False)