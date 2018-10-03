from setuptools import setup

setup(name='dsp3',
      version='0.1c36',
      description='Python 3 client for Trend Micro\'s Deep Security Platform',
      url='https://github.com/trend206/dsp3',
      author='Jeff Thorne',
      author_email='jthorne@u.washington.edu',
      license='MIT',
      packages=['dsp3', 'dsp3.models', 'dsp3.utilities'],
      install_requires=['suds-py3 >= 1.2.0.0', 'requests >= 2.9.1'],
      zip_safe=False)