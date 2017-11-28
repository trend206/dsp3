from setuptools import setup

setup(name='dsp3',
      version='0.1c22',
      description='Deep Security Python SDK',
      url='https://github.com/jeffthorne/dsp3',
      author='Jeff Thorne',
      author_email='jthorne@u.washington.edu',
      license='MIT',
      packages=['dsp3', 'dsp3.models', 'dsp3.utilities'],
      install_requires=['suds-py3 >= 1.2.0.0', 'requests >= 2.9.1'],
      zip_safe=False)