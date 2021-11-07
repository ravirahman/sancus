from distutils.core import setup

from setuptools import find_packages

setup(name='common',
      version='1.0',
      include_package_data=True,
      package_data={
            'common': ['py.typed'],
      },
      install_requires=[
            'sqlalchemy',
            'zksk @ git+https://github.com/ravirahman/zksk@0ae25d26a1d9bc48ee0eb2d7d1e544b901775d0c#egg=zksk',
            'petlib @ git+https://github.com/ravirahman/petlib@3b28c97955655671fbc167e007ab6f7ea438801b#egg=petlib',
            'pytz',
            'protobuf',
            'hexbytes',
            'ipfshttpclient',
            'grpc_interceptor',
            'py-cid',
      ],
      packages=find_packages('.', include=('common*')),
)
