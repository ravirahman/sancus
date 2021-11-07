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
            'zksk @ git+https://github.com/spring-epfl/zksk@master#egg=zksk',
            'petlib @ git+https://github.com/gdanezis/petlib@master#egg=petlib',
            'pytz',
            'protobuf',
            'hexbytes',
            'ipfshttpclient',
            'grpc_interceptor',
            'py-cid',
      ],
      packages=find_packages('.', include=('common*')),
)
