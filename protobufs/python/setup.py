from distutils.core import setup

from setuptools import find_packages

setup(name='protobufs',
      version='1.0',
      include_package_data=True,
      package_data={
            'protobufs': ['*.pyi', 'py.typed'],
            'protobufs.institution': ['*.pyi'],
            'protobufs.validator': ['*.pyi'],
      },
      install_requires=[
            'grpcio',
            'protobuf'
      ],
      packages=find_packages('.', include=('protobufs*')),
)
