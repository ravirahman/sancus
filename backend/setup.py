from distutils.core import setup

from setuptools import find_packages

setup(name='sancus_backend',
      version='1.0',
      include_package_data=True,
      package_data={
            'backend': ['py.typed'],
            'auditgen': ['py.typed', 'audit_publisher_abi.json'],
            'backend.utils.blockchain_client': ['erc20abi.json'],
      },
      install_requires=[
            'SQLAlchemy',
            'sqlalchemy-utils',
            'grpcio',
            'grpcio-health-checking',
            'protobuf',
            'webauthn',
            'pyjwt',
            'eth_rlp',
            'eth_account',
            'eth_keys',
            'petlib @ git+https://github.com/gdanezis/petlib@master#egg=petlib',
            'eth_account',
            'hexbytes',
            'web3',
            'pymysql',
            'requests',
            'python-bitcoinlib',
            'sqlalchemy-utils',
            'pytz',
            'py-cid',
            # TODO sancus common
            # TODO sancus protobufs
      ],
      packages=find_packages('.', include=('backend*', 'auditgen*')),
)
