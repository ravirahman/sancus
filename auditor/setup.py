from distutils.core import setup

from setuptools import find_packages

setup(name='sancus_auditor',
      version='1.0',
      include_package_data=True,
      package_data={
            'auditor': ['py.typed', 'audit_publisher_abi.json'],
            'auditor.utils.blockchain_client': ['erc20abi.json'],
      },
      install_requires=[
            'SQLAlchemy',
            'grpcio',
            'grpcio-health-checking',
            'protobuf',
            'webauthn',
            'python-dotenv',
            'pyjwt',
            'eth_keys',
            'petlib @ git+https://github.com/gdanezis/petlib@master#egg=petlib',
            'eth_account',
            'web3',
            'pymysql',
            'requests',
            'python-bitcoinlib',
            'sqlalchemy-stubs',
            'sqlalchemy-utils',
            'pytz',
            'py-cid',
            # TODO sancus common
            # TODO sancus protobufs
      ],
      packages=find_packages('.', include=('auditgen*')),
)
