import logging

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy_utils import create_database, database_exists

from common.config import SQLAlchemyConfig

LOGGER = logging.getLogger(__name__)


def make_sqlalchemy_engine(config: SQLAlchemyConfig) -> Engine:
    if not database_exists(config.uri):
        LOGGER.info("Creating database %s", config.uri)
        create_database(config.uri)
    # 10 extra pool workers for the background threads and one-off requests
    if config.uri.startswith("sqlite://"):
        engine = create_engine(config.uri, echo=config.echo)
    else:
        engine = create_engine(
            config.uri,
            echo=config.echo,
            pool_size=config.pool_size,
            max_overflow=config.max_overflow,
        )
    return engine
