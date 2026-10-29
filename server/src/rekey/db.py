from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool


def make_engine(url: str) -> AsyncEngine:
    if url.startswith("sqlite") and ":memory:" in url:
        # One shared connection so the in-memory database survives across sessions (tests).
        return create_async_engine(
            url, poolclass=StaticPool, connect_args={"check_same_thread": False}
        )
    return create_async_engine(url, pool_pre_ping=True)


def make_sessionmaker(engine: AsyncEngine) -> async_sessionmaker:  # type: ignore[type-arg]
    return async_sessionmaker(engine, expire_on_commit=False)
