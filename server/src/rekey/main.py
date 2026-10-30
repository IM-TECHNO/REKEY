import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from rekey import alerts, anchor, audit, autounseal, devunseal, dynamic, rotation, service
from rekey.api import router
from rekey.auth_api import router as auth_router
from rekey.changes import router as changes_router
from rekey.config import Settings
from rekey.crypto.errors import DecryptionError, SealedError
from rekey.db import make_engine, make_sessionmaker
from rekey.insights import router as insights_router
from rekey.oidc import Provider
from rekey.ratelimit import RateLimiter
from rekey.rotation import RoutingConnector
from rekey.rotation import router as rotation_router


def create_app(
    settings: Settings | None = None, http_client: httpx.AsyncClient | None = None
) -> FastAPI:
    settings = settings or Settings()
    owns_client = http_client is None
    http = http_client or httpx.AsyncClient(timeout=10.0, follow_redirects=False)

    @asynccontextmanager
    async def lifespan(app_: FastAPI) -> AsyncIterator[None]:
        devunseal.check_allowed(settings)
        if settings.dev_unseal_file:
            await devunseal.try_unseal(app_)
        autounseal.check_config(settings)
        unseal_task: asyncio.Task[None] | None = None
        if settings.auto_unseal != "off":
            await autounseal.try_unseal(app_)
            unseal_task = asyncio.create_task(autounseal.run_forever(app_))
        task: asyncio.Task[None] | None = None
        rot_task = asyncio.create_task(rotation.run_forever(app_))
        dyn_task = asyncio.create_task(dynamic.run_forever(app_))
        alert_task = asyncio.create_task(alerts.run_forever(app_))
        if anchor.enabled(settings):
            if settings.audit_anchor_webhook:
                anchor.check_webhook_url(settings.audit_anchor_webhook)
            task = asyncio.create_task(anchor.run_forever(settings, app_.state.sessionmaker, http))
        yield
        rot_task.cancel()
        dyn_task.cancel()
        alert_task.cancel()
        audit.unlisten(app_.state.sessionmaker)
        await asyncio.gather(rot_task, dyn_task, alert_task, return_exceptions=True)
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        if unseal_task is not None:
            unseal_task.cancel()
            await asyncio.gather(unseal_task, return_exceptions=True)
        if owns_client:
            await http.aclose()

    app = FastAPI(title="Rekey", version="0.0.1", lifespan=lifespan)
    app.state.settings = settings
    app.state.engine = make_engine(settings.database_url)
    app.state.sessionmaker = make_sessionmaker(app.state.engine)
    app.state.keyring = None
    app.state.autounseal_paused = False  # set by an explicit seal: stays until the next restart
    app.state.oidc = Provider(settings, http)
    app.state.limiter = RateLimiter()
    app.state.rotation_connector = RoutingConnector()
    app.state.http = http
    app.state.rotation_locks = {}
    app.state.dynamic_connector = dynamic.RoutingDynamic()
    app.state.alerts = alerts.Notifier(settings, app.state.sessionmaker)
    audit.listen(app.state.sessionmaker, app.state.alerts.on_audit)
    app.include_router(router)
    app.include_router(auth_router)
    app.include_router(insights_router)
    app.include_router(changes_router)
    app.include_router(rotation_router)
    app.include_router(dynamic.router)
    app.include_router(dynamic.renewals_router)
    app.include_router(alerts.router)

    @app.middleware("http")
    async def no_store(request: Request, call_next):  # type: ignore[no-untyped-def]
        # Secrets, shares and tokens travel in these responses: no browser or proxy may keep one.
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.exception_handler(service.NotFound)
    async def _not_found(_: Request, exc: service.NotFound) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=404)

    @app.exception_handler(service.Conflict)
    async def _conflict(_: Request, exc: service.Conflict) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.exception_handler(SealedError)
    async def _sealed(_: Request, __: SealedError) -> JSONResponse:
        return JSONResponse({"detail": "sealed"}, status_code=503)

    @app.exception_handler(DecryptionError)
    async def _decrypt(_: Request, __: DecryptionError) -> JSONResponse:
        # Never leak why decryption failed.
        return JSONResponse({"detail": "internal error"}, status_code=500)

    return app
