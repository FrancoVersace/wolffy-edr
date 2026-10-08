import sys

from common.config import ConfigError, load_server_config
from common.logs import setup_logging


def main():
    setup_logging("server.log")
    try:
        cfg = load_server_config()
    except ConfigError as exc:
        print(f"error de configuracion: {exc}", file=sys.stderr)
        return 2
    import logging

    import uvicorn

    from .api import create_app

    app = create_app(cfg)
    host, port = cfg["server"]["host"], int(cfg["server"]["port"])
    log = logging.getLogger("wolffy.server")
    log.info("servidor en http://%s:%s", host, port)
    if app.state.dashboard_token:
        log.info("el dashboard requiere token (ver 'python wolffy.py token')")
    uvicorn.run(app, host=host, port=port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
