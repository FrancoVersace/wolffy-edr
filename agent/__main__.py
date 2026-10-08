import sys

from common.config import ConfigError, load_agent_config
from common.logs import setup_logging


def main():
    setup_logging("agent.log")
    try:
        cfg = load_agent_config()
    except ConfigError as exc:
        print(f"error de configuracion: {exc}", file=sys.stderr)
        return 2
    from .agent import Agent
    Agent(cfg).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
