#!/usr/bin/env python3
"""Lanzador de Wolffy EDR: instalacion, arranque, parada, diagnostico y pruebas."""
import argparse
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
MIN_PYTHON = (3, 9)
sys.path.insert(0, str(ROOT))

from common.paths import DATA_DIR, LOG_DIR, RUN_DIR, ensure_dirs  # noqa: E402


def venv_python():
    return VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def inside_venv():
    return Path(sys.prefix).resolve() == VENV.resolve()


def dependencies_available():
    try:
        import fastapi, psutil, requests, sqlalchemy, uvicorn, watchdog, yaml  # noqa: F401
        return True
    except ImportError:
        return False


def require_environment():
    """Reejecuta el comando dentro del entorno virtual si existe."""
    if inside_venv() or dependencies_available():
        return
    python = venv_python()
    if python.exists():
        sys.exit(subprocess.call([str(python), str(Path(__file__).resolve())] + sys.argv[1:]))
    print("Faltan dependencias. Ejecuta primero: python wolffy.py install", file=sys.stderr)
    sys.exit(1)


def cmd_install(_args):
    if sys.version_info < MIN_PYTHON:
        sys.exit("Se requiere Python %d.%d o superior" % MIN_PYTHON)
    if not venv_python().exists():
        print("[1/3] Creando entorno virtual en .venv")
        import venv
        try:
            venv.EnvBuilder(with_pip=True).create(str(VENV))
        except Exception as exc:
            sys.exit(
                "No se pudo crear el entorno virtual (%s).\n"
                "En Debian/Ubuntu/Kali instala: sudo apt install python3-venv python3-pip" % exc
            )
    else:
        print("[1/3] Entorno virtual existente")
    print("[2/3] Instalando dependencias")
    code = subprocess.call([str(venv_python()), "-m", "pip", "install", "-q", "-r", str(ROOT / "requirements.txt")])
    if code != 0:
        sys.exit("Fallo la instalacion de dependencias")
    print("[3/3] Inicializando datos y clave compartida")
    from common.security import resolve_secret
    ensure_dirs()
    resolve_secret()
    print("\nListo. Arranca el sistema con:  python wolffy.py start")
    print("Dashboard:                       http://127.0.0.1:8000")


def server_url():
    from common.config import load_server_config
    cfg = load_server_config()["server"]
    host = "127.0.0.1" if cfg["host"] in ("0.0.0.0", "::") else cfg["host"]
    return "http://%s:%s" % (host, cfg["port"])


def server_healthy(url, timeout=1.5):
    try:
        with urllib.request.urlopen(url + "/health", timeout=timeout) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


def spawn(module, detached):
    ensure_dirs()
    kwargs = {"cwd": str(ROOT)}
    if detached:
        out = open(LOG_DIR / (module + ".out"), "ab")
        kwargs.update(stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        if os.name == "nt":
            kwargs["creationflags"] = 0x00000008 | 0x00000200
        else:
            kwargs["start_new_session"] = True
    process = subprocess.Popen([sys.executable, "-m", module], **kwargs)
    (RUN_DIR / (module + ".pid")).write_text(str(process.pid))
    return process


def read_pid(name):
    try:
        return int((RUN_DIR / (name + ".pid")).read_text().strip())
    except (OSError, ValueError):
        return None


def component_running(name):
    import psutil
    pid = read_pid(name)
    if not pid or not psutil.pid_exists(pid):
        return None
    try:
        process = psutil.Process(pid)
        if name in " ".join(process.cmdline()):
            return process
    except psutil.Error:
        pass
    return None


def cmd_start(args):
    require_environment()
    ensure_dirs()
    url = server_url()
    children = []
    if server_healthy(url):
        print("Servidor ya activo en %s" % url)
    else:
        children.append(("server", spawn("server", args.background)))
        for _ in range(40):
            if server_healthy(url):
                break
            if children[0][1].poll() is not None:
                sys.exit("El servidor termino inesperadamente; revisa data/logs/server.log")
            time.sleep(0.5)
        else:
            sys.exit("El servidor no respondio a tiempo; revisa data/logs/server.log")
        print("Servidor activo en %s" % url)
    if not args.no_agent:
        if component_running("agent"):
            print("El agente ya esta en ejecucion")
        else:
            children.append(("agent", spawn("agent", args.background)))
            print("Agente iniciado")
    if args.background:
        print("Ejecutando en segundo plano. Detener con: python wolffy.py stop")
        return
    print("Presiona Ctrl+C para detener")
    try:
        while True:
            for name, process in children:
                if process.poll() is not None:
                    print("%s termino con codigo %s" % (name, process.returncode))
                    raise KeyboardInterrupt
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for _, process in children:
            if process.poll() is None:
                process.terminate()
        for name, process in children:
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
            pidfile = RUN_DIR / (name + ".pid")
            if pidfile.exists():
                pidfile.unlink()


def cmd_stop(_args):
    require_environment()
    import psutil
    stopped = False
    for name in ("agent", "server"):
        process = component_running(name)
        if process is None:
            continue
        process.terminate()
        try:
            process.wait(8)
        except psutil.TimeoutExpired:
            process.kill()
        print("%s detenido (PID %s)" % (name, process.pid))
        stopped = True
        pidfile = RUN_DIR / (name + ".pid")
        if pidfile.exists():
            pidfile.unlink()
    if not stopped:
        print("No hay componentes en segundo plano. Si los lanzaste con 'start', usa Ctrl+C en su terminal.")


def cmd_status(_args):
    require_environment()
    url = server_url()
    print("Python:      %s" % sys.version.split()[0])
    print("Entorno:     %s" % ("OK (.venv)" if venv_python().exists() else "no instalado (python wolffy.py install)"))
    print("Datos:       %s" % DATA_DIR)
    for name in ("server", "agent"):
        process = component_running(name)
        print("%-12s %s" % (name.capitalize() + ":", "activo (PID %s)" % process.pid if process else "no gestionado por wolffy.py"))
    print("API:         %s" % ("responde en " + url if server_healthy(url) else "no responde en " + url))
    from agent.rules_engine import load_rules
    from common.config import load_agent_config, resolve_path
    rules, errors = load_rules(resolve_path(load_agent_config()["agent"]["rules_file"]))
    print("Reglas:      %d cargadas, %d con errores" % (len(rules), len(errors)))


def cmd_token(args):
    from common.config import load_server_config
    from common.security import resolve_dashboard_token, resolve_secret
    cfg = load_server_config()["server"]
    token = resolve_dashboard_token(cfg["dashboard_token"], cfg["host"])
    print("Token del dashboard: %s" % (token or "no requerido (el servidor solo escucha en localhost)"))
    if args.secret:
        print("Clave compartida de agentes: %s" % resolve_secret(cfg["secret_key"]))
        print("Usala en otros equipos con: python wolffy.py agent --server http://IP:PUERTO --secret CLAVE")


def cmd_check_rules(args):
    sys.path.insert(0, str(ROOT))
    from agent.rules_engine import load_rules
    from common.config import load_agent_config, resolve_path
    path = Path(args.file) if args.file else resolve_path(load_agent_config()["agent"]["rules_file"])
    rules, errors = load_rules(path)
    print("%s: %d reglas validas" % (path, len(rules)))
    for message in errors:
        print("  ERROR %s" % message)
    sys.exit(1 if errors else 0)


def cmd_agent(args):
    require_environment()
    if args.server:
        os.environ["WOLFFY_SERVER_URL"] = args.server
    if args.secret:
        os.environ["WOLFFY_SECRET"] = args.secret
    sys.exit(subprocess.call([sys.executable, "-m", "agent"], cwd=str(ROOT)))


def cmd_server(_args):
    require_environment()
    sys.exit(subprocess.call([sys.executable, "-m", "server"], cwd=str(ROOT)))


def cmd_test(_args):
    require_environment()
    sys.exit(subprocess.call([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"], cwd=str(ROOT)))


def cmd_simulate(args):
    require_environment()
    sys.exit(subprocess.call([sys.executable, str(ROOT / "scripts" / "simulate_attack.py")] + args.rest, cwd=str(ROOT)))


def build_parser():
    parser = argparse.ArgumentParser(prog="wolffy.py", description="Wolffy EDR")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("install", help="crea .venv e instala dependencias").set_defaults(func=cmd_install)
    start = sub.add_parser("start", help="inicia servidor y agente")
    start.add_argument("--background", action="store_true", help="ejecutar en segundo plano")
    start.add_argument("--no-agent", action="store_true", help="iniciar solo el servidor")
    start.set_defaults(func=cmd_start)
    sub.add_parser("stop", help="detiene los componentes en segundo plano").set_defaults(func=cmd_stop)
    sub.add_parser("status", help="muestra el estado").set_defaults(func=cmd_status)
    sub.add_parser("server", help="ejecuta solo el servidor en primer plano").set_defaults(func=cmd_server)
    agent = sub.add_parser("agent", help="ejecuta solo el agente en primer plano")
    agent.add_argument("--server", help="URL del servidor, ej. http://10.0.0.5:8000")
    agent.add_argument("--secret", help="clave compartida con el servidor")
    agent.set_defaults(func=cmd_agent)
    token = sub.add_parser("token", help="muestra el token del dashboard")
    token.add_argument("--secret", action="store_true", help="mostrar tambien la clave compartida de agentes")
    token.set_defaults(func=cmd_token)
    check = sub.add_parser("check-rules", help="valida el archivo de reglas")
    check.add_argument("--file", help="ruta alternativa de reglas")
    check.set_defaults(func=cmd_check_rules)
    sub.add_parser("test", help="ejecuta la suite de pruebas").set_defaults(func=cmd_test)
    simulate = sub.add_parser("simulate", help="ejecuta la simulacion de ataque (inocua)")
    simulate.add_argument("rest", nargs=argparse.REMAINDER)
    simulate.set_defaults(func=cmd_simulate)
    return parser


if __name__ == "__main__":
    try:
        arguments = build_parser().parse_args()
        arguments.func(arguments)
    except KeyboardInterrupt:
        pass
