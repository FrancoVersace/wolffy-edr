# Wolffy EDR

Sistema de deteccion y respuesta en endpoints: un agente que vigila procesos, archivos y red, un motor de reglas YAML y un servidor con API REST y dashboard web. Funciona en Linux, macOS y Windows con Python 3.9 o superior.

## Inicio rapido

```bash
python wolffy.py install     # crea .venv e instala dependencias
python wolffy.py start       # servidor + agente (Ctrl+C para detener)
```

Dashboard: http://127.0.0.1:8000

Para vigilar archivos del sistema (`/etc`, `/root`, otros usuarios) y ver todas las conexiones de red, ejecuta el agente con privilegios (`sudo python wolffy.py start` en Linux/macOS, terminal de administrador en Windows). Sin ellos funciona igual, pero con visibilidad parcial.

## Comandos

| Comando | Funcion |
|---|---|
| `install` | Crea `.venv`, instala dependencias y genera la clave compartida |
| `start [--background] [--no-agent]` | Inicia servidor y agente |
| `stop` | Detiene lo iniciado con `--background` |
| `status` | Estado de componentes, API y reglas |
| `server` / `agent` | Ejecuta un solo componente |
| `token [--secret]` | Muestra el token del dashboard y la clave de agentes |
| `check-rules [--file ruta]` | Valida un archivo de reglas |
| `test` | Ejecuta las pruebas |
| `simulate` | Genera actividad inocua que dispara varias reglas |

## Varios equipos

1. En el servidor, en `config/server.yaml` pon `host: 0.0.0.0`. Al hacerlo se genera un token para el dashboard (`python wolffy.py token --secret`).
2. En cada equipo: `python wolffy.py install` y luego
   `python wolffy.py agent --server http://IP_SERVIDOR:8000 --secret CLAVE`.

Los agentes firman cada peticion con HMAC-SHA256 y marca de tiempo; el servidor rechaza firmas invalidas y peticiones repetidas fuera de una ventana de 5 minutos. Sin TLS el trafico viaja sin cifrar: en redes no confiables coloca un proxy inverso con HTTPS y usa `server.url: https://...` en el agente.

## Reglas

Las reglas estan en `config/rules.yaml` y se recargan en caliente cada pocos segundos.

```yaml
- id: WLF-1003
  name: Ejecucion desde directorio temporal
  severity: medium            # low | medium | high | critical
  event_type: process_start   # process_start | file_event | network_connect
  platforms: [linux]          # opcional
  mitre: T1059
  cooldown: 120               # segundos sin repetir la misma alerta
  match:                      # lista = todas deben cumplirse; tambien all / any / not
    - {field: target, op: startswith_any, value: [/tmp/, /dev/shm/]}
  exclude:                    # si esto coincide, no hay alerta
    - {field: parent_name, op: in, value: [dpkg, apt, pip]}
  dedupe_by: [target]
  message: "Ejecucion desde {target} (usuario {username})"
```

Operadores: `eq`, `ne`, `contains`, `startswith`, `endswith`, `in`, `not_in`, `contains_any`, `startswith_any`, `endswith_any`, `regex`, `gt`, `gte`, `lt`, `lte`, `exists`. Umbrales de frecuencia con `threshold: {count, window, group_by, distinct}`.

Campos principales: procesos (`name`, `cmdline`, `target`, `exe`, `username`, `parent_name`), archivos (`action`, `path`, `filename`, `extension`, `content_changed`), red (`remote_ip`, `remote_port`, `process_name`, `process_path`, `remote_is_private`).

Una regla con errores se omite y se registra; el resto sigue funcionando.

## Reducir falsos positivos

- Los eventos de archivos solo se emiten si el contenido realmente cambio (comparacion SHA-256), de modo que un `touch` o un guardado sin cambios no alerta.
- Se suprimen las alertas de persistencia y autenticacion durante instalaciones de paquetes.
- Las conexiones ya existentes al arrancar el agente no generan eventos.
- La deduplicacion y el `cooldown` evitan repeticiones.
- Lista de excepciones propia en `config/agent.yaml`:

```yaml
allowlist:
  rule_ids: [WLF-1004]
  process_names: [nmap]
  paths: [/opt/laboratorio/]
  command_patterns: ['mi-script-interno']
```

## API (`/api/v1`)

Los endpoints de agentes (`POST /agents/register`, `POST /events`) requieren firma. Los de lectura aceptan `Authorization: Bearer TOKEN` cuando hay token configurado. Documentacion interactiva en `/docs`.

| Metodo | Ruta | Descripcion |
|---|---|---|
| GET | `/health` | Estado del servicio |
| GET | `/stats` | Resumen de agentes, alertas y eventos |
| GET | `/agents`, `/agents/{id}`, `/agents/{id}/metrics` | Agentes y metricas |
| GET | `/alerts` | Filtros: `severity`, `agent_id`, `acknowledged`, `limit`, `offset` |
| GET | `/alerts/{id}` | Detalle |
| POST | `/alerts/{id}/ack`, `/alerts/ack-all` | Reconocer alertas |
| GET | `/events` | Filtros: `event_type`, `agent_id`, paginacion |
| GET | `/rules` | Reglas cargadas y errores |

## Datos y configuracion

Todo lo generado vive en `data/` (base de datos, logs, clave, identidad del agente). Variables de entorno: `WOLFFY_DATA_DIR`, `WOLFFY_CONFIG_DIR`, `WOLFFY_SECRET`, `WOLFFY_SERVER_URL`, `WOLFFY_HOST`, `WOLFFY_PORT`, `WOLFFY_DASHBOARD_TOKEN`. La retencion de eventos, metricas y alertas se configura en `config/server.yaml`.

## Limitaciones conocidas

- La deteccion de procesos usa sondeo (cada 0.5 s por defecto): un proceso que vive menos que ese intervalo puede pasar desapercibido. Es un EDR ligero, no un sustituto de auditoria a nivel de kernel (auditd, eBPF, ETW).
- Las reglas sobre linea de comandos coinciden con el texto: un comando que solo contenga una cadena maliciosa como texto (por ejemplo, un `grep` buscandola) puede alertar. Usa `allowlist.command_patterns` para esos casos.
- El sistema detecta y alerta; no bloquea ni aisla equipos.
- Las reglas de archivos de usuario se limitan a Descargas, Documentos, Escritorio e Imagenes; añade mas en `monitors.files.extra_paths`.
- En Linux, vigilar muchas rutas puede agotar `fs.inotify.max_user_watches`; el agente lo avisa en el log.
