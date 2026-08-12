# EXPEDIENTES DPCJM

Sistema web para la gestión de expedientes del **Departamento de Protección Civil de Jesús María, Aguascalientes**.

Desarrollado para reemplazar el registro manual en papel, centraliza la información de inspecciones y permite consulta desde cualquier equipo en red local.
---

## Características

- **Gestión de expedientes** — alta, edición y eliminación de expedientes con número de control normalizado (`0001/0126/DPCJM`)
- **Seguimiento de documentos** — registro de fechas de citatorio, inspección, acta, resolutivo, avisos, clausura, VO BO y PIPC
- **Días restantes** — cálculo automático con semáforo visual (vencido / rojo / amarillo / verde / cumplido)
- **Checklist de contenido** — lista de documentos presentados por expediente
- **Filtros y búsqueda** — por texto, año, y estado de días restantes
- **Paginación** — 50 registros por página
- **Selección múltiple** — persistente entre páginas para exportación masiva
- **Exportación a CSV** — con todos los campos y días restantes calculados
- **Generación de PDF** — con hoja membretada oficial, tabla de datos y checklist
- **Descarga ZIP** — múltiples PDFs en un solo archivo
- **Control de acceso** — roles LECTURA, CAPTURA y ADMINISTRADOR
- **Bitácora de auditoría** — registro de todos los cambios con usuario y fecha
- **Sesión con expiración** — cierre automático a los 30 minutos de inactividad
- **Modo oscuro/claro** — persistente por dispositivo
- **Acceso en red local** — disponible en `http://proteccioncivil.local:5000` para todos los equipos de la oficina

---

## Tecnologías

| Componente | Tecnología |
|---|---|
| Backend | Python 3.11+ / Flask 3.0 |
| Base de datos | SQLite |
| PDF | ReportLab + pypdf |
| Frontend | HTML / CSS / JS vanilla |
| Autenticación | Werkzeug password hashing |

---

## Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/mdaviddlce/expedientes-dpcjm.git
cd expedientes-dpcjm
```

### 2. Crear entorno virtual e instalar dependencias

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### 3. Colocar la hoja membretada

Copia el archivo `hoja_membretada.pdf` oficial a la carpeta `static/`:

```
static/hoja_membretada.pdf
```

> Si no existe, el PDF se genera sin membrete como respaldo automático.

### 4. Correr la aplicación

```bash
export APP_ENV=prod && .venv/bin/python app.py
```

La aplicación queda disponible en:
- **Mismo equipo:** `http://localhost:5000`
- **Red local:** `http://proteccioncivil.local:5000`

---

## Variables de entorno

| Variable | Valores | Descripción |
|---|---|---|
| `APP_ENV` | `prod` / `dev` | Entorno de ejecución. Dev usa puerto 5001 y BD separada |
| `EXPEDIENTES_DATA_DIR` | ruta | Carpeta donde se guarda la base de datos (por defecto `/Users/Shared/EXPEDIENTES_DPCJM/data`) |
| `FLASK_SECRET_KEY` | texto | Clave secreta para sesiones (cambiar en producción) |

---

## Roles de usuario

| Rol | Permisos |
|---|---|
| `LECTURA` | Ver expedientes, descargar PDF y CSV |
| `CAPTURA` | Todo lo anterior + crear, editar y registrar documentos |
| `ADMINISTRADOR` | Todo lo anterior + gestión de usuarios y bitácora |

> El usuario `admin` se crea automáticamente en el primer arranque con contraseña `Admin-2026!`. **Cambiarla inmediatamente.**

---

## Estructura del proyecto

```
expedientes_dpcjm/
├── app.py                  # Aplicación principal (Flask)
├── requirements.txt        # Dependencias Python
├── static/
│   ├── app.css             # Estilos
│   ├── app.js              # JavaScript
│   └── hoja_membretada.pdf # Membrete oficial (no incluido en el repo)
└── templates/
    ├── layout.html
    ├── login.html
    ├── index.html
    ├── expediente_form.html
    ├── expediente_view.html
    ├── users_list.html
    ├── user_form.html
    └── audit_log.html
```

---

## Base de datos

La base de datos SQLite se crea y migra automáticamente al iniciar. Se almacena en:

- **Producción:** `/Users/Shared/EXPEDIENTES_DPCJM/data/expedientes_prod.db`
- **Desarrollo:** `/Users/Shared/EXPEDIENTES_DPCJM/data/expedientes_dev.db`

---

## Licencia

Uso interno — Departamento de Protección Civil de Jesús María, Aguascalientes.

