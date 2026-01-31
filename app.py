from __future__ import annotations

import os
import re
import sqlite3
import zipfile
from datetime import datetime, timezone
from functools import wraps
from io import BytesIO
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas
from werkzeug.security import check_password_hash, generate_password_hash

# =========================================================
# CONFIG
# =========================================================
APP_DIR = Path(__file__).resolve().parent

# Sufijo fijo del expediente
SUFIJO = "DPCJM"

def normalize_expediente_code(raw: str) -> str:
    """
    Normaliza a formato canonico:
      NNNN/MMYY/DPCJM
    Acepta:
      "35/0126", "0035/0126/DPCJM", "35-0126-dpcjm", "35 / 0126"
    """
    s = (raw or "").strip().upper()
    s = s.replace("-", "/").replace(" ", "")

    parts = s.split("/")
    if len(parts) < 2:
        raise ValueError("FORMATO INVALIDO. USA: 0001/0126/DPCJM")

    num_str = parts[0]
    mmyy = parts[1]

    if not num_str.isdigit():
        raise ValueError("EL NUMERO DE EXPEDIENTE DEBE SER NUMERICO.")

    num = int(num_str)
    if num < 0 or num > 9999:
        raise ValueError("NUMERO DE EXPEDIENTE FUERA DE RANGO (0-9999).")

    if not re.fullmatch(r"\d{4}", mmyy):
        raise ValueError("LA PARTE MMAA DEBE SER 4 DIGITOS (EJ. 0126).")

    return f"{num:04d}/{mmyy}/{SUFIJO}"


# --- ENV: DEV/PROD + DATA DIR ---
DATA_DIR = Path(os.environ.get("EXPEDIENTES_DATA_DIR", "/Users/Shared/EXPEDIENTES_DPCJM/data"))
APP_ENV = os.environ.get("APP_ENV", "prod").lower()  # "prod" o "dev"
DB_PATH = DATA_DIR / ("expedientes_dev.db" if APP_ENV == "dev" else "expedientes_prod.db")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

ROLES = ["LECTURA", "CAPTURA", "ADMINISTRADOR"]
WHO_OPTIONS = ["Propietario", "Apoderado", "Operador"]
ARCHIVO_FISICO_OPTIONS = ["Archivo 1", "Archivo 2", "Archivo 3", "Archivo 4"]

CHECKLIST_DEFAULT = [
    "SOLICITUD",
    "INE DEL PROPIETARIO Y/O REP. LEGAL",
    "CARTA PODER COMPLETA",
    "INE DE LOS TESTIGOS",
    "ACTA CONSTITUTIVA (PERSONA MORAL)",
    "PODER DEL REPRESENTANTE LEGAL",
    "CONSTANCIA DE COMPATIBILIDAD URBANISTA",
    "CONSTANCIA DE SITUACION FISCAL",
    "PAGO REALIZADO VO. BO.",
    "PAGO REALIZADO DE PROGRAMA O PLAN",
    "TRANSPARENCIA",
]

PRIVACY_NOTICE = (
    "Nombre de la Dependencia: Protección Civil. Es responsable de recabar sus datos personales, del uso "
    "que se le dé a los mismos y de su protección. Los datos personales que se solicitan, serán utilizados "
    "para proveer los servicios que haya solicitado, pero ello, se requiere obtener los siguientes datos "
    "personales: nombre, dirección, teléfono, credencial de elector, comprobante de domicilio, curp, firma y "
    "otros, es mismo dominio que en cualquier momento usted tendrá acceso, rectificación, cancelación y oposición "
    "al tratamiento de los mismos, utilizando los medios que para tal efecto se han implementado en esta Dependencia "
    "y/o unidad administrativa. Si usted, no manifiesta en su oposición para el uso y/o tratamiento de su información "
    "personal, se entenderá que ha otorgado consentimiento para ello."
)

# =========================================================
# UTILS
# =========================================================
def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        g.db = conn
    return g.db


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login_get"))
        return fn(*args, **kwargs)
    return wrapper


def role_required(allowed_roles: list[str]):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if session.get("role") not in allowed_roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return deco


def current_user_id() -> int | None:
    return session.get("user_id")


def current_role() -> str:
    return session.get("role", "")


def audit(
    db: sqlite3.Connection,
    user_id: int | None,
    action: str,
    entity: str,
    entity_id: int | None,
    field: str | None,
    old_value: str | None,
    new_value: str | None,
) -> None:
    db.execute(
        """
        INSERT INTO audit_log (ts, user_id, action, entity, entity_id, field, old_value, new_value)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (utc_now(), user_id, action, entity, entity_id, field, old_value, new_value),
    )


def has_column(cur: sqlite3.Cursor, table: str, col: str) -> bool:
    cur.execute(f"PRAGMA table_info({table})")
    return any(r[1] == col for r in cur.fetchall())


def add_column(cur: sqlite3.Cursor, table: str, col_def: str) -> None:
    col_name = col_def.split()[0]
    if not has_column(cur, table, col_name):
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")


def init_db(app: Flask) -> None:
    with app.app_context():
        db = get_db()
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS expedientes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                expediente_code TEXT NOT NULL,
                inmueble_nombre TEXT NOT NULL,
                representante_legal TEXT,
                apoderados TEXT,
                domicilio_inspeccion TEXT,
                telefono TEXT,
                quien_solicita TEXT NOT NULL,
                archivo_fisico TEXT,
                verificaciones INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                created_by INTEGER,
                updated_at TEXT NOT NULL,
                updated_by INTEGER,
                FOREIGN KEY(created_by) REFERENCES users(id),
                FOREIGN KEY(updated_by) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS checklist_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL UNIQUE,
                sort_order INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS expediente_checklist (
                expediente_id INTEGER NOT NULL,
                item_id INTEGER NOT NULL,
                status TEXT CHECK(status IN ('presenta','no_presenta') OR status IS NULL),
                PRIMARY KEY (expediente_id, item_id),
                FOREIGN KEY (expediente_id) REFERENCES expedientes(id) ON DELETE CASCADE,
                FOREIGN KEY (item_id) REFERENCES checklist_items(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                user_id INTEGER,
                action TEXT NOT NULL,
                entity TEXT NOT NULL,
                entity_id INTEGER,
                field TEXT,
                old_value TEXT,
                new_value TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            """
        )

        # Seed checklist catalog if empty
        existing = db.execute("SELECT COUNT(*) AS c FROM checklist_items").fetchone()["c"]
        if existing == 0:
            for i, label in enumerate(CHECKLIST_DEFAULT, start=1):
                db.execute("INSERT INTO checklist_items (label, sort_order) VALUES (?, ?)", (label, i))
            db.commit()

        # --- MIGRATIONS (safe) ---
        cur = db.cursor()
        add_column(cur, "expedientes", "verificaciones INTEGER NOT NULL DEFAULT 0")
        add_column(cur, "expedientes", "archivo_fisico TEXT")
        add_column(cur, "expedientes", "created_by INTEGER")
        add_column(cur, "expedientes", "updated_by INTEGER")
        add_column(cur, "expedientes", "updated_at TEXT")
        add_column(cur, "expedientes", "created_at TEXT")
        add_column(cur, "expedientes", "apoderados TEXT")

        # Rellena timestamps si vienen nulos
        now = utc_now()
        cur.execute("UPDATE expedientes SET created_at = COALESCE(created_at, ?)", (now,))
        cur.execute("UPDATE expedientes SET updated_at = COALESCE(updated_at, created_at, ?)", (now,))
        db.commit()


def ensure_default_admin() -> None:
    db = get_db()
    exists = db.execute("SELECT 1 FROM users WHERE username='admin'").fetchone()
    if exists:
        return
    db.execute(
        "INSERT INTO users (username, password_hash, role, is_active, created_at) VALUES (?, ?, ?, 1, ?)",
        ("admin", generate_password_hash("Admin-2026!"), "ADMINISTRADOR", utc_now()),
    )
    db.commit()


def load_checklist_items():
    db = get_db()
    return db.execute("SELECT id, label FROM checklist_items ORDER BY sort_order ASC").fetchall()


def load_checklist_state(expediente_id: int) -> dict[int, str | None]:
    db = get_db()
    rows = db.execute(
        "SELECT item_id, status FROM expediente_checklist WHERE expediente_id = ?",
        (expediente_id,),
    ).fetchall()
    return {r["item_id"]: r["status"] for r in rows}


def compare_and_audit(db: sqlite3.Connection, user_id: int | None, expediente_id: int, old_row, new_map: dict):
    for k, new_v in new_map.items():
        old_v = old_row[k] if k in old_row.keys() else None
        if (old_v or "") != (new_v or ""):
            audit(db, user_id, "UPDATE", "expedientes", expediente_id, k, str(old_v or ""), str(new_v or ""))


def draw_wrapped_text(c, text, x, y, max_width, line_height=12, font="Helvetica", font_size=9):
    c.setFont(font, font_size)
    words = (text or "").split()
    line = ""
    while words:
        w = words.pop(0)
        test = (line + " " + w).strip()
        if c.stringWidth(test, font, font_size) <= max_width:
            line = test
        else:
            if line:
                c.drawString(x, y, line)
                y -= line_height
            line = w
    if line:
        c.drawString(x, y, line)
        y -= line_height
    return y


def build_expediente_pdf_bytes(expediente, checklist, checklist_state) -> bytes:
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=LETTER)
    width, height = LETTER

    x = 2 * cm
    y = height - 2 * cm

    year = (expediente["created_at"] or "")[:4] or "AAAA"

    c.setFont("Helvetica-Bold", 11)
    c.drawCentredString(width / 2, y, f"EXPEDIENTE {year} DEPARTAMENTO DE PROTECCION CIVIL")
    y -= 1.2 * cm

    c.setFont("Helvetica-Bold", 9)
    fields = [
        ("EXPEDIENTE", expediente["expediente_code"]),
        ("NOMBRE DEL INMUEBLE", expediente["inmueble_nombre"]),
        ("REPRESENTANTE LEGAL", expediente["representante_legal"] or ""),
        ("APODERADOS", expediente["apoderados"] or ""),
        ("DOMICILIO DE LA INSPECCION", expediente["domicilio_inspeccion"] or ""),
        ("TELEFONO", expediente["telefono"] or ""),
        ("QUIEN SOLICITA", expediente["quien_solicita"]),
        ("ARCHIVO FISICO", expediente["archivo_fisico"] or ""),
        ("VERIFICACIONES/AVISOS", str(int(expediente["verificaciones"] or 0))),
    ]

    for k, v in fields:
        c.drawString(x, y, f"{k}:")
        c.setFont("Helvetica", 9)
        c.drawString(x + 6.2 * cm, y, str(v))
        c.setFont("Helvetica-Bold", 9)
        y -= 0.55 * cm

    y -= 0.6 * cm

    c.setFont("Helvetica-Bold", 9)
    c.drawString(x, y, "CONTENIDO DEL EXPEDIENTE")
    c.drawString(width - 6.0 * cm, y, "PRESENTA")
    c.drawString(width - 3.2 * cm, y, "NO PRESENTA")
    y -= 0.45 * cm
    c.line(x, y, width - x, y)
    y -= 0.35 * cm

    c.setFont("Helvetica", 9)
    for item in checklist:
        st = checklist_state.get(item["id"])
        label = item["label"]

        if y < 5.0 * cm:
            c.showPage()
            y = height - 2 * cm

        c.drawString(x, y, label[:95])
        c.drawString(width - 5.2 * cm, y, "X" if st == "presenta" else "")
        c.drawString(width - 2.4 * cm, y, "X" if st == "no_presenta" else "")
        y -= 0.45 * cm

    y -= 0.5 * cm
    if y < 5.0 * cm:
        c.showPage()
        y = height - 2 * cm

    c.setFont("Helvetica-Bold", 9)
    c.drawString(x, y, "AVISO DE PRIVACIDAD")
    y -= 0.6 * cm
    y = draw_wrapped_text(c, PRIVACY_NOTICE, x, y, (width - 2 * x), line_height=11, font="Helvetica", font_size=9)

    y -= 0.6 * cm
    c.setFont("Helvetica", 9)
    c.drawString(x, y, "C. Beltran 315, Zona Centro, 20920 Jesús María, Ags. Tel: 449 963 9921")

    c.showPage()
    c.save()
    buf.seek(0)
    return buf.read()


# =========================================================
# APP
# =========================================================
def create_app() -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "CAMBIA-ESTO")

    init_db(app)
    with app.app_context():
        ensure_default_admin()

    @app.teardown_appcontext
    def close_db(exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    # -------------------------
    # AUTH
    # -------------------------
    @app.get("/login")
    def login_get():
        if session.get("user_id"):
            return redirect(url_for("index"))
        return render_template("login.html")

    @app.post("/login")
    def login_post():
        username = (request.form.get("username") or "").strip().lower()
        password = (request.form.get("password") or "").strip()

        db = get_db()
        user = db.execute(
            "SELECT id, username, password_hash, role, is_active FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if not user or user["is_active"] != 1 or not check_password_hash(user["password_hash"], password):
            flash("CREDENCIALES INVALIDAS.", "error")
            return redirect(url_for("login_get"))

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        flash("SESION INICIADA.", "ok")
        return redirect(url_for("index"))

    @app.post("/logout")
    @login_required
    def logout_post():
        session.clear()
        flash("SESION CERRADA.", "ok")
        return redirect(url_for("login_get"))

    # -------------------------
    # USUARIOS (ADMIN)
    # -------------------------
    @app.get("/users")
    @login_required
    @role_required(["ADMINISTRADOR"])
    def users_list():
        db = get_db()
        rows = db.execute(
            """
            SELECT id, username, role, is_active, created_at
            FROM users
            ORDER BY datetime(created_at) DESC
            """
        ).fetchall()
        return render_template("users_list.html", rows=rows)

    @app.get("/users/new")
    @login_required
    @role_required(["ADMINISTRADOR"])
    def user_new():
        return render_template("user_form.html", mode="new", roles=ROLES, user=None)

    @app.post("/users")
    @login_required
    @role_required(["ADMINISTRADOR"])
    def user_create():
        f = request.form
        username = (f.get("username") or "").strip().lower()
        password = (f.get("password") or "").strip()
        role = (f.get("role") or "").strip()
        is_active = 1 if (f.get("is_active") == "1") else 0

        if not username or not password or role not in ROLES:
            flash("VERIFICA: USUARIO, CONTRASEÑA Y ROL.", "error")
            return redirect(url_for("user_new"))

        db = get_db()
        exists = db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
        if exists:
            flash("ESE USUARIO YA EXISTE.", "error")
            return redirect(url_for("user_new"))

        now = utc_now()
        db.execute(
            """
            INSERT INTO users (username, password_hash, role, is_active, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, generate_password_hash(password), role, is_active, now),
        )
        new_id = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
        audit(db, current_user_id(), "CREATE", "users", new_id, None, None, None)
        db.commit()

        flash("USUARIO CREADO.", "ok")
        return redirect(url_for("users_list"))

    @app.get("/users/<int:user_id>/edit")
    @login_required
    @role_required(["ADMINISTRADOR"])
    def user_edit(user_id: int):
        db = get_db()
        user = db.execute(
            "SELECT id, username, role, is_active, created_at FROM users WHERE id=?",
            (user_id,),
        ).fetchone()
        if not user:
            abort(404)
        return render_template("user_form.html", mode="edit", roles=ROLES, user=user)

    @app.post("/users/<int:user_id>")
    @login_required
    @role_required(["ADMINISTRADOR"])
    def user_update(user_id: int):
        db = get_db()
        old = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not old:
            abort(404)

        f = request.form
        username = (f.get("username") or "").strip().lower()
        role = (f.get("role") or "").strip()
        is_active = 1 if (f.get("is_active") == "1") else 0
        new_password = (f.get("password") or "").strip()

        if not username or role not in ROLES:
            flash("VERIFICA: USUARIO Y ROL.", "error")
            return redirect(url_for("user_edit", user_id=user_id))

        dupe = db.execute("SELECT 1 FROM users WHERE username=? AND id<>?", (username, user_id)).fetchone()
        if dupe:
            flash("ESE USUARIO YA EXISTE.", "error")
            return redirect(url_for("user_edit", user_id=user_id))

        if user_id == current_user_id() and is_active == 0:
            flash("NO PUEDES DESACTIVAR TU PROPIO USUARIO.", "error")
            return redirect(url_for("user_edit", user_id=user_id))

        sets = ["username=?", "role=?", "is_active=?"]
        vals = [username, role, is_active]
        if new_password:
            sets.append("password_hash=?")
            vals.append(generate_password_hash(new_password))
        vals.append(user_id)

        db.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=?", vals)

        if (old["username"] or "") != username:
            audit(db, current_user_id(), "UPDATE", "users", user_id, "username", str(old["username"] or ""), username)
        if (old["role"] or "") != role:
            audit(db, current_user_id(), "UPDATE", "users", user_id, "role", str(old["role"] or ""), role)
        if int(old["is_active"] or 0) != int(is_active):
            audit(db, current_user_id(), "UPDATE", "users", user_id, "is_active", str(old["is_active"]), str(is_active))
        if new_password:
            audit(db, current_user_id(), "UPDATE", "users", user_id, "password_hash", "", "CHANGED")

        db.commit()
        flash("USUARIO ACTUALIZADO.", "ok")
        return redirect(url_for("users_list"))

    @app.post("/users/<int:user_id>/eliminar")
    @login_required
    @role_required(["ADMINISTRADOR"])
    def user_delete(user_id: int):
        db = get_db()
        u = db.execute("SELECT id, username FROM users WHERE id=?", (user_id,)).fetchone()
        if not u:
            abort(404)

        if user_id == current_user_id():
            flash("NO PUEDES ELIMINAR TU PROPIO USUARIO.", "error")
            return redirect(url_for("users_list"))

        audit(db, current_user_id(), "DELETE", "users", user_id, None, None, f"USER:{u['username']}")
        db.commit()

        # Evita romper FKs
        db.execute("UPDATE expedientes SET created_by=NULL WHERE created_by=?", (user_id,))
        db.execute("UPDATE expedientes SET updated_by=NULL WHERE updated_by=?", (user_id,))
        db.execute("UPDATE audit_log SET user_id=NULL WHERE user_id=?", (user_id,))

        db.execute("DELETE FROM users WHERE id=?", (user_id,))
        db.commit()

        flash("USUARIO ELIMINADO PERMANENTEMENTE.", "ok")
        return redirect(url_for("users_list"))

    # -------------------------
    # INDEX
    # -------------------------
    @app.get("/")
    @login_required
    def index():
        q = (request.args.get("q") or "").strip()
        year = (request.args.get("year") or "").strip()
        sort = (request.args.get("sort") or "desc").strip().lower()  # asc|desc

        sort_dir = "ASC" if sort == "asc" else "DESC"

        db = get_db()
        sql = """
        SELECT id, expediente_code, inmueble_nombre, representante_legal, apoderados, domicilio_inspeccion,
               telefono, quien_solicita, created_at, verificaciones, archivo_fisico
        FROM expedientes
        WHERE 1=1
        """
        params: list[str] = []

        if q:
            sql += """
              AND (
                expediente_code LIKE ? OR inmueble_nombre LIKE ? OR representante_legal LIKE ?
                OR apoderados LIKE ? OR domicilio_inspeccion LIKE ? OR telefono LIKE ?
              )
            """
            like = f"%{q}%"
            params += [like, like, like, like, like, like]

        if year:
            sql += " AND strftime('%Y', created_at) = ?"
            params.append(year)

        # Orden por NUMERO (0001, 0002...) desde expediente_code:
        # substr(expediente_code,1,4) -> "0001"
        # Nota: asume formato canonico. Si no, tu normalizador lo debe asegurar al guardar.
        sql += f"""
        ORDER BY
          CAST(substr(expediente_code, 1, 4) AS INTEGER) {sort_dir},
          datetime(created_at) DESC
        """

        rows = db.execute(sql, params).fetchall()

        years = db.execute(
            "SELECT DISTINCT strftime('%Y', created_at) AS y FROM expedientes ORDER BY y DESC"
        ).fetchall()

        return render_template(
            "index.html",
            rows=rows,
            q=q,
            year=year,
            years=[r["y"] for r in years if r["y"]],
        )

    # -------------------------
    # EXPEDIENTES
    # -------------------------
    @app.get("/expedientes/nuevo")
    @login_required
    @role_required(["CAPTURA", "ADMINISTRADOR"])
    def expediente_new():
        return render_template(
            "expediente_form.html",
            mode="new",
            who_options=WHO_OPTIONS,
            archivo_options=ARCHIVO_FISICO_OPTIONS,
            expediente=None,
            checklist=load_checklist_items(),
            checklist_state={},
        )

    @app.post("/expedientes")
    @login_required
    @role_required(["CAPTURA", "ADMINISTRADOR"])
    def expediente_create():
        form = request.form

        raw_code = (form.get("expediente_code") or "").strip()
        inmueble_nombre = (form.get("inmueble_nombre") or "").strip()
        representante_legal = (form.get("representante_legal") or "").strip()
        apoderados = (form.get("apoderados") or "").strip()
        domicilio_inspeccion = (form.get("domicilio_inspeccion") or "").strip()
        telefono = (form.get("telefono") or "").strip()
        quien_solicita = (form.get("quien_solicita") or "").strip()
        archivo_fisico = (form.get("archivo_fisico") or "").strip()

        if archivo_fisico and archivo_fisico not in ARCHIVO_FISICO_OPTIONS:
            archivo_fisico = ""

        if not raw_code or not inmueble_nombre or quien_solicita not in WHO_OPTIONS:
            flash("VERIFICA: EXPEDIENTE, NOMBRE DEL INMUEBLE Y QUIEN SOLICITA.", "error")
            return redirect(url_for("expediente_new"))

        try:
            expediente_code = normalize_expediente_code(raw_code)
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("expediente_new"))

        now = utc_now()
        user_id = current_user_id()

        db = get_db()
        cur = db.execute(
            """
            INSERT INTO expedientes (
              expediente_code, inmueble_nombre, representante_legal, apoderados,
              domicilio_inspeccion, telefono, quien_solicita,
              archivo_fisico,
              verificaciones,
              created_at, created_by, updated_at, updated_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
            """,
            (
                expediente_code,
                inmueble_nombre,
                representante_legal,
                apoderados,
                domicilio_inspeccion,
                telefono,
                quien_solicita,
                archivo_fisico,
                now,
                user_id,
                now,
                user_id,
            ),
        )
        expediente_id = cur.lastrowid

        for item in load_checklist_items():
            key = f"item_{item['id']}"
            status = (form.get(key) or "").strip()
            status_db = status if status in ("presenta", "no_presenta") else None
            db.execute(
                "INSERT INTO expediente_checklist (expediente_id, item_id, status) VALUES (?, ?, ?)",
                (expediente_id, item["id"], status_db),
            )

        audit(db, user_id, "CREATE", "expedientes", expediente_id, None, None, None)
        db.commit()

        flash("EXPEDIENTE CREADO.", "ok")
        return redirect(url_for("expediente_view", expediente_id=expediente_id))

    @app.get("/expedientes/<int:expediente_id>")
    @login_required
    def expediente_view(expediente_id: int):
        db = get_db()
        expediente = db.execute("SELECT * FROM expedientes WHERE id = ?", (expediente_id,)).fetchone()
        if not expediente:
            abort(404)

        checklist = load_checklist_items()
        checklist_state = load_checklist_state(expediente_id)
        can_edit = current_role() in ("CAPTURA", "ADMINISTRADOR")

        return render_template(
            "expediente_view.html",
            expediente=expediente,
            checklist=checklist,
            checklist_state=checklist_state,
            can_edit=can_edit,
        )

    @app.get("/expedientes/<int:expediente_id>/editar")
    @login_required
    @role_required(["CAPTURA", "ADMINISTRADOR"])
    def expediente_edit(expediente_id: int):
        db = get_db()
        expediente = db.execute("SELECT * FROM expedientes WHERE id = ?", (expediente_id,)).fetchone()
        if not expediente:
            abort(404)

        checklist = load_checklist_items()
        checklist_state = load_checklist_state(expediente_id)

        return render_template(
            "expediente_form.html",
            mode="edit",
            who_options=WHO_OPTIONS,
            archivo_options=ARCHIVO_FISICO_OPTIONS,
            expediente=expediente,
            checklist=checklist,
            checklist_state=checklist_state,
        )

    @app.post("/expedientes/<int:expediente_id>")
    @login_required
    @role_required(["CAPTURA", "ADMINISTRADOR"])
    def expediente_update(expediente_id: int):
        db = get_db()
        old = db.execute("SELECT * FROM expedientes WHERE id = ?", (expediente_id,)).fetchone()
        if not old:
            abort(404)

        form = request.form
        quien_solicita = (form.get("quien_solicita") or "").strip()
        if quien_solicita not in WHO_OPTIONS:
            flash("QUIEN SOLICITA INVALIDO.", "error")
            return redirect(url_for("expediente_edit", expediente_id=expediente_id))

        raw_code = (form.get("expediente_code") or "").strip()
        inmueble_nombre = (form.get("inmueble_nombre") or "").strip()
        representante_legal = (form.get("representante_legal") or "").strip()
        apoderados = (form.get("apoderados") or "").strip()
        domicilio_inspeccion = (form.get("domicilio_inspeccion") or "").strip()
        telefono = (form.get("telefono") or "").strip()
        archivo_fisico = (form.get("archivo_fisico") or "").strip()

        if archivo_fisico and archivo_fisico not in ARCHIVO_FISICO_OPTIONS:
            archivo_fisico = ""

        if not raw_code or not inmueble_nombre:
            flash("VERIFICA: EXPEDIENTE Y NOMBRE DEL INMUEBLE.", "error")
            return redirect(url_for("expediente_edit", expediente_id=expediente_id))

        try:
            expediente_code = normalize_expediente_code(raw_code)
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("expediente_edit", expediente_id=expediente_id))

        now = utc_now()
        user_id = current_user_id()

        db.execute(
            """
            UPDATE expedientes
            SET expediente_code = ?, inmueble_nombre = ?, representante_legal = ?, apoderados = ?,
                domicilio_inspeccion = ?, telefono = ?, quien_solicita = ?,
                archivo_fisico = ?,
                updated_at = ?, updated_by = ?
            WHERE id = ?
            """,
            (
                expediente_code,
                inmueble_nombre,
                representante_legal,
                apoderados,
                domicilio_inspeccion,
                telefono,
                quien_solicita,
                archivo_fisico,
                now,
                user_id,
                expediente_id,
            ),
        )

        compare_and_audit(
            db,
            user_id,
            expediente_id,
            old,
            {
                "expediente_code": expediente_code,
                "inmueble_nombre": inmueble_nombre,
                "representante_legal": representante_legal,
                "apoderados": apoderados,
                "domicilio_inspeccion": domicilio_inspeccion,
                "telefono": telefono,
                "quien_solicita": quien_solicita,
                "archivo_fisico": archivo_fisico,
            },
        )

        for item in load_checklist_items():
            key = f"item_{item['id']}"
            status = (form.get(key) or "").strip()
            status_db = status if status in ("presenta", "no_presenta") else None

            old_row = db.execute(
                "SELECT status FROM expediente_checklist WHERE expediente_id=? AND item_id=?",
                (expediente_id, item["id"]),
            ).fetchone()
            old_status = old_row["status"] if old_row else None

            db.execute(
                "UPDATE expediente_checklist SET status=? WHERE expediente_id=? AND item_id=?",
                (status_db, expediente_id, item["id"]),
            )

            if old_status != status_db:
                audit(
                    db,
                    user_id,
                    "UPDATE",
                    "expediente_checklist",
                    expediente_id,
                    f"ITEM:{item['label']}",
                    str(old_status) if old_status is not None else "",
                    str(status_db) if status_db is not None else "",
                )

        db.commit()
        flash("EXPEDIENTE ACTUALIZADO.", "ok")
        return redirect(url_for("expediente_view", expediente_id=expediente_id))

    @app.post("/expedientes/<int:expediente_id>/eliminar")
    @login_required
    @role_required(["CAPTURA", "ADMINISTRADOR"])
    def expediente_delete(expediente_id: int):
        db = get_db()
        exp = db.execute("SELECT id, expediente_code FROM expedientes WHERE id=?", (expediente_id,)).fetchone()
        if not exp:
            abort(404)

        audit(db, current_user_id(), "DELETE", "expedientes", expediente_id, None, None, f"EXP:{exp['expediente_code']}")
        db.commit()

        # checklist tiene ON DELETE CASCADE -> basta borrar expedientes
        db.execute("DELETE FROM expedientes WHERE id=?", (expediente_id,))
        db.commit()

        flash("EXPEDIENTE ELIMINADO PERMANENTEMENTE.", "ok")
        return redirect(url_for("index"))

    # -----------------------------
    # VERIFICACIONES / AVISOS (+/-)
    # -----------------------------
    @app.post("/expedientes/<int:expediente_id>/verificaciones/inc")
    @login_required
    @role_required(["CAPTURA", "ADMINISTRADOR"])
    def verificaciones_inc(expediente_id: int):
        db = get_db()
        row = db.execute("SELECT verificaciones FROM expedientes WHERE id=?", (expediente_id,)).fetchone()
        if not row:
            abort(404)

        old_v = int(row["verificaciones"] or 0)
        new_v = old_v + 1

        now = utc_now()
        user_id = current_user_id()

        db.execute(
            "UPDATE expedientes SET verificaciones=?, updated_at=?, updated_by=? WHERE id=?",
            (new_v, now, user_id, expediente_id),
        )
        audit(db, user_id, "UPDATE", "expedientes", expediente_id, "verificaciones", str(old_v), str(new_v))
        db.commit()

        # Si es fetch (AJAX), no redirigir
        if request.headers.get("X-Requested-With") == "fetch":
            return ("", 204)

        flash("VERIFICACION/AVISO REGISTRADO.", "ok")
        return redirect(url_for("expediente_view", expediente_id=expediente_id))

    @app.post("/expedientes/<int:expediente_id>/verificaciones/dec")
    @login_required
    @role_required(["CAPTURA", "ADMINISTRADOR"])
    def verificaciones_dec(expediente_id: int):
        db = get_db()
        row = db.execute("SELECT verificaciones FROM expedientes WHERE id=?", (expediente_id,)).fetchone()
        if not row:
            abort(404)

        old_v = int(row["verificaciones"] or 0)
        new_v = max(0, old_v - 1)

        now = utc_now()
        user_id = current_user_id()

        db.execute(
            "UPDATE expedientes SET verificaciones=?, updated_at=?, updated_by=? WHERE id=?",
            (new_v, now, user_id, expediente_id),
        )
        audit(db, user_id, "UPDATE", "expedientes", expediente_id, "verificaciones", str(old_v), str(new_v))
        db.commit()

        if request.headers.get("X-Requested-With") == "fetch":
            return ("", 204)

        flash("VERIFICACION/AVISO AJUSTADO.", "ok")
        return redirect(url_for("expediente_view", expediente_id=expediente_id))

    # -----------------------------
    # PDF INDIVIDUAL
    # -----------------------------
    @app.get("/expedientes/<int:expediente_id>/pdf")
    @login_required
    def expediente_pdf(expediente_id: int):
        db = get_db()
        expediente = db.execute("SELECT * FROM expedientes WHERE id = ?", (expediente_id,)).fetchone()
        if not expediente:
            abort(404)

        checklist = load_checklist_items()
        checklist_state = load_checklist_state(expediente_id)
        pdf_bytes = build_expediente_pdf_bytes(expediente, checklist, checklist_state)

        safe_code = (expediente["expediente_code"] or "EXPEDIENTE").replace("/", "-")
        filename = f"{safe_code}.pdf"
        return send_file(BytesIO(pdf_bytes), as_attachment=True, download_name=filename, mimetype="application/pdf")

    # -----------------------------
    # ZIP MULTI-PDF
    # -----------------------------
    @app.post("/expedientes/pdfs.zip")
    @login_required
    def expedientes_zip():
        ids = request.form.getlist("expediente_ids")
        ids = [int(i) for i in ids if str(i).isdigit()]
        if not ids:
            flash("SELECCIONA AL MENOS UN EXPEDIENTE.", "error")
            return redirect(url_for("index"))

        db = get_db()
        rows = db.execute(
            f"SELECT * FROM expedientes WHERE id IN ({','.join(['?'] * len(ids))})",
            ids,
        ).fetchall()

        buf = BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for exp in rows:
                exp_id = exp["id"]
                checklist = load_checklist_items()
                checklist_state = load_checklist_state(exp_id)
                pdf_bytes = build_expediente_pdf_bytes(exp, checklist, checklist_state)
                safe_code = (exp["expediente_code"] or f"EXP-{exp_id}").replace("/", "-")
                z.writestr(f"{safe_code}.pdf", pdf_bytes)

        buf.seek(0)
        return send_file(buf, as_attachment=True, download_name="expedientes_pdfs.zip", mimetype="application/zip")

    return app


if __name__ == "__main__":
    app = create_app()
    port = 5001 if APP_ENV == "dev" else 5000
    debug = True if APP_ENV == "dev" else False
    app.run(host="0.0.0.0", port=port, debug=debug)