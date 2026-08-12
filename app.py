from __future__ import annotations

import os
import re
import zipfile
from datetime import datetime, timezone
from functools import wraps
from io import BytesIO, StringIO
from pathlib import Path

import csv
import psycopg2
import psycopg2.extras
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
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from werkzeug.security import check_password_hash, generate_password_hash

# =========================================================
# CONFIG
# =========================================================
APP_DIR = Path(__file__).resolve().parent

SUFIJO = "DPCJM"


def normalize_expediente_code(raw: str) -> str:
    s = (raw or "").strip().upper()
    s = s.replace("-", "/").replace(" ", "")

    parts = s.split("/")
    if len(parts) < 2:
        raise ValueError("FORMATO INVALIDO. USA: 0001/0126/DPCJM")

    num_part = parts[0]
    mmyy = parts[1]

    m = re.fullmatch(r"(\d{1,4})([A-Z]?)", num_part)
    if not m:
        raise ValueError("EL NUMERO DE EXPEDIENTE DEBE SER NUMERICO O NUMERO + LETRA (EJ: 1380A).")

    num = int(m.group(1))
    letra = m.group(2)

    if num < 0 or num > 9999:
        raise ValueError("NUMERO DE EXPEDIENTE FUERA DE RANGO (0-9999).")

    if not re.fullmatch(r"\d{4}", mmyy):
        raise ValueError("LA PARTE MMAA DEBE SER 4 DIGITOS (EJ. 0126).")

    if letra:
        return f"{num:04d}{letra}/{mmyy}/{SUFIJO}"
    else:
        return f"{num:04d}/{mmyy}/{SUFIJO}"


# --- DATABASE URL desde Railway ---
DATABASE_URL = os.environ.get("DATABASE_URL", "")
APP_ENV = os.environ.get("APP_ENV", "prod").lower()

ROLES = ["LECTURA", "CAPTURA", "ADMINISTRADOR"]
WHO_OPTIONS = [
    "Propietario",
    "Apoderado",
    "Operativo",
    "Tramite En Oficina",
    "Representante Legal",
    "Operativo Tortillero Seguro",
    "Comandante",
    "Operativo  Inmueble Seguro",
    "Desarrollo Economico",
    "Mejora Regulatoria",
    "Tercero Acreditado",
]
ARCHIVO_FISICO_OPTIONS = [
    "Transparencia",
    "Pendientes",
    "Archivo 09318",
    "Archivo Gris",
]

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


def get_db():
    if "db" not in g:
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False
        g.db = conn
    return g.db


def dict_row(cursor, row):
    """Convierte una fila de psycopg2 en dict."""
    if row is None:
        return None
    cols = [desc[0] for desc in cursor.description]
    return dict(zip(cols, row))


def fetchone(cursor) -> dict | None:
    row = cursor.fetchone()
    return dict_row(cursor, row)


def fetchall(cursor) -> list[dict]:
    rows = cursor.fetchall()
    cols = [desc[0] for desc in cursor.description]
    return [dict(zip(cols, r)) for r in rows]


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


def audit(db, user_id, action, entity, entity_id, field, old_value, new_value):
    cur = db.cursor()
    cur.execute(
        """
        INSERT INTO audit_log (ts, user_id, action, entity, entity_id, field, old_value, new_value)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (utc_now(), user_id, action, entity, entity_id, field, old_value, new_value),
    )


def init_db(app: Flask) -> None:
    with app.app_context():
        db = get_db()
        cur = db.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS expedientes (
                id SERIAL PRIMARY KEY,
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
                citatorio_fecha TEXT,
                acta_inspeccion_folio TEXT,
                acta_verificacion_fecha TEXT,
                resolutivo_fecha TEXT,
                ultimo_aviso_fecha TEXT,
                segundo_aviso_fecha TEXT,
                clausura_fecha TEXT,
                vobo_fecha TEXT,
                pipc_fecha TEXT
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS checklist_items (
                id SERIAL PRIMARY KEY,
                label TEXT NOT NULL UNIQUE,
                sort_order INTEGER NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS expediente_checklist (
                expediente_id INTEGER NOT NULL,
                item_id INTEGER NOT NULL,
                status TEXT CHECK(status IN ('presenta','no_presenta') OR status IS NULL),
                PRIMARY KEY (expediente_id, item_id),
                FOREIGN KEY (expediente_id) REFERENCES expedientes(id) ON DELETE CASCADE,
                FOREIGN KEY (item_id) REFERENCES checklist_items(id) ON DELETE CASCADE
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id SERIAL PRIMARY KEY,
                ts TEXT NOT NULL,
                user_id INTEGER,
                action TEXT NOT NULL,
                entity TEXT NOT NULL,
                entity_id INTEGER,
                field TEXT,
                old_value TEXT,
                new_value TEXT
            )
        """)

        # Seed checklist si está vacío
        cur.execute("SELECT COUNT(*) AS c FROM checklist_items")
        count = cur.fetchone()[0]
        if count == 0:
            for i, label in enumerate(CHECKLIST_DEFAULT, start=1):
                cur.execute(
                    "INSERT INTO checklist_items (label, sort_order) VALUES (%s, %s)",
                    (label, i)
                )

        db.commit()


def ensure_default_admin() -> None:
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT 1 FROM users WHERE username='admin'")
    exists = cur.fetchone()
    if exists:
        return
    cur.execute(
        "INSERT INTO users (username, password_hash, role, is_active, created_at) VALUES (%s, %s, %s, 1, %s)",
        ("admin", generate_password_hash("Admin-2026!"), "ADMINISTRADOR", utc_now()),
    )
    db.commit()


def load_checklist_items():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, label FROM checklist_items ORDER BY sort_order ASC")
    return fetchall(cur)


def load_checklist_state(expediente_id: int) -> dict[int, str | None]:
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT item_id, status FROM expediente_checklist WHERE expediente_id = %s",
        (expediente_id,),
    )
    rows = fetchall(cur)
    return {r["item_id"]: r["status"] for r in rows}


def compare_and_audit(db, user_id, expediente_id, old_row: dict, new_map: dict):
    for k, new_v in new_map.items():
        old_v = old_row.get(k)
        if (old_v or "") != (new_v or ""):
            audit(db, user_id, "UPDATE", "expedientes", expediente_id, k, str(old_v or ""), str(new_v or ""))


def draw_justified_text(c, text, x, y, max_width, line_height=12, font="Helvetica", font_size=9):
    c.setFont(font, font_size)
    words = (text or "").split()
    line_words = []
    lines = []

    for word in words:
        test_line = " ".join(line_words + [word])
        if c.stringWidth(test_line, font, font_size) <= max_width:
            line_words.append(word)
        else:
            lines.append(line_words)
            line_words = [word]
    if line_words:
        lines.append(line_words)

    for i, line in enumerate(lines):
        if y < 5 * cm:
            c.showPage()
            c.setFont(font, font_size)
            y = LETTER[1] - 2 * cm

        if i == len(lines) - 1 or len(line) == 1:
            c.drawString(x, y, " ".join(line))
        else:
            total_words_width = sum(c.stringWidth(w, font, font_size) for w in line)
            space_count = len(line) - 1
            extra_space = (max_width - total_words_width) / space_count
            cursor_x = x
            for w in line[:-1]:
                c.drawString(cursor_x, y, w)
                cursor_x += c.stringWidth(w, font, font_size) + extra_space
            c.drawString(cursor_x, y, line[-1])

        y -= line_height

    return y


def build_expediente_pdf_bytes(expediente: dict, checklist, checklist_state) -> bytes:
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=LETTER)
    width, height = LETTER
    x = 2 * cm
    y = height - 2 * cm

    logo_path = APP_DIR / "static" / "logo_pcjm.png"
    if logo_path.exists():
        img = ImageReader(str(logo_path))
        logo_w = 3.2 * cm
        logo_h = 3.2 * cm
        logo_x = (width - logo_w) / 2
        logo_y = y - logo_h
        c.drawImage(img, logo_x, logo_y, width=logo_w, height=logo_h,
                    mask="auto", preserveAspectRatio=True, anchor="c")
        y = logo_y - 0.8 * cm

    year = (expediente.get("created_at") or "")[:4] or "AAAA"
    c.setFont("Helvetica-Bold", 11)
    c.drawCentredString(width / 2, y, f"EXPEDIENTE {year} DEPARTAMENTO DE PROTECCION CIVIL")
    y -= 1.2 * cm

    c.setFont("Helvetica-Bold", 9)
    fields = [
        ("EXPEDIENTE", expediente.get("expediente_code", "")),
        ("NOMBRE DEL INMUEBLE", expediente.get("inmueble_nombre", "")),
        ("REPRESENTANTE LEGAL", expediente.get("representante_legal") or ""),
        ("APODERADOS", expediente.get("apoderados") or ""),
        ("DOMICILIO DE LA INSPECCION", expediente.get("domicilio_inspeccion") or ""),
        ("TELEFONO", expediente.get("telefono") or ""),
        ("QUIEN SOLICITA", expediente.get("quien_solicita", "")),
        ("ARCHIVO FISICO", expediente.get("archivo_fisico") or ""),
        ("VERIFICACIONES/AVISOS", str(int(expediente.get("verificaciones") or 0))),
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
        if y < 5.0 * cm:
            c.showPage()
            y = height - 2 * cm
        c.drawString(x, y, item["label"][:95])
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
    y = draw_justified_text(c, PRIVACY_NOTICE, x, y, (width - 2 * x), line_height=10, font="Helvetica", font_size=9)

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
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "CAMBIA-ESTO-EN-RAILWAY")

    init_db(app)
    with app.app_context():
        ensure_default_admin()

    @app.teardown_appcontext
    def close_db(exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.context_processor
    def inject_now():
        return {"now": datetime.now}

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
        cur = db.cursor()
        cur.execute(
            "SELECT id, username, password_hash, role, is_active FROM users WHERE username = %s",
            (username,),
        )
        user = fetchone(cur)

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
        cur = db.cursor()
        cur.execute("SELECT id, username, role, is_active, created_at FROM users ORDER BY created_at DESC")
        rows = fetchall(cur)
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
        cur = db.cursor()
        cur.execute("SELECT 1 FROM users WHERE username=%s", (username,))
        if cur.fetchone():
            flash("ESE USUARIO YA EXISTE.", "error")
            return redirect(url_for("user_new"))

        now = utc_now()
        cur.execute(
            "INSERT INTO users (username, password_hash, role, is_active, created_at) VALUES (%s, %s, %s, %s, %s) RETURNING id",
            (username, generate_password_hash(password), role, is_active, now),
        )
        new_id = cur.fetchone()[0]
        audit(db, current_user_id(), "CREATE", "users", new_id, None, None, None)
        db.commit()
        flash("USUARIO CREADO.", "ok")
        return redirect(url_for("users_list"))

    @app.get("/users/<int:user_id>/edit")
    @login_required
    @role_required(["ADMINISTRADOR"])
    def user_edit(user_id: int):
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id, username, role, is_active, created_at FROM users WHERE id=%s", (user_id,))
        user = fetchone(cur)
        if not user:
            abort(404)
        return render_template("user_form.html", mode="edit", roles=ROLES, user=user)

    @app.post("/users/<int:user_id>")
    @login_required
    @role_required(["ADMINISTRADOR"])
    def user_update(user_id: int):
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        old = fetchone(cur)
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

        cur.execute("SELECT 1 FROM users WHERE username=%s AND id<>%s", (username, user_id))
        if cur.fetchone():
            flash("ESE USUARIO YA EXISTE.", "error")
            return redirect(url_for("user_edit", user_id=user_id))

        if user_id == current_user_id() and is_active == 0:
            flash("NO PUEDES DESACTIVAR TU PROPIO USUARIO.", "error")
            return redirect(url_for("user_edit", user_id=user_id))

        if new_password:
            cur.execute(
                "UPDATE users SET username=%s, role=%s, is_active=%s, password_hash=%s WHERE id=%s",
                (username, role, is_active, generate_password_hash(new_password), user_id),
            )
        else:
            cur.execute(
                "UPDATE users SET username=%s, role=%s, is_active=%s WHERE id=%s",
                (username, role, is_active, user_id),
            )

        if (old["username"] or "") != username:
            audit(db, current_user_id(), "UPDATE", "users", user_id, "username", old["username"], username)
        if (old["role"] or "") != role:
            audit(db, current_user_id(), "UPDATE", "users", user_id, "role", old["role"], role)
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
        cur = db.cursor()
        cur.execute("SELECT id, username FROM users WHERE id=%s", (user_id,))
        u = fetchone(cur)
        if not u:
            abort(404)

        if user_id == current_user_id():
            flash("NO PUEDES ELIMINAR TU PROPIO USUARIO.", "error")
            return redirect(url_for("users_list"))

        audit(db, current_user_id(), "DELETE", "users", user_id, None, None, f"USER:{u['username']}")
        cur.execute("UPDATE expedientes SET created_by=NULL WHERE created_by=%s", (user_id,))
        cur.execute("UPDATE expedientes SET updated_by=NULL WHERE updated_by=%s", (user_id,))
        cur.execute("UPDATE audit_log SET user_id=NULL WHERE user_id=%s", (user_id,))
        cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
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
        sort = (request.args.get("sort") or "desc").strip().lower()
        sort_dir = "ASC" if sort == "asc" else "DESC"

        db = get_db()
        cur = db.cursor()

        sql = """
        SELECT id, expediente_code, inmueble_nombre, representante_legal, apoderados, domicilio_inspeccion,
               telefono, quien_solicita, created_at, verificaciones, archivo_fisico
        FROM expedientes
        WHERE 1=1
        """
        params: list = []

        if q:
            sql += """
              AND (
                expediente_code ILIKE %s OR inmueble_nombre ILIKE %s OR representante_legal ILIKE %s
                OR apoderados ILIKE %s OR domicilio_inspeccion ILIKE %s OR telefono ILIKE %s
              )
            """
            like = f"%{q}%"
            params += [like, like, like, like, like, like]

        if year:
            yy = year[2:4]
            sql += " AND SUBSTR(SPLIT_PART(expediente_code, '/', 2), 3, 2) = %s"
            params.append(yy)

        sql += f"""
        ORDER BY
            CAST(NULLIF(REGEXP_REPLACE(SPLIT_PART(expediente_code, '/', 2), '[^0-9]', '', 'g'), '') AS INTEGER) {sort_dir} NULLS LAST,
            created_at DESC
        """

        cur.execute(sql, params)
        rows = fetchall(cur)

        cur.execute("""
            SELECT DISTINCT '20' || SUBSTR(SPLIT_PART(expediente_code, '/', 2), 3, 2) AS y
            FROM expedientes
            WHERE STRPOS(expediente_code, '/') > 0
            ORDER BY y DESC
        """)
        years_rows = fetchall(cur)

        return render_template(
            "index.html",
            rows=rows,
            q=q,
            year=year,
            years=[r["y"] for r in years_rows if r.get("y")],
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
        cur = db.cursor()

        try:
            cur.execute(
                """
                INSERT INTO expedientes (
                  expediente_code, inmueble_nombre, representante_legal, apoderados,
                  domicilio_inspeccion, telefono, quien_solicita, archivo_fisico,
                  verificaciones, created_at, created_by, updated_at, updated_by
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,0,%s,%s,%s,%s)
                RETURNING id
                """,
                (expediente_code, inmueble_nombre, representante_legal, apoderados,
                 domicilio_inspeccion, telefono, quien_solicita, archivo_fisico or None,
                 now, user_id, now, user_id),
            )
            new_id = cur.fetchone()[0]
        except psycopg2.errors.UniqueViolation:
            db.rollback()
            flash("YA EXISTE UN EXPEDIENTE CON ESE CODIGO.", "error")
            return redirect(url_for("expediente_new"))

        # Checklist items
        checklist = load_checklist_items()
        for item in checklist:
            key = f"item_{item['id']}"
            status = (form.get(key) or "").strip()
            status_db = status if status in ("presenta", "no_presenta") else None
            cur.execute(
                "INSERT INTO expediente_checklist (expediente_id, item_id, status) VALUES (%s,%s,%s)",
                (new_id, item["id"], status_db),
            )

        audit(db, user_id, "CREATE", "expedientes", new_id, None, None, expediente_code)
        db.commit()
        flash("EXPEDIENTE CREADO.", "ok")
        return redirect(url_for("expediente_view", expediente_id=new_id))

    @app.get("/expedientes/<int:expediente_id>")
    @login_required
    def expediente_view(expediente_id: int):
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM expedientes WHERE id = %s", (expediente_id,))
        expediente = fetchone(cur)
        if not expediente:
            abort(404)

        checklist = load_checklist_items()
        checklist_state = load_checklist_state(expediente_id)
        can_edit = current_role() in ["CAPTURA", "ADMINISTRADOR"]

        return render_template(
            "expediente_view.html",
            expediente=expediente,
            checklist=checklist,
            checklist_state=checklist_state,
            can_edit=can_edit,
        )

    @app.post("/expedientes/<int:expediente_id>/documentos")
    @login_required
    @role_required(["CAPTURA", "ADMINISTRADOR"])
    def expediente_documentos_update(expediente_id: int):
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM expedientes WHERE id=%s", (expediente_id,))
        old = fetchone(cur)
        if not old:
            abort(404)

        f = request.form

        def clean_date(name: str) -> str | None:
            v = (f.get(name) or "").strip()
            if not v:
                return None
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
                raise ValueError(f"FECHA INVALIDA EN {name}.")
            return v

        try:
            citatorio_fecha = clean_date("citatorio_fecha")
            acta_verificacion_fecha = clean_date("acta_verificacion_fecha")
            resolutivo_fecha = clean_date("resolutivo_fecha")
            ultimo_aviso_fecha = clean_date("ultimo_aviso_fecha")
            segundo_aviso_fecha = clean_date("segundo_aviso_fecha")
            clausura_fecha = clean_date("clausura_fecha")
            vobo_fecha = clean_date("vobo_fecha")
            pipc_fecha = clean_date("pipc_fecha")
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("expediente_view", expediente_id=expediente_id))

        acta_inspeccion_folio = (f.get("acta_inspeccion_folio") or "").strip().upper()
        now = utc_now()
        user_id = current_user_id()

        cur.execute(
            """
            UPDATE expedientes
            SET citatorio_fecha=%s, acta_inspeccion_folio=%s, acta_verificacion_fecha=%s,
                resolutivo_fecha=%s, ultimo_aviso_fecha=%s, segundo_aviso_fecha=%s,
                clausura_fecha=%s, vobo_fecha=%s, pipc_fecha=%s,
                updated_at=%s, updated_by=%s
            WHERE id=%s
            """,
            (citatorio_fecha, acta_inspeccion_folio or None, acta_verificacion_fecha,
             resolutivo_fecha, ultimo_aviso_fecha, segundo_aviso_fecha,
             clausura_fecha, vobo_fecha, pipc_fecha, now, user_id, expediente_id),
        )

        db.commit()
        flash("DOCUMENTOS ACTUALIZADOS.", "ok")
        return redirect(url_for("expediente_view", expediente_id=expediente_id))

    @app.get("/expedientes/<int:expediente_id>/editar")
    @login_required
    @role_required(["CAPTURA", "ADMINISTRADOR"])
    def expediente_edit(expediente_id: int):
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM expedientes WHERE id = %s", (expediente_id,))
        expediente = fetchone(cur)
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
        cur = db.cursor()
        cur.execute("SELECT * FROM expedientes WHERE id = %s", (expediente_id,))
        old = fetchone(cur)
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

        cur.execute(
            """
            UPDATE expedientes
            SET expediente_code=%s, inmueble_nombre=%s, representante_legal=%s, apoderados=%s,
                domicilio_inspeccion=%s, telefono=%s, quien_solicita=%s, archivo_fisico=%s,
                updated_at=%s, updated_by=%s
            WHERE id=%s
            """,
            (expediente_code, inmueble_nombre, representante_legal, apoderados,
             domicilio_inspeccion, telefono, quien_solicita, archivo_fisico,
             now, user_id, expediente_id),
        )

        compare_and_audit(db, user_id, expediente_id, old, {
            "expediente_code": expediente_code,
            "inmueble_nombre": inmueble_nombre,
            "representante_legal": representante_legal,
            "apoderados": apoderados,
            "domicilio_inspeccion": domicilio_inspeccion,
            "telefono": telefono,
            "quien_solicita": quien_solicita,
            "archivo_fisico": archivo_fisico,
        })

        for item in load_checklist_items():
            key = f"item_{item['id']}"
            status = (form.get(key) or "").strip()
            status_db = status if status in ("presenta", "no_presenta") else None

            cur.execute(
                "SELECT status FROM expediente_checklist WHERE expediente_id=%s AND item_id=%s",
                (expediente_id, item["id"]),
            )
            old_row = cur.fetchone()
            old_status = old_row[0] if old_row else None

            cur.execute(
                "UPDATE expediente_checklist SET status=%s WHERE expediente_id=%s AND item_id=%s",
                (status_db, expediente_id, item["id"]),
            )

            if old_status != status_db:
                audit(db, user_id, "UPDATE", "expediente_checklist", expediente_id,
                      f"ITEM:{item['label']}", str(old_status or ""), str(status_db or ""))

        db.commit()
        flash("EXPEDIENTE ACTUALIZADO.", "ok")
        return redirect(url_for("expediente_view", expediente_id=expediente_id))

    @app.post("/expedientes/<int:expediente_id>/eliminar")
    @login_required
    @role_required(["CAPTURA", "ADMINISTRADOR"])
    def expediente_delete(expediente_id: int):
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id, expediente_code FROM expedientes WHERE id=%s", (expediente_id,))
        exp = fetchone(cur)
        if not exp:
            abort(404)

        audit(db, current_user_id(), "DELETE", "expedientes", expediente_id, None, None, f"EXP:{exp['expediente_code']}")
        cur.execute("DELETE FROM expedientes WHERE id=%s", (expediente_id,))
        db.commit()

        flash("EXPEDIENTE ELIMINADO PERMANENTEMENTE.", "ok")
        return redirect(url_for("index"))

    # -------------------------
    # VERIFICACIONES / AVISOS
    # -------------------------
    @app.post("/expedientes/<int:expediente_id>/verificaciones/inc")
    @login_required
    @role_required(["CAPTURA", "ADMINISTRADOR"])
    def verificaciones_inc(expediente_id: int):
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT verificaciones FROM expedientes WHERE id=%s", (expediente_id,))
        row = cur.fetchone()
        if not row:
            abort(404)

        old_v = int(row[0] or 0)
        new_v = old_v + 1
        now = utc_now()
        user_id = current_user_id()

        cur.execute(
            "UPDATE expedientes SET verificaciones=%s, updated_at=%s, updated_by=%s WHERE id=%s",
            (new_v, now, user_id, expediente_id),
        )
        audit(db, user_id, "UPDATE", "expedientes", expediente_id, "verificaciones", str(old_v), str(new_v))
        db.commit()

        if request.headers.get("X-Requested-With") == "fetch":
            return ("", 204)

        flash("VERIFICACION/AVISO REGISTRADO.", "ok")
        return redirect(url_for("expediente_view", expediente_id=expediente_id))

    @app.post("/expedientes/<int:expediente_id>/verificaciones/dec")
    @login_required
    @role_required(["CAPTURA", "ADMINISTRADOR"])
    def verificaciones_dec(expediente_id: int):
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT verificaciones FROM expedientes WHERE id=%s", (expediente_id,))
        row = cur.fetchone()
        if not row:
            abort(404)

        old_v = int(row[0] or 0)
        new_v = max(0, old_v - 1)
        now = utc_now()
        user_id = current_user_id()

        cur.execute(
            "UPDATE expedientes SET verificaciones=%s, updated_at=%s, updated_by=%s WHERE id=%s",
            (new_v, now, user_id, expediente_id),
        )
        audit(db, user_id, "UPDATE", "expedientes", expediente_id, "verificaciones", str(old_v), str(new_v))
        db.commit()

        if request.headers.get("X-Requested-With") == "fetch":
            return ("", 204)

        flash("VERIFICACION/AVISO AJUSTADO.", "ok")
        return redirect(url_for("expediente_view", expediente_id=expediente_id))

    # -------------------------
    # PDF INDIVIDUAL
    # -------------------------
    @app.get("/expedientes/<int:expediente_id>/pdf")
    @login_required
    def expediente_pdf(expediente_id: int):
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM expedientes WHERE id = %s", (expediente_id,))
        expediente = fetchone(cur)
        if not expediente:
            abort(404)

        checklist = load_checklist_items()
        checklist_state = load_checklist_state(expediente_id)
        pdf_bytes = build_expediente_pdf_bytes(expediente, checklist, checklist_state)

        safe_code = (expediente["expediente_code"] or "EXPEDIENTE").replace("/", "-")
        filename = f"{safe_code}.pdf"
        return send_file(BytesIO(pdf_bytes), as_attachment=True, download_name=filename, mimetype="application/pdf")

    # -------------------------
    # ZIP MULTI-PDF
    # -------------------------
    @app.post("/expedientes/pdfs.zip")
    @login_required
    def expedientes_zip():
        ids = request.form.getlist("expediente_ids")
        ids = [int(i) for i in ids if str(i).isdigit()]
        if not ids:
            flash("SELECCIONA AL MENOS UN EXPEDIENTE.", "error")
            return redirect(url_for("index"))

        db = get_db()
        cur = db.cursor()
        cur.execute(
            f"SELECT * FROM expedientes WHERE id IN ({','.join(['%s'] * len(ids))})",
            ids,
        )
        rows = fetchall(cur)

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

    # -------------------------
    # CSV LISTA  (bug de coma corregido)
    # -------------------------
    @app.post("/expedientes/lista.csv")
    @login_required
    def expedientes_lista():
        ids = request.form.getlist("expediente_ids")
        ids = [int(i) for i in ids if str(i).isdigit()]

        if not ids:
            flash("SELECCIONA AL MENOS UN EXPEDIENTE.", "error")
            return redirect(url_for("index"))

        db = get_db()
        cur = db.cursor()
        cur.execute(
            f"""
            SELECT
              expediente_code, inmueble_nombre, representante_legal, apoderados,
              domicilio_inspeccion, telefono, quien_solicita,
              citatorio_fecha, acta_inspeccion_folio, acta_verificacion_fecha,
              resolutivo_fecha, ultimo_aviso_fecha, segundo_aviso_fecha,
              clausura_fecha, vobo_fecha, pipc_fecha
            FROM expedientes
            WHERE id IN ({",".join(["%s"] * len(ids))})
            ORDER BY expediente_code ASC
            """,
            ids,
        )
        rows = fetchall(cur)

        sio = StringIO()
        w = csv.writer(sio)
        w.writerow([
            "NUMERO DE EXPEDIENTE", "NOMBRE DEL INMUEBLE", "REPRESENTANTE LEGAL",
            "APODERADOS", "DOMICILIO DE LA INSPECCION", "TELEFONO", "QUIEN SOLICITA",
            "CITATORIO", "NO. ACTA INSPECCION", "ACTA VERIFICACION", "RESOLUTIVO",
            "ULTIMO AVISO", "SEGUNDO AVISO ANTES DE CLAUSURA", "CLAUSURA", "VO BO", "PIPC",
        ])
        for r in rows:
            w.writerow([
                r.get("expediente_code") or "", r.get("inmueble_nombre") or "",
                r.get("representante_legal") or "", r.get("apoderados") or "",
                r.get("domicilio_inspeccion") or "", r.get("telefono") or "",
                r.get("quien_solicita") or "", r.get("citatorio_fecha") or "",
                r.get("acta_inspeccion_folio") or "", r.get("acta_verificacion_fecha") or "",
                r.get("resolutivo_fecha") or "", r.get("ultimo_aviso_fecha") or "",
                r.get("segundo_aviso_fecha") or "", r.get("clausura_fecha") or "",
                r.get("vobo_fecha") or "", r.get("pipc_fecha") or "",
            ])

        data = sio.getvalue().encode("utf-8-sig")
        return send_file(
            BytesIO(data),
            as_attachment=True,
            download_name="expedientes_lista.csv",
            mimetype="text/csv; charset=utf-8",
        )

    return app


if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=(APP_ENV == "dev"))