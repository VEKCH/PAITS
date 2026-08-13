require("dotenv").config();
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const ExcelJS = require("exceljs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const PRODUCCION = process.env.NODE_ENV === "production";
const DATA_DIR = path.join(__dirname, "data");
const UPLOADS_DIR = path.join(__dirname, "uploads");
const DB_FICHAS = path.join(DATA_DIR, "fichas.json");
const DB_USERS = path.join(DATA_DIR, "usuarios.json");
const DB_MATERIALES = path.join(DATA_DIR, "materiales.json");
const DB_GRUPOS = path.join(DATA_DIR, "grupos.json");

fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
fs.mkdirSync(UPLOADS_DIR, { recursive: true, mode: 0o700 });

// Clave de sesión: si no configuraste SESSION_SECRET, en producción se genera una
// aleatoria en cada arranque (más seguro que un valor por defecto adivinable,
// aunque esto cierra las sesiones activas cada vez que el servidor se reinicia).
let SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
  SESSION_SECRET = crypto.randomBytes(32).toString("hex");
  if (PRODUCCION) {
    console.warn("Aviso: no configuraste SESSION_SECRET. Se generó uno temporal — las sesiones se cerrarán en cada reinicio del servidor. Configúralo como variable de entorno para evitarlo.");
  }
}

app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

// Forzar HTTPS en producción (los servicios como Render/Railway terminan el
// certificado en su proxy y reenvían la cabecera x-forwarded-proto).
app.use((req, res, next) => {
  if (PRODUCCION && req.headers["x-forwarded-proto"] && req.headers["x-forwarded-proto"] !== "https") {
    return res.redirect(301, `https://${req.headers.host}${req.originalUrl}`);
  }
  next();
});

app.use(express.json());
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax", secure: PRODUCCION, maxAge: 1000 * 60 * 60 * 8 },
  })
);

// Límite general de peticiones a la API, para dificultar abuso automatizado.
app.use("/api", rateLimit({ windowMs: 15 * 60 * 1000, max: 300, standardHeaders: true, legacyHeaders: false }));

// Límite estricto de intentos de login por IP (fuerza bruta).
const limitadorLogin = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Demasiados intentos de inicio de sesión. Espera unos minutos e intenta de nuevo." },
});

// Protección CSRF: token de un solo secreto por sesión, exigido en cada
// petición que modifica datos (POST/PATCH/DELETE), salvo el login mismo.
function requireCsrf(req, res, next) {
  if (!["POST", "PATCH", "DELETE", "PUT"].includes(req.method)) return next();
  const token = req.get("x-csrf-token");
  if (!req.session.csrfToken || !token || token !== req.session.csrfToken) {
    return res.status(403).json({ error: "Token de seguridad inválido o expirado. Recarga la página e inténtalo de nuevo." });
  }
  next();
}
app.use("/api", (req, res, next) => {
  if (req.path === "/login") return next();
  requireCsrf(req, res, next);
});

/* ---------------- almacenamiento en archivos JSON ---------------- */
function leer(archivo, porDefecto) {
  try {
    if (!fs.existsSync(archivo)) return porDefecto;
    return JSON.parse(fs.readFileSync(archivo, "utf-8"));
  } catch (e) {
    return porDefecto;
  }
}
function guardar(archivo, datos) {
  fs.writeFileSync(archivo, JSON.stringify(datos, null, 2), { mode: 0o600 });
  try { fs.chmodSync(archivo, 0o600); } catch (e) {}
}
function nuevoId() {
  return crypto.randomBytes(8).toString("hex");
}

/* ---------------- usuarios: crear director inicial si no existe ---------------- */
function inicializarUsuarios() {
  const usuarios = leer(DB_USERS, []);
  if (usuarios.length === 0) {
    const claveInicial = "director123";
    usuarios.push({
      id: nuevoId(),
      username: "director",
      nombre: "Director/a",
      role: "director",
      passwordHash: bcrypt.hashSync(claveInicial, 10),
      activo: true,
      intentosFallidos: 0,
      bloqueadoHasta: null,
    });
    guardar(DB_USERS, usuarios);
    console.log("========================================================");
    console.log("Cuenta de director creada automáticamente:");
    console.log("  usuario:  director");
    console.log(`  clave:    ${claveInicial}`);
    console.log("Inicia sesión y cámbiala de inmediato desde 'Mi perfil'.");
    console.log("========================================================");
  }
}
inicializarUsuarios();

/* ---------------- auth middlewares ---------------- */
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "No has iniciado sesión." });
  next();
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user) return res.status(401).json({ error: "No has iniciado sesión." });
    if (req.session.user.role !== role) return res.status(403).json({ error: "No tienes permiso para esta acción." });
    next();
  };
}

/* ---------------- auth routes ---------------- */
const MAX_INTENTOS = 5;
const BLOQUEO_MS = 15 * 60 * 1000;

function generarCsrfToken() {
  return crypto.randomBytes(24).toString("hex");
}

app.post("/api/login", limitadorLogin, (req, res) => {
  const { username, password } = req.body || {};
  const usuarios = leer(DB_USERS, []);
  const idx = usuarios.findIndex((x) => x.username === (username || "").trim().toLowerCase());
  const u = idx !== -1 ? usuarios[idx] : null;

  if (u && u.bloqueadoHasta && new Date(u.bloqueadoHasta) > new Date()) {
    const minutos = Math.ceil((new Date(u.bloqueadoHasta) - new Date()) / 60000);
    return res.status(423).json({ error: `Cuenta bloqueada temporalmente por varios intentos fallidos. Intenta de nuevo en ${minutos} minuto(s).` });
  }

  const valido = u && u.activo && bcrypt.compareSync(password || "", u.passwordHash);
  if (!valido) {
    if (u) {
      u.intentosFallidos = (u.intentosFallidos || 0) + 1;
      if (u.intentosFallidos >= MAX_INTENTOS) {
        u.bloqueadoHasta = new Date(Date.now() + BLOQUEO_MS).toISOString();
        u.intentosFallidos = 0;
      }
      usuarios[idx] = u;
      guardar(DB_USERS, usuarios);
    }
    return res.status(401).json({ error: "Usuario o clave incorrectos." });
  }

  u.intentosFallidos = 0;
  u.bloqueadoHasta = null;
  usuarios[idx] = u;
  guardar(DB_USERS, usuarios);

  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: "No se pudo iniciar sesión, intenta de nuevo." });
    req.session.user = { id: u.id, username: u.username, nombre: u.nombre, role: u.role };
    req.session.csrfToken = generarCsrfToken();
    res.json({ ...req.session.user, csrfToken: req.session.csrfToken });
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.status(204).end());
});

app.get("/api/me", requireAuth, (req, res) => {
  if (!req.session.csrfToken) req.session.csrfToken = generarCsrfToken();
  res.json({ ...req.session.user, csrfToken: req.session.csrfToken });
});

app.post("/api/me/password", requireAuth, (req, res) => {
  const { actual, nueva } = req.body || {};
  const usuarios = leer(DB_USERS, []);
  const idx = usuarios.findIndex((u) => u.id === req.session.user.id);
  if (idx === -1) return res.status(404).json({ error: "Usuario no encontrado." });
  if (!bcrypt.compareSync(actual || "", usuarios[idx].passwordHash)) {
    return res.status(400).json({ error: "La clave actual no es correcta." });
  }
  if (!nueva || nueva.length < 6) return res.status(400).json({ error: "La nueva clave debe tener al menos 6 caracteres." });
  usuarios[idx].passwordHash = bcrypt.hashSync(nueva, 10);
  guardar(DB_USERS, usuarios);
  res.json({ ok: true });
});

/* ---------------- gestión de tutores (solo director) ---------------- */
app.get("/api/tutores", requireAuth, (req, res) => {
  const usuarios = leer(DB_USERS, []).filter((u) => u.role === "tutor");
  res.json(usuarios.map((u) => ({ id: u.id, username: u.username, nombre: u.nombre, activo: u.activo })));
});

app.post("/api/tutores", requireRole("director"), (req, res) => {
  const { username, nombre, password } = req.body || {};
  if (!username || !nombre || !password) return res.status(400).json({ error: "Faltan datos (usuario, nombre o clave)." });
  const usuarios = leer(DB_USERS, []);
  const uname = username.trim().toLowerCase();
  if (usuarios.some((u) => u.username === uname)) return res.status(409).json({ error: "Ese nombre de usuario ya existe." });
  const tutor = { id: nuevoId(), username: uname, nombre, role: "tutor", passwordHash: bcrypt.hashSync(password, 10), activo: true, intentosFallidos: 0, bloqueadoHasta: null };
  usuarios.push(tutor);
  guardar(DB_USERS, usuarios);
  res.status(201).json({ id: tutor.id, username: tutor.username, nombre: tutor.nombre, activo: tutor.activo });
});

app.patch("/api/tutores/:id", requireRole("director"), (req, res) => {
  const usuarios = leer(DB_USERS, []);
  const idx = usuarios.findIndex((u) => u.id === req.params.id && u.role === "tutor");
  if (idx === -1) return res.status(404).json({ error: "Tutor no encontrado." });
  if (typeof req.body.activo === "boolean") usuarios[idx].activo = req.body.activo;
  if (req.body.nombre) usuarios[idx].nombre = req.body.nombre;
  if (req.body.password) usuarios[idx].passwordHash = bcrypt.hashSync(req.body.password, 10);
  guardar(DB_USERS, usuarios);
  res.json({ id: usuarios[idx].id, username: usuarios[idx].username, nombre: usuarios[idx].nombre, activo: usuarios[idx].activo });
});

app.delete("/api/tutores/:id", requireRole("director"), (req, res) => {
  const usuarios = leer(DB_USERS, []).filter((u) => !(u.id === req.params.id && u.role === "tutor"));
  guardar(DB_USERS, usuarios);
  res.status(204).end();
});

/* ---------------- utilidades ---------------- */
function porcentajeAsistencia(asistencia) {
  if (!Array.isArray(asistencia) || asistencia.length === 0) return null;
  const presentes = asistencia.filter((a) => a.presente).length;
  return Math.round((presentes / asistencia.length) * 1000) / 10;
}

// Oculta información de derivación a los tutores
function filtrarParaTutor(ficha) {
  const { estadoProcedimiento, procedimientoActual, notas, ...resto } = ficha;
  return resto;
}

/* ---------------- fichas ---------------- */
app.get("/api/fichas", requireAuth, (req, res) => {
  let lista = leer(DB_FICHAS, []);
  if (req.session.user.role === "tutor") {
    lista = lista.filter((f) => f.tutorUsername === req.session.user.username).map(filtrarParaTutor);
  }
  lista = lista.map((f) => ({ ...f, porcentajeAsistencia: porcentajeAsistencia(f.asistencia) }));
  res.json(lista);
});

app.post("/api/fichas", requireAuth, (req, res) => {
  const datos = req.body || {};
  if (!datos.urgencia || !["Crítico", "Urgente", "Normal"].includes(datos.urgencia)) {
    return res.status(400).json({ error: "Debes indicar un nivel de urgencia válido (Crítico, Urgente o Normal)." });
  }

  let tutorUsername, tutorNombre;
  if (req.session.user.role === "tutor") {
    tutorUsername = req.session.user.username;
    tutorNombre = req.session.user.nombre;
  } else {
    if (!datos.tutorUsername) return res.status(400).json({ error: "Debes seleccionar un/a tutor/a." });
    const usuarios = leer(DB_USERS, []);
    const t = usuarios.find((u) => u.username === datos.tutorUsername && u.role === "tutor");
    if (!t) return res.status(400).json({ error: "Tutor/a no encontrado/a." });
    tutorUsername = t.username;
    tutorNombre = t.nombre;
  }

  const ficha = {
    id: nuevoId(),
    creadoEn: new Date().toISOString(),
    tutorUsername,
    tutor: tutorNombre,
    jornada: datos.jornada || "",
    fecha: datos.fecha || "",
    modalidad: datos.modalidad || "",
    sesion: datos.sesion || "",
    asistencia: Array.isArray(datos.asistencia) ? datos.asistencia : [],
    temas: datos.temas || "",
    situaciones: datos.situaciones || "",
    dificultades: datos.dificultades || {},
    seguimiento: datos.seguimiento || {},
    urgencia: datos.urgencia,
    estadoProcedimiento: "Pendiente de revisión",
    procedimientoActual: "",
    notas: [],
  };

  const lista = leer(DB_FICHAS, []);
  lista.unshift(ficha);
  guardar(DB_FICHAS, lista);
  res.status(201).json(req.session.user.role === "tutor" ? filtrarParaTutor(ficha) : ficha);
});

// Solo el director administra estado / derivación / notas / urgencia final
app.patch("/api/fichas/:id", requireRole("director"), (req, res) => {
  const lista = leer(DB_FICHAS, []);
  const idx = lista.findIndex((f) => f.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Ficha no encontrada." });
  const permitido = ["estadoProcedimiento", "procedimientoActual", "urgencia", "notas"];
  for (const campo of permitido) {
    if (campo in req.body) lista[idx][campo] = req.body[campo];
  }
  guardar(DB_FICHAS, lista);
  res.json(lista[idx]);
});

app.post("/api/fichas/:id/notas", requireRole("director"), (req, res) => {
  const { texto } = req.body || {};
  if (!texto || !texto.trim()) return res.status(400).json({ error: "La nota no puede estar vacía." });
  const lista = leer(DB_FICHAS, []);
  const idx = lista.findIndex((f) => f.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Ficha no encontrada." });
  lista[idx].notas.push({ texto: texto.trim(), fecha: new Date().toISOString(), autor: req.session.user.nombre });
  guardar(DB_FICHAS, lista);
  res.json(lista[idx]);
});

app.delete("/api/fichas/:id", requireRole("director"), (req, res) => {
  guardar(DB_FICHAS, leer(DB_FICHAS, []).filter((f) => f.id !== req.params.id));
  res.status(204).end();
});

/* ---------------- grupos de estudiantes (para agilizar la asistencia) ---------------- */
app.get("/api/grupos", requireAuth, (req, res) => {
  let lista = leer(DB_GRUPOS, []);
  if (req.session.user.role === "tutor") lista = lista.filter((g) => g.tutorUsername === req.session.user.username);
  res.json(lista);
});

app.post("/api/grupos", requireAuth, (req, res) => {
  const { nombre, estudiantes, tutorUsername } = req.body || {};
  if (!nombre || !nombre.trim()) return res.status(400).json({ error: "El grupo necesita un nombre." });

  let destinoUsername, destinoNombre;
  if (req.session.user.role === "tutor") {
    destinoUsername = req.session.user.username;
    destinoNombre = req.session.user.nombre;
  } else {
    if (!tutorUsername) return res.status(400).json({ error: "Selecciona a qué tutor/a pertenece este grupo." });
    const t = leer(DB_USERS, []).find((u) => u.username === tutorUsername && u.role === "tutor");
    if (!t) return res.status(400).json({ error: "Tutor/a no encontrado/a." });
    destinoUsername = t.username;
    destinoNombre = t.nombre;
  }

  const grupo = {
    id: nuevoId(),
    nombre: nombre.trim(),
    tutorUsername: destinoUsername,
    tutorNombre: destinoNombre,
    estudiantes: (Array.isArray(estudiantes) ? estudiantes : [])
      .map((n) => (typeof n === "string" ? n : n.nombre))
      .filter((n) => n && n.trim())
      .map((n) => ({ id: nuevoId(), nombre: n.trim() })),
    creadoEn: new Date().toISOString(),
  };
  const lista = leer(DB_GRUPOS, []);
  lista.unshift(grupo);
  guardar(DB_GRUPOS, lista);
  res.status(201).json(grupo);
});

app.patch("/api/grupos/:id", requireAuth, (req, res) => {
  const lista = leer(DB_GRUPOS, []);
  const idx = lista.findIndex((g) => g.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Grupo no encontrado." });
  const grupo = lista[idx];
  if (req.session.user.role === "tutor" && grupo.tutorUsername !== req.session.user.username) {
    return res.status(403).json({ error: "No puedes editar el grupo de otro/a tutor/a." });
  }
  if (typeof req.body.nombre === "string" && req.body.nombre.trim()) grupo.nombre = req.body.nombre.trim();
  if (Array.isArray(req.body.estudiantes)) {
    grupo.estudiantes = req.body.estudiantes
      .map((e) => (typeof e === "string" ? { id: nuevoId(), nombre: e } : { id: e.id || nuevoId(), nombre: e.nombre }))
      .filter((e) => e.nombre && e.nombre.trim());
  }
  lista[idx] = grupo;
  guardar(DB_GRUPOS, lista);
  res.json(grupo);
});

app.delete("/api/grupos/:id", requireAuth, (req, res) => {
  const lista = leer(DB_GRUPOS, []);
  const grupo = lista.find((g) => g.id === req.params.id);
  if (!grupo) return res.status(404).end();
  if (req.session.user.role === "tutor" && grupo.tutorUsername !== req.session.user.username) {
    return res.status(403).json({ error: "No puedes eliminar el grupo de otro/a tutor/a." });
  }
  guardar(DB_GRUPOS, lista.filter((g) => g.id !== req.params.id));
  res.status(204).end();
});

/* ---------------- materiales (documentos / presentaciones) ---------------- */
const storageMulter = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, `${nuevoId()}-${file.originalname.replace(/[^a-zA-Z0-9.\-_ ]/g, "_")}`),
});
const uploadMaterial = multer({
  storage: storageMulter,
  limits: { fileSize: 30 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const permitido = /\.(pdf|docx?|pptx?|xlsx?|odt|odp|ods|txt)$/i;
    cb(null, permitido.test(file.originalname));
  },
});

app.get("/api/materiales", requireAuth, (req, res) => {
  res.json(leer(DB_MATERIALES, []));
});

app.post("/api/materiales", requireRole("director"), uploadMaterial.single("archivo"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Archivo no válido. Se aceptan documentos y presentaciones." });
  const material = {
    id: nuevoId(),
    nombre: req.body.nombre || req.file.originalname,
    archivoGuardado: req.file.filename,
    tamano: req.file.size,
    subidoPor: req.session.user.nombre,
    fecha: new Date().toISOString(),
  };
  const lista = leer(DB_MATERIALES, []);
  lista.unshift(material);
  guardar(DB_MATERIALES, lista);
  res.status(201).json(material);
});

app.get("/api/materiales/:id/descargar", requireAuth, (req, res) => {
  const material = leer(DB_MATERIALES, []).find((m) => m.id === req.params.id);
  if (!material) return res.status(404).json({ error: "Material no encontrado." });
  res.download(path.join(UPLOADS_DIR, material.archivoGuardado), material.nombre);
});

app.delete("/api/materiales/:id", requireRole("director"), (req, res) => {
  const lista = leer(DB_MATERIALES, []);
  const material = lista.find((m) => m.id === req.params.id);
  if (material) {
    try { fs.unlinkSync(path.join(UPLOADS_DIR, material.archivoGuardado)); } catch (e) {}
  }
  guardar(DB_MATERIALES, lista.filter((m) => m.id !== req.params.id));
  res.status(204).end();
});

/* ---------------- Excel: exportar / plantilla / importar (solo director) ---------------- */
const COLUMNAS_EXCEL = ["Tutor", "Fecha", "Jornada", "Modalidad", "Sesion", "Temas", "Situaciones", "Urgencia", "Estado", "ProcedimientoActual", "Presentes", "Total"];

async function libroDesdeFilas(filas, nombreHoja) {
  const libro = new ExcelJS.Workbook();
  const hoja = libro.addWorksheet(nombreHoja);
  hoja.columns = COLUMNAS_EXCEL.map((c) => ({ header: c, key: c, width: 22 }));
  hoja.getRow(1).font = { bold: true };
  filas.forEach((f) => hoja.addRow(f));
  return libro.xlsx.writeBuffer();
}

app.get("/api/excel/exportar", requireRole("director"), async (req, res) => {
  const fichas = leer(DB_FICHAS, []);
  const filas = fichas.map((f) => ({
    Tutor: f.tutor,
    Fecha: f.fecha,
    Jornada: f.jornada,
    Modalidad: f.modalidad,
    Sesion: f.sesion,
    Temas: f.temas,
    Situaciones: f.situaciones,
    Urgencia: f.urgencia,
    Estado: f.estadoProcedimiento,
    ProcedimientoActual: f.procedimientoActual,
    Presentes: (f.asistencia || []).filter((a) => a.presente).length,
    Total: (f.asistencia || []).length,
  }));
  const buffer = await libroDesdeFilas(filas, "Fichas");
  res.setHeader("Content-Disposition", "attachment; filename=fichas-dapsi.xlsx");
  res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  res.send(Buffer.from(buffer));
});

app.get("/api/excel/plantilla", requireRole("director"), async (req, res) => {
  const buffer = await libroDesdeFilas([], "Plantilla");
  res.setHeader("Content-Disposition", "attachment; filename=plantilla-dapsi.xlsx");
  res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  res.send(Buffer.from(buffer));
});

const uploadExcel = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });
app.post("/api/excel/importar", requireRole("director"), uploadExcel.single("archivo"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Debes adjuntar un archivo .xlsx" });
  let filas = [];
  try {
    const libro = new ExcelJS.Workbook();
    await libro.xlsx.load(req.file.buffer);
    const hoja = libro.worksheets[0];
    const encabezados = [];
    hoja.getRow(1).eachCell({ includeEmpty: false }, (celda, col) => { encabezados[col] = String(celda.value || "").trim(); });
    hoja.eachRow({ includeEmpty: false }, (fila, numFila) => {
      if (numFila === 1) return;
      const obj = {};
      fila.eachCell({ includeEmpty: false }, (celda, col) => {
        if (encabezados[col]) obj[encabezados[col]] = celda.value != null ? String(celda.value) : "";
      });
      if (Object.keys(obj).length) filas.push(obj);
    });
  } catch (e) {
    return res.status(400).json({ error: "No se pudo leer el archivo Excel." });
  }

  const lista = leer(DB_FICHAS, []);
  let creadas = 0;
  for (const fila of filas) {
    if (!fila.Tutor) continue;
    const presentes = parseInt(fila.Presentes, 10) || 0;
    const total = parseInt(fila.Total, 10) || 0;
    const asistencia = [];
    for (let i = 0; i < total; i++) asistencia.push({ id: nuevoId(), nombre: "", presente: i < presentes, observacion: "" });
    lista.unshift({
      id: nuevoId(),
      creadoEn: new Date().toISOString(),
      tutorUsername: null,
      tutor: String(fila.Tutor),
      jornada: fila.Jornada || "",
      fecha: fila.Fecha || "",
      modalidad: fila.Modalidad || "",
      sesion: fila.Sesion || "",
      asistencia,
      temas: fila.Temas || "",
      situaciones: fila.Situaciones || "",
      dificultades: {},
      seguimiento: {},
      urgencia: ["Crítico", "Urgente", "Normal"].includes(fila.Urgencia) ? fila.Urgencia : "Normal",
      estadoProcedimiento: fila.Estado || "Pendiente de revisión",
      procedimientoActual: fila.ProcedimientoActual || "",
      notas: [],
    });
    creadas++;
  }
  guardar(DB_FICHAS, lista);
  res.json({ creadas });
});

/* ---------------- frontend estático ---------------- */
app.use(express.static(path.join(__dirname, "public")));
app.use((req, res) => {
  if (req.path.startsWith("/api/")) return res.status(404).json({ error: "Ruta no encontrada." });
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Servidor DAPSI escuchando en http://localhost:${PORT}`);
});
