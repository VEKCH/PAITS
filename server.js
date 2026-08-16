require("dotenv").config();
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const ExcelJS = require("exceljs");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  WidthType, HeadingLevel, AlignmentType, BorderStyle, ShadingType, PageBreak,
} = require("docx");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const crypto = require("crypto");
const store = require("./store");
const { leer, guardar } = store;

const app = express();
const PORT = process.env.PORT || 3000;
const PRODUCCION = process.env.NODE_ENV === "production";

// Nombres de colecciones (en modo archivo: <nombre>.json dentro de /data;
// en modo MongoDB: documentos dentro de la colección "almacen").
const COL_FICHAS = "fichas";
const COL_USUARIOS = "usuarios";
const COL_MATERIALES = "materiales";
const COL_GRUPOS = "grupos";
const COL_ESTUDIANTES = "estudiantes";
const COL_FICHAS_PERSONALES = "fichas-personales";

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

function nuevoId() {
  return crypto.randomBytes(8).toString("hex");
}

// Envuelve un handler async para que sus errores lleguen a un mensaje claro
// en vez de colgar la petición (por ejemplo, si MongoDB no responde).
function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch((err) => {
    console.error(err);
    if (!res.headersSent) res.status(500).json({ error: "Error interno del servidor. Intenta de nuevo en unos segundos." });
  });
}

/* ---------------- usuarios: crear director inicial si no existe ---------------- */
async function inicializarUsuarios() {
  const usuarios = await leer(COL_USUARIOS, []);
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
    await guardar(COL_USUARIOS, usuarios);
    console.log("========================================================");
    console.log("Cuenta de director creada automáticamente:");
    console.log("  usuario:  director");
    console.log(`  clave:    ${claveInicial}`);
    console.log("Inicia sesión y cámbiala de inmediato desde 'Mi perfil'.");
    console.log("========================================================");
  }
}

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

app.post("/api/login", limitadorLogin, asyncHandler(async (req, res) => {
  const { username, password } = req.body || {};
  const usuarios = await leer(COL_USUARIOS, []);
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
      await guardar(COL_USUARIOS, usuarios);
    }
    return res.status(401).json({ error: "Usuario o clave incorrectos." });
  }

  u.intentosFallidos = 0;
  u.bloqueadoHasta = null;
  usuarios[idx] = u;
  await guardar(COL_USUARIOS, usuarios);

  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: "No se pudo iniciar sesión, intenta de nuevo." });
    req.session.user = { id: u.id, username: u.username, nombre: u.nombre, role: u.role };
    req.session.csrfToken = generarCsrfToken();
    res.json({ ...req.session.user, csrfToken: req.session.csrfToken });
  });
}));

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.status(204).end());
});

app.get("/api/me", requireAuth, (req, res) => {
  if (!req.session.csrfToken) req.session.csrfToken = generarCsrfToken();
  res.json({ ...req.session.user, csrfToken: req.session.csrfToken });
});

app.post("/api/me/password", requireAuth, asyncHandler(async (req, res) => {
  const { actual, nueva } = req.body || {};
  const usuarios = await leer(COL_USUARIOS, []);
  const idx = usuarios.findIndex((u) => u.id === req.session.user.id);
  if (idx === -1) return res.status(404).json({ error: "Usuario no encontrado." });
  if (!bcrypt.compareSync(actual || "", usuarios[idx].passwordHash)) {
    return res.status(400).json({ error: "La clave actual no es correcta." });
  }
  if (!nueva || nueva.length < 6) return res.status(400).json({ error: "La nueva clave debe tener al menos 6 caracteres." });
  usuarios[idx].passwordHash = bcrypt.hashSync(nueva, 10);
  await guardar(COL_USUARIOS, usuarios);
  res.json({ ok: true });
}));

/* ---------------- gestión de tutores (solo director) ---------------- */
app.get("/api/tutores", requireAuth, asyncHandler(async (req, res) => {
  const usuarios = (await leer(COL_USUARIOS, [])).filter((u) => u.role === "tutor");
  res.json(usuarios.map((u) => ({ id: u.id, username: u.username, nombre: u.nombre, activo: u.activo })));
}));

app.post("/api/tutores", requireRole("director"), asyncHandler(async (req, res) => {
  const { username, nombre, password } = req.body || {};
  if (!username || !nombre || !password) return res.status(400).json({ error: "Faltan datos (usuario, nombre o clave)." });
  const usuarios = await leer(COL_USUARIOS, []);
  const uname = username.trim().toLowerCase();
  if (usuarios.some((u) => u.username === uname)) return res.status(409).json({ error: "Ese nombre de usuario ya existe." });
  const tutor = { id: nuevoId(), username: uname, nombre, role: "tutor", passwordHash: bcrypt.hashSync(password, 10), activo: true, intentosFallidos: 0, bloqueadoHasta: null };
  usuarios.push(tutor);
  await guardar(COL_USUARIOS, usuarios);
  res.status(201).json({ id: tutor.id, username: tutor.username, nombre: tutor.nombre, activo: tutor.activo });
}));

app.patch("/api/tutores/:id", requireRole("director"), asyncHandler(async (req, res) => {
  const usuarios = await leer(COL_USUARIOS, []);
  const idx = usuarios.findIndex((u) => u.id === req.params.id && u.role === "tutor");
  if (idx === -1) return res.status(404).json({ error: "Tutor no encontrado." });
  if (typeof req.body.activo === "boolean") usuarios[idx].activo = req.body.activo;
  if (req.body.nombre) usuarios[idx].nombre = req.body.nombre;
  if (req.body.password) usuarios[idx].passwordHash = bcrypt.hashSync(req.body.password, 10);
  await guardar(COL_USUARIOS, usuarios);
  res.json({ id: usuarios[idx].id, username: usuarios[idx].username, nombre: usuarios[idx].nombre, activo: usuarios[idx].activo });
}));

app.delete("/api/tutores/:id", requireRole("director"), asyncHandler(async (req, res) => {
  const usuarios = (await leer(COL_USUARIOS, [])).filter((u) => !(u.id === req.params.id && u.role === "tutor"));
  await guardar(COL_USUARIOS, usuarios);
  res.status(204).end();
}));

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

/* ---------------- fichas de sesión ---------------- */
app.get("/api/fichas", requireAuth, asyncHandler(async (req, res) => {
  let lista = await leer(COL_FICHAS, []);
  if (req.session.user.role === "tutor") {
    lista = lista.filter((f) => f.tutorUsername === req.session.user.username).map(filtrarParaTutor);
  }
  lista = lista.map((f) => ({ ...f, porcentajeAsistencia: porcentajeAsistencia(f.asistencia) }));
  res.json(lista);
}));

app.post("/api/fichas", requireAuth, asyncHandler(async (req, res) => {
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
    const usuarios = await leer(COL_USUARIOS, []);
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

  const lista = await leer(COL_FICHAS, []);
  lista.unshift(ficha);
  await guardar(COL_FICHAS, lista);
  res.status(201).json(req.session.user.role === "tutor" ? filtrarParaTutor(ficha) : ficha);
}));

// Solo el director administra estado / derivación / notas / urgencia final
app.patch("/api/fichas/:id", requireRole("director"), asyncHandler(async (req, res) => {
  const lista = await leer(COL_FICHAS, []);
  const idx = lista.findIndex((f) => f.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Ficha no encontrada." });
  const permitido = ["estadoProcedimiento", "procedimientoActual", "urgencia", "notas"];
  for (const campo of permitido) {
    if (campo in req.body) lista[idx][campo] = req.body[campo];
  }
  await guardar(COL_FICHAS, lista);
  res.json(lista[idx]);
}));

app.post("/api/fichas/:id/notas", requireRole("director"), asyncHandler(async (req, res) => {
  const { texto } = req.body || {};
  if (!texto || !texto.trim()) return res.status(400).json({ error: "La nota no puede estar vacía." });
  const lista = await leer(COL_FICHAS, []);
  const idx = lista.findIndex((f) => f.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Ficha no encontrada." });
  lista[idx].notas.push({ texto: texto.trim(), fecha: new Date().toISOString(), autor: req.session.user.nombre });
  await guardar(COL_FICHAS, lista);
  res.json(lista[idx]);
}));

app.delete("/api/fichas/:id", requireRole("director"), asyncHandler(async (req, res) => {
  await guardar(COL_FICHAS, (await leer(COL_FICHAS, [])).filter((f) => f.id !== req.params.id));
  res.status(204).end();
}));

/* ---------------- grupos de estudiantes (para agilizar la asistencia) ---------------- */
app.get("/api/grupos", requireAuth, asyncHandler(async (req, res) => {
  let lista = await leer(COL_GRUPOS, []);
  if (req.session.user.role === "tutor") lista = lista.filter((g) => g.tutorUsername === req.session.user.username);
  res.json(lista);
}));

app.post("/api/grupos", requireAuth, asyncHandler(async (req, res) => {
  const { nombre, estudiantes, tutorUsername } = req.body || {};
  if (!nombre || !nombre.trim()) return res.status(400).json({ error: "El grupo necesita un nombre." });

  let destinoUsername, destinoNombre;
  if (req.session.user.role === "tutor") {
    destinoUsername = req.session.user.username;
    destinoNombre = req.session.user.nombre;
  } else {
    if (!tutorUsername) return res.status(400).json({ error: "Selecciona a qué tutor/a pertenece este grupo." });
    const t = (await leer(COL_USUARIOS, [])).find((u) => u.username === tutorUsername && u.role === "tutor");
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
  const lista = await leer(COL_GRUPOS, []);
  lista.unshift(grupo);
  await guardar(COL_GRUPOS, lista);
  res.status(201).json(grupo);
}));

app.patch("/api/grupos/:id", requireAuth, asyncHandler(async (req, res) => {
  const lista = await leer(COL_GRUPOS, []);
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
  await guardar(COL_GRUPOS, lista);
  res.json(grupo);
}));

app.delete("/api/grupos/:id", requireAuth, asyncHandler(async (req, res) => {
  const lista = await leer(COL_GRUPOS, []);
  const grupo = lista.find((g) => g.id === req.params.id);
  if (!grupo) return res.status(404).end();
  if (req.session.user.role === "tutor" && grupo.tutorUsername !== req.session.user.username) {
    return res.status(403).json({ error: "No puedes eliminar el grupo de otro/a tutor/a." });
  }
  await guardar(COL_GRUPOS, lista.filter((g) => g.id !== req.params.id));
  res.status(204).end();
}));

/* ---------------- estudiantes (registro y estado de casos) ---------------- */
// El registro completo (crear/editar/estado del caso) es exclusivo del director.
// Los tutores solo reciben una versión liviana de SUS estudiantes asignados
// (sin estadoCaso/procedimientoActual/notasCaso), necesaria para poder elegir
// a quién corresponde una ficha personal — no ven el registro completo ni el
// de otros tutores.

async function calcularAsistenciaPorNombre(nombreEstudiante) {
  const nombreNorm = (nombreEstudiante || "").trim().toLowerCase();
  if (!nombreNorm) return { porcentaje: null, presentes: 0, total: 0 };
  const fichas = await leer(COL_FICHAS, []);
  let presentes = 0, total = 0;
  fichas.forEach((f) => {
    (f.asistencia || []).forEach((a) => {
      if ((a.nombre || "").trim().toLowerCase() === nombreNorm) {
        total++;
        if (a.presente) presentes++;
      }
    });
  });
  return { porcentaje: total > 0 ? Math.round((presentes / total) * 1000) / 10 : null, presentes, total };
}

function filtrarEstudianteParaTutor(est) {
  const { estadoCaso, procedimientoActual, notasCaso, ...resto } = est;
  return resto;
}

async function conAsistencia(est) {
  const r = await calcularAsistenciaPorNombre(est.nombre);
  return { ...est, porcentajeAsistencia: r.porcentaje, sesionesTotales: r.total, sesionesPresente: r.presentes };
}

app.get("/api/estudiantes", requireAuth, asyncHandler(async (req, res) => {
  let lista = await leer(COL_ESTUDIANTES, []);
  if (req.session.user.role === "tutor") {
    lista = lista.filter((e) => e.tutorUsername === req.session.user.username).map(filtrarEstudianteParaTutor);
  }
  lista = await Promise.all(lista.map(conAsistencia));
  res.json(lista);
}));

app.get("/api/estudiantes/:id", requireAuth, asyncHandler(async (req, res) => {
  const estudiante = (await leer(COL_ESTUDIANTES, [])).find((e) => e.id === req.params.id);
  if (!estudiante) return res.status(404).json({ error: "Estudiante no encontrado." });
  if (req.session.user.role === "tutor" && estudiante.tutorUsername !== req.session.user.username) {
    return res.status(403).json({ error: "No puedes ver la información de un/a estudiante que no es tuyo/a." });
  }
  const esTutor = req.session.user.role === "tutor";
  const nombreNorm = estudiante.nombre.trim().toLowerCase();
  const sesiones = (await leer(COL_FICHAS, []))
    .filter((f) => (f.asistencia || []).some((a) => (a.nombre || "").trim().toLowerCase() === nombreNorm))
    .map((f) => {
      const asist = f.asistencia.find((a) => (a.nombre || "").trim().toLowerCase() === nombreNorm);
      return { id: f.id, fecha: f.fecha, tutor: f.tutor, sesion: f.sesion, presente: asist ? asist.presente : null, situaciones: f.situaciones, temas: f.temas };
    });
  const fichasPersonales = (await leer(COL_FICHAS_PERSONALES, [])).filter((fp) => fp.estudianteId === estudiante.id);
  const asis = await calcularAsistenciaPorNombre(estudiante.nombre);
  res.json({
    estudiante: esTutor ? filtrarEstudianteParaTutor(estudiante) : estudiante,
    porcentajeAsistencia: asis.porcentaje,
    sesionesTotales: asis.total,
    sesionesPresente: asis.presentes,
    sesiones,
    fichasPersonales,
  });
}));

app.post("/api/estudiantes", requireRole("director"), asyncHandler(async (req, res) => {
  const { nombre, jornada, carrera, tutorUsername } = req.body || {};
  if (!nombre || !nombre.trim()) return res.status(400).json({ error: "El nombre del/de la estudiante es obligatorio." });
  if (!tutorUsername) return res.status(400).json({ error: "Debes asignar un/a tutor/a." });
  const t = (await leer(COL_USUARIOS, [])).find((u) => u.username === tutorUsername && u.role === "tutor");
  if (!t) return res.status(400).json({ error: "Tutor/a no encontrado/a." });
  const estudiante = {
    id: nuevoId(),
    nombre: nombre.trim(),
    jornada: jornada || "",
    carrera: carrera || "",
    tutorUsername: t.username,
    tutorNombre: t.nombre,
    estado: "Activo",
    estadoCaso: "Sin seguimiento",
    procedimientoActual: "",
    notasCaso: [],
    creadoEn: new Date().toISOString(),
  };
  const lista = await leer(COL_ESTUDIANTES, []);
  lista.unshift(estudiante);
  await guardar(COL_ESTUDIANTES, lista);
  res.status(201).json(estudiante);
}));

app.patch("/api/estudiantes/:id", requireRole("director"), asyncHandler(async (req, res) => {
  const lista = await leer(COL_ESTUDIANTES, []);
  const idx = lista.findIndex((e) => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Estudiante no encontrado." });
  const permitido = ["nombre", "jornada", "carrera", "estado", "estadoCaso", "procedimientoActual", "tutorUsername"];
  for (const campo of permitido) {
    if (campo in req.body) lista[idx][campo] = req.body[campo];
  }
  if (req.body.tutorUsername) {
    const t = (await leer(COL_USUARIOS, [])).find((u) => u.username === req.body.tutorUsername && u.role === "tutor");
    if (t) lista[idx].tutorNombre = t.nombre;
  }
  await guardar(COL_ESTUDIANTES, lista);
  res.json(lista[idx]);
}));

app.post("/api/estudiantes/:id/notas", requireRole("director"), asyncHandler(async (req, res) => {
  const { texto } = req.body || {};
  if (!texto || !texto.trim()) return res.status(400).json({ error: "La nota no puede estar vacía." });
  const lista = await leer(COL_ESTUDIANTES, []);
  const idx = lista.findIndex((e) => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Estudiante no encontrado." });
  lista[idx].notasCaso.push({ texto: texto.trim(), fecha: new Date().toISOString(), autor: req.session.user.nombre });
  await guardar(COL_ESTUDIANTES, lista);
  res.json(lista[idx]);
}));

app.delete("/api/estudiantes/:id", requireRole("director"), asyncHandler(async (req, res) => {
  await guardar(COL_ESTUDIANTES, (await leer(COL_ESTUDIANTES, [])).filter((e) => e.id !== req.params.id));
  res.status(204).end();
}));

/* ---------------- fichas personales (perfil del/de la estudiante, no de sesión) ---------------- */
app.get("/api/fichas-personales", requireAuth, asyncHandler(async (req, res) => {
  let lista = await leer(COL_FICHAS_PERSONALES, []);
  if (req.session.user.role === "tutor") lista = lista.filter((fp) => fp.tutorUsername === req.session.user.username);
  res.json(lista);
}));

app.post("/api/fichas-personales", requireAuth, asyncHandler(async (req, res) => {
  const datos = req.body || {};
  if (!datos.estudianteId) return res.status(400).json({ error: "Selecciona a qué estudiante corresponde esta ficha." });
  const estudiante = (await leer(COL_ESTUDIANTES, [])).find((e) => e.id === datos.estudianteId);
  if (!estudiante) return res.status(400).json({ error: "Estudiante no encontrado." });

  let tutorUsername, tutorNombre;
  if (req.session.user.role === "tutor") {
    if (estudiante.tutorUsername !== req.session.user.username) {
      return res.status(403).json({ error: "Solo puedes crear fichas personales de tus propios/as estudiantes." });
    }
    tutorUsername = req.session.user.username;
    tutorNombre = req.session.user.nombre;
  } else {
    tutorUsername = estudiante.tutorUsername;
    tutorNombre = estudiante.tutorNombre;
  }

  const ficha = {
    id: nuevoId(),
    estudianteId: estudiante.id,
    estudianteNombre: estudiante.nombre,
    tutorUsername,
    tutorNombre,
    fecha: datos.fecha || new Date().toISOString().slice(0, 10),
    motivoIngreso: datos.motivoIngreso || "",
    situacionAcademica: datos.situacionAcademica || "",
    situacionPersonalFamiliar: datos.situacionPersonalFamiliar || "",
    fortalezas: datos.fortalezas || "",
    dificultades: datos.dificultades || {},
    observaciones: datos.observaciones || "",
    urgencia: ["Crítico", "Urgente", "Normal"].includes(datos.urgencia) ? datos.urgencia : "Normal",
    creadoEn: new Date().toISOString(),
  };
  const lista = await leer(COL_FICHAS_PERSONALES, []);
  lista.unshift(ficha);
  await guardar(COL_FICHAS_PERSONALES, lista);
  res.status(201).json(ficha);
}));

app.delete("/api/fichas-personales/:id", requireAuth, asyncHandler(async (req, res) => {
  const lista = await leer(COL_FICHAS_PERSONALES, []);
  const ficha = lista.find((fp) => fp.id === req.params.id);
  if (!ficha) return res.status(404).end();
  if (req.session.user.role === "tutor" && ficha.tutorUsername !== req.session.user.username) {
    return res.status(403).json({ error: "No puedes eliminar la ficha personal de otro/a tutor/a." });
  }
  await guardar(COL_FICHAS_PERSONALES, lista.filter((fp) => fp.id !== req.params.id));
  res.status(204).end();
}));

/* ---------------- materiales (documentos / presentaciones) ---------------- */
// El contenido del archivo se guarda vía store.js: en disco si trabajas local,
// o en MongoDB (GridFS) si configuraste MONGODB_URI — así los materiales
// tampoco se pierden al reiniciar el servicio en producción.
const uploadMaterial = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 30 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const permitido = /\.(pdf|docx?|pptx?|xlsx?|odt|odp|ods|txt)$/i;
    cb(null, permitido.test(file.originalname));
  },
});

app.get("/api/materiales", requireAuth, asyncHandler(async (req, res) => {
  res.json(await leer(COL_MATERIALES, []));
}));

app.post("/api/materiales", requireRole("director"), uploadMaterial.single("archivo"), asyncHandler(async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Archivo no válido. Se aceptan documentos y presentaciones." });
  const nombreGuardado = `${nuevoId()}-${req.file.originalname.replace(/[^a-zA-Z0-9.\-_ ]/g, "_")}`;
  await store.guardarArchivoSubido(nombreGuardado, req.file.buffer);
  const material = {
    id: nuevoId(),
    nombre: req.body.nombre || req.file.originalname,
    archivoGuardado: nombreGuardado,
    tamano: req.file.size,
    subidoPor: req.session.user.nombre,
    fecha: new Date().toISOString(),
  };
  const lista = await leer(COL_MATERIALES, []);
  lista.unshift(material);
  await guardar(COL_MATERIALES, lista);
  res.status(201).json(material);
}));

app.get("/api/materiales/:id/descargar", requireAuth, asyncHandler(async (req, res) => {
  const material = (await leer(COL_MATERIALES, [])).find((m) => m.id === req.params.id);
  if (!material) return res.status(404).json({ error: "Material no encontrado." });
  try {
    const buffer = await store.obtenerArchivoSubido(material.archivoGuardado);
    res.setHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(material.nombre)}"`);
    res.send(buffer);
  } catch (e) {
    res.status(404).json({ error: "No se pudo encontrar el contenido del archivo." });
  }
}));

app.delete("/api/materiales/:id", requireRole("director"), asyncHandler(async (req, res) => {
  const lista = await leer(COL_MATERIALES, []);
  const material = lista.find((m) => m.id === req.params.id);
  if (material) await store.eliminarArchivoSubido(material.archivoGuardado);
  await guardar(COL_MATERIALES, lista.filter((m) => m.id !== req.params.id));
  res.status(204).end();
}));

/* ---------------- Word: exportar fichas (individuales y en lote) ---------------- */
const COLOR_ACENTO = "2F5D50";
const COLOR_SUAVE = "5B6355";

function tituloDoc(texto) {
  return new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { after: 120 }, pageBreakBefore: false, children: [new TextRun({ text: texto, color: COLOR_ACENTO })] });
}
function subtitulo(texto) {
  return new Paragraph({ spacing: { after: 160 }, children: [new TextRun({ text: texto, color: COLOR_SUAVE, size: 20 })] });
}
function seccion(texto) {
  return new Paragraph({ heading: HeadingLevel.HEADING_3, spacing: { before: 200, after: 60 }, children: [new TextRun({ text: texto, color: COLOR_ACENTO })] });
}
function parrafo(texto) {
  return new Paragraph({ spacing: { after: 100 }, children: [new TextRun({ text: texto && texto.trim() ? texto : "—" })] });
}
function tablaAsistencia(asistencia) {
  const filas = [
    new TableRow({
      tableHeader: true,
      children: ["Estudiante", "Presente", "Observación"].map((h) => new TableCell({
        shading: { type: ShadingType.CLEAR, color: "auto", fill: COLOR_ACENTO },
        children: [new Paragraph({ children: [new TextRun({ text: h, bold: true, color: "FFFFFF", size: 18 })] })],
        margins: { top: 80, bottom: 80, left: 80, right: 80 },
      })),
    }),
    ...(asistencia || []).map((a) => new TableRow({
      children: [
        new TableCell({ children: [new Paragraph(a.nombre || "(sin nombre)")], margins: { top: 60, bottom: 60, left: 80, right: 80 } }),
        new TableCell({ children: [new Paragraph(a.presente ? "Sí" : "No")], margins: { top: 60, bottom: 60, left: 80, right: 80 } }),
        new TableCell({ children: [new Paragraph(a.observacion || "")], margins: { top: 60, bottom: 60, left: 80, right: 80 } }),
      ],
    })),
  ];
  return new Table({ width: { size: 9000, type: WidthType.DXA }, rows: filas });
}
function listaDificultades(dif) {
  const nombres = { academica: "Académica", emocional: "Emocional / psicosocial", social: "Social o de integración", tramites: "Desconocimiento de trámites/servicios", otra: dif && dif.otraTexto ? `Otra: ${dif.otraTexto}` : "Otra" };
  const activas = Object.entries(nombres).filter(([k]) => dif && dif[k]);
  if (activas.length === 0) return parrafo("Ninguna registrada.");
  return activas.map(([, texto]) => new Paragraph({ bullet: { level: 0 }, spacing: { after: 40 }, children: [new TextRun(texto)] }));
}

function bloqueFichaSesion(f, incluirDerivacion) {
  const bloque = [
    tituloDoc("Ficha de sesión"),
    subtitulo(`${f.tutor || "Tutor/a sin nombre"} · Sesión ${f.sesion || "—"} · ${f.fecha || "sin fecha"} · ${f.jornada || "sin jornada"} · ${f.modalidad || "sin modalidad"}`),
    seccion("Asistencia"),
    tablaAsistencia(f.asistencia),
    seccion("Temas abordados"),
    parrafo(f.temas),
    seccion("Situaciones relevantes, acuerdos y solicitudes"),
    parrafo(f.situaciones),
    seccion("Dificultades detectadas"),
    ...[].concat(listaDificultades(f.dificultades)),
    seccion("Seguimiento"),
    parrafo(`¿Cómo se sintió el/la tutor/a?: ${f.seguimiento?.comoSeSintio || "—"}`),
    parrafo(`¿Recursos suficientes?: ${f.seguimiento?.recursosSuficientes || "—"} · ¿Manejó las dudas?: ${f.seguimiento?.logroManejarDudas || "—"} · ¿Necesita apoyo?: ${f.seguimiento?.necesitaApoyo || "—"}`),
    parrafo(`Comentarios al equipo coordinador: ${f.seguimiento?.comentariosCoordinador || "—"}`),
    seccion("Clasificación"),
    parrafo(`Urgencia: ${f.urgencia}`),
  ];
  if (incluirDerivacion) {
    bloque.push(
      seccion("Procedimiento / derivación"),
      parrafo(`Estado: ${f.estadoProcedimiento || "—"}`),
      parrafo(`Procedimiento actual: ${f.procedimientoActual || "—"}`),
      ...(f.notas && f.notas.length ? f.notas.map((n) => parrafo(`• ${n.texto} (${n.autor || ""}, ${new Date(n.fecha).toLocaleDateString("es-CL")})`)) : [parrafo("Sin notas registradas.")])
    );
  }
  return bloque;
}

function bloqueFichaPersonal(fp) {
  return [
    tituloDoc(`Ficha personal — ${fp.estudianteNombre}`),
    subtitulo(`Tutor/a: ${fp.tutorNombre} · Fecha: ${fp.fecha}`),
    seccion("Motivo de ingreso al programa"),
    parrafo(fp.motivoIngreso),
    seccion("Situación académica"),
    parrafo(fp.situacionAcademica),
    seccion("Situación personal / familiar"),
    parrafo(fp.situacionPersonalFamiliar),
    seccion("Fortalezas y recursos"),
    parrafo(fp.fortalezas),
    seccion("Dificultades detectadas"),
    ...[].concat(listaDificultades(fp.dificultades)),
    seccion("Observaciones y seguimiento"),
    parrafo(fp.observaciones),
    seccion("Clasificación"),
    parrafo(`Urgencia: ${fp.urgencia}`),
  ];
}

async function enviarDocx(res, children, nombreArchivo) {
  const doc = new Document({ sections: [{ properties: {}, children }] });
  const buffer = await Packer.toBuffer(doc);
  res.setHeader("Content-Disposition", `attachment; filename="${nombreArchivo}"`);
  res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
  res.send(buffer);
}

app.get("/api/fichas/:id/word", requireAuth, asyncHandler(async (req, res) => {
  const f = (await leer(COL_FICHAS, [])).find((x) => x.id === req.params.id);
  if (!f) return res.status(404).json({ error: "Ficha no encontrada." });
  const esDirector = req.session.user.role === "director";
  if (!esDirector && f.tutorUsername !== req.session.user.username) {
    return res.status(403).json({ error: "No puedes descargar la ficha de otro/a tutor/a." });
  }
  await enviarDocx(res, bloqueFichaSesion(f, esDirector), `ficha-sesion-${(f.tutor || "").replace(/\s+/g, "_")}-${f.fecha}.docx`);
}));

app.get("/api/fichas-personales/:id/word", requireAuth, asyncHandler(async (req, res) => {
  const fp = (await leer(COL_FICHAS_PERSONALES, [])).find((x) => x.id === req.params.id);
  if (!fp) return res.status(404).json({ error: "Ficha no encontrada." });
  if (req.session.user.role === "tutor" && fp.tutorUsername !== req.session.user.username) {
    return res.status(403).json({ error: "No puedes descargar la ficha de otro/a tutor/a." });
  }
  await enviarDocx(res, bloqueFichaPersonal(fp), `ficha-personal-${fp.estudianteNombre.replace(/\s+/g, "_")}-${fp.fecha}.docx`);
}));

app.get("/api/word/fichas", requireRole("director"), asyncHandler(async (req, res) => {
  const fichas = await leer(COL_FICHAS, []);
  if (fichas.length === 0) return res.status(400).json({ error: "No hay fichas de sesión para exportar." });
  let children = [];
  fichas.forEach((f, i) => {
    const bloque = bloqueFichaSesion(f, true);
    if (i > 0) bloque[0] = new Paragraph({ heading: HeadingLevel.HEADING_1, pageBreakBefore: true, spacing: { after: 120 }, children: [new TextRun({ text: "Ficha de sesión", color: COLOR_ACENTO })] });
    children = children.concat(bloque);
  });
  await enviarDocx(res, children, "fichas-sesion-dapsi.docx");
}));

app.get("/api/word/fichas-personales", requireRole("director"), asyncHandler(async (req, res) => {
  const fichas = await leer(COL_FICHAS_PERSONALES, []);
  if (fichas.length === 0) return res.status(400).json({ error: "No hay fichas personales para exportar." });
  let children = [];
  fichas.forEach((fp, i) => {
    const bloque = bloqueFichaPersonal(fp);
    if (i > 0) bloque[0] = new Paragraph({ heading: HeadingLevel.HEADING_1, pageBreakBefore: true, spacing: { after: 120 }, children: [new TextRun({ text: `Ficha personal — ${fp.estudianteNombre}`, color: COLOR_ACENTO })] });
    children = children.concat(bloque);
  });
  await enviarDocx(res, children, "fichas-personales-dapsi.docx");
}));

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

app.get("/api/excel/exportar", requireRole("director"), asyncHandler(async (req, res) => {
  const fichas = await leer(COL_FICHAS, []);
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
}));

app.get("/api/excel/plantilla", requireRole("director"), asyncHandler(async (req, res) => {
  const buffer = await libroDesdeFilas([], "Plantilla");
  res.setHeader("Content-Disposition", "attachment; filename=plantilla-dapsi.xlsx");
  res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  res.send(Buffer.from(buffer));
}));

const uploadExcel = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });
app.post("/api/excel/importar", requireRole("director"), uploadExcel.single("archivo"), asyncHandler(async (req, res) => {
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

  const lista = await leer(COL_FICHAS, []);
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
  await guardar(COL_FICHAS, lista);
  res.json({ creadas });
}));

/* ---------------- frontend estático ---------------- */
app.use(express.static(path.join(__dirname, "public")));
app.use((req, res) => {
  if (req.path.startsWith("/api/")) return res.status(404).json({ error: "Ruta no encontrada." });
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

/* ---------------- arranque ---------------- */
(async () => {
  console.log(store.USANDO_MONGO ? "Modo de almacenamiento: MongoDB (persistente)." : "Modo de almacenamiento: archivos locales en /data (no persiste en Render sin disco pagado).");
  try {
    await inicializarUsuarios();
  } catch (e) {
    console.error("No se pudo inicializar el usuario director:", e.message);
  }
  app.listen(PORT, () => {
    console.log(`Servidor DAPSI escuchando en http://localhost:${PORT}`);
  });
})();
