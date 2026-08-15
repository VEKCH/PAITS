// Capa de almacenamiento con dos modos:
//  - Si existe la variable de entorno MONGODB_URI: guarda todo en MongoDB Atlas
//    (persiste para siempre, ideal para producción en Render).
//  - Si NO existe: sigue guardando en archivos JSON locales dentro de /data,
//    tal como funcionaba antes (ideal para probar la app en tu computador
//    sin necesidad de configurar una base de datos).
//
// El resto del servidor no necesita saber cuál de los dos modos está activo:
// solo llama a leer(coleccion, porDefecto) y guardar(coleccion, datos).

const fs = require("fs");
const path = require("path");
const { MongoClient, GridFSBucket, ObjectId } = require("mongodb");

const DATA_DIR = path.join(__dirname, "data");
const USANDO_MONGO = !!process.env.MONGODB_URI;

let clientePromesa = null;
let dbInstancia = null;

async function conectar() {
  if (!USANDO_MONGO) return null;
  if (dbInstancia) return dbInstancia;
  if (!clientePromesa) {
    const cliente = new MongoClient(process.env.MONGODB_URI);
    clientePromesa = cliente.connect().then((c) => {
      dbInstancia = c.db(process.env.MONGODB_DB || "dapsi");
      console.log("Conectado a MongoDB — los datos se guardan de forma persistente.");
      return dbInstancia;
    }).catch((err) => {
      console.error("No se pudo conectar a MongoDB:", err.message);
      clientePromesa = null;
      throw err;
    });
  }
  return clientePromesa;
}

/* ---------------- colecciones tipo "documento único con un arreglo adentro" ---------------- */
// Mantiene exactamente el mismo formato que los archivos JSON de antes
// (un arreglo completo por colección), para no tener que rediseñar el resto
// del servidor.

function rutaArchivo(coleccion) {
  return path.join(DATA_DIR, `${coleccion}.json`);
}

function leerArchivoLocal(coleccion, porDefecto) {
  try {
    const ruta = rutaArchivo(coleccion);
    if (!fs.existsSync(ruta)) return porDefecto;
    return JSON.parse(fs.readFileSync(ruta, "utf-8"));
  } catch (e) {
    return porDefecto;
  }
}

function guardarArchivoLocal(coleccion, datos) {
  fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  const ruta = rutaArchivo(coleccion);
  fs.writeFileSync(ruta, JSON.stringify(datos, null, 2), { mode: 0o600 });
  try { fs.chmodSync(ruta, 0o600); } catch (e) {}
}

async function leer(coleccion, porDefecto) {
  if (!USANDO_MONGO) return leerArchivoLocal(coleccion, porDefecto);
  const db = await conectar();
  const doc = await db.collection("almacen").findOne({ _id: coleccion });
  return doc ? doc.datos : porDefecto;
}

async function guardar(coleccion, datos) {
  if (!USANDO_MONGO) return guardarArchivoLocal(coleccion, datos);
  const db = await conectar();
  await db.collection("almacen").updateOne({ _id: coleccion }, { $set: { datos } }, { upsert: true });
}

/* ---------------- archivos subidos en "Materiales" ---------------- */
// En modo local se guardan en disco (carpeta /uploads), igual que antes.
// En modo MongoDB se guardan con GridFS, que soporta archivos grandes
// dentro de la misma base de datos gratuita.

const UPLOADS_DIR = path.join(__dirname, "uploads");

async function guardarArchivoSubido(nombreGuardado, buffer) {
  if (!USANDO_MONGO) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(UPLOADS_DIR, nombreGuardado), buffer);
    return;
  }
  const db = await conectar();
  const bucket = new GridFSBucket(db, { bucketName: "materiales" });
  await new Promise((resolve, reject) => {
    const stream = bucket.openUploadStream(nombreGuardado);
    stream.on("error", reject);
    stream.on("finish", resolve);
    stream.end(buffer);
  });
}

async function obtenerArchivoSubido(nombreGuardado) {
  if (!USANDO_MONGO) {
    return fs.readFileSync(path.join(UPLOADS_DIR, nombreGuardado));
  }
  const db = await conectar();
  const bucket = new GridFSBucket(db, { bucketName: "materiales" });
  const archivos = await bucket.find({ filename: nombreGuardado }).toArray();
  if (archivos.length === 0) throw new Error("Archivo no encontrado en la base de datos.");
  const chunks = [];
  return new Promise((resolve, reject) => {
    const stream = bucket.openDownloadStream(archivos[0]._id);
    stream.on("data", (c) => chunks.push(c));
    stream.on("error", reject);
    stream.on("end", () => resolve(Buffer.concat(chunks)));
  });
}

async function eliminarArchivoSubido(nombreGuardado) {
  if (!USANDO_MONGO) {
    try { fs.unlinkSync(path.join(UPLOADS_DIR, nombreGuardado)); } catch (e) {}
    return;
  }
  const db = await conectar();
  const bucket = new GridFSBucket(db, { bucketName: "materiales" });
  const archivos = await bucket.find({ filename: nombreGuardado }).toArray();
  for (const a of archivos) {
    try { await bucket.delete(a._id); } catch (e) {}
  }
}

module.exports = {
  USANDO_MONGO,
  conectar,
  leer,
  guardar,
  guardarArchivoSubido,
  obtenerArchivoSubido,
  eliminarArchivoSubido,
  DATA_DIR,
  UPLOADS_DIR,
};
