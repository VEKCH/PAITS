# Plataforma DAPSI · UCSH

Aplicación web para registrar fichas de sesión, clasificar casos manualmente por urgencia (Normal / Urgente / Crítico), hacer seguimiento de derivaciones, calcular % de asistencia, gestionar materiales (documentos y presentaciones) y traspasar información a Excel.

## Roles

- **Director/a**: ve todos los casos (agrupados por tutor/a), gestiona el estado y la derivación de cada caso, administra cuentas de tutores, sube materiales, exporta/importa Excel.
- **Tutor/a**: solo ve sus propias fichas y su % de asistencia. **No ve** el estado del procedimiento, el destino de la derivación ni las notas de seguimiento — esa información es exclusiva del equipo director.

## 1. Uso local (para probarla en tu computador)

Necesitas tener instalado [Node.js](https://nodejs.org) (versión 18 o superior).

```bash
cd dapsi-app
npm install
npm start
```

Abre `http://localhost:3000` en tu navegador.

**La primera vez**, el sistema crea automáticamente una cuenta de director:

```
usuario: director
clave:   director123
```

Inicia sesión con esos datos y cambia la clave de inmediato desde "Cambiar clave" (arriba a la derecha). Desde la pestaña **Tutores** puedes crear las cuentas del resto del equipo.

Los datos (fichas, usuarios, materiales) se guardan en la carpeta `data/` y los archivos subidos en `uploads/` — mientras no borres esas carpetas, la información persiste entre reinicios.

## 2. Publicarla en internet (para que el equipo la use desde cualquier lugar)

Esto requiere subir el proyecto a un servicio de hosting. La opción más simple y con capa gratuita es **Render**. Railway o Fly.io funcionan de forma muy similar.

### Paso a paso con Render

1. Crea una cuenta gratuita en [render.com](https://render.com).
2. Sube esta carpeta a un repositorio de GitHub (puedes arrastrar los archivos directamente en github.com si no usas Git desde la terminal).
3. En Render: **New + → Web Service** y conecta ese repositorio.
4. Configura:
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
5. En la sección **Environment**, agrega esta variable:
   - `SESSION_SECRET` = un texto largo y aleatorio inventado por ti (por ejemplo, generado en https://1password.com/password-generator/).
6. **Importante — persistencia de datos**: por defecto, el disco de estos servicios se borra en cada despliegue. Para que las fichas y materiales no se pierdan, agrega un **Persistent Disk** (Render lo ofrece gratis desde el panel del servicio) montado en la ruta `/opt/render/project/src/data` y otro en `.../uploads`, o monta un único disco en la raíz del proyecto. Si tu plan no incluye disco persistente, considera Railway (ofrece volúmenes) como alternativa.
7. Haz clic en **Create Web Service**. Cuando termine el despliegue, Render te da una URL pública (algo como `https://dapsi-ucsh.onrender.com`) — esa es la dirección que comparten director y tutores.

### Alternativa: Railway

1. Cuenta en [railway.app](https://railway.app).
2. **New Project → Deploy from GitHub repo**.
3. Añade un **Volume** y móntalo en `/app/data` y `/app/uploads` para que los datos persistan.
4. Define la variable de entorno `SESSION_SECRET`.
5. Railway detecta automáticamente `npm start`.

## 3. Después del primer despliegue

- Inicia sesión como `director` / `director123` y cambia la clave inmediatamente.
- Ve a **Tutores** y crea una cuenta para cada tutor/a del programa.
- Comparte la URL pública con el equipo — cada persona inicia sesión con su propio usuario.

## Estructura del proyecto

```
dapsi-app/
  server.js          → backend (API, login, lógica de negocio)
  public/index.html  → toda la interfaz (React, sin paso de compilación)
  data/               → fichas.json, usuarios.json, materiales.json (se crea solo)
  uploads/             → archivos subidos en "Materiales" (se crea solo)
```

## Grupos de estudiantes (para agilizar la asistencia)

Antes había que escribir el nombre de cada estudiante en cada ficha. Ahora:

1. Ve a la pestaña **Grupos** y crea uno (por ejemplo "Grupo A — Lunes") pegando los nombres, uno por línea.
2. Al crear una **Nueva ficha**, elige ese grupo en el desplegable de la sección "Asistencia" — la lista se carga automáticamente con todos marcados como presentes, y solo tienes que desmarcar a quien faltó.
3. Puedes editar la lista de un grupo en cualquier momento desde la misma pestaña, sin afectar las fichas ya guardadas.

Cada tutor/a solo ve y administra sus propios grupos. El director puede crear o editar el grupo de cualquier tutor/a eligiéndolo al crear el grupo.

## Excel

- **Exportar**: descarga un `.xlsx` con todas las fichas.
- **Plantilla**: descarga un Excel vacío con las columnas correctas para importar.
- **Importar**: sube un `.xlsx` con esas columnas (Tutor, Fecha, Jornada, Modalidad, Sesion, Temas, Situaciones, Urgencia, Estado, ProcedimientoActual, Presentes, Total) y crea fichas en lote.

## Seguridad incluida

- **Claves cifradas** con bcrypt (nunca se guardan en texto plano).
- **Bloqueo por intentos fallidos**: tras 5 intentos de clave incorrecta, la cuenta se bloquea 15 minutos.
- **Límite de peticiones (rate limiting)**: por IP, tanto en el login como en el resto de la API, para dificultar ataques automatizados.
- **Protección CSRF**: cada sesión recibe un token que se exige en toda operación que modifica datos (crear, editar, eliminar, subir archivos). Si ves el error "Token de seguridad inválido o expirado", simplemente recarga la página.
- **Cabeceras de seguridad** (Helmet): protección contra clickjacking, sniffing de tipo MIME, etc.
- **HTTPS forzado en producción**: si despliegas con `NODE_ENV=production`, cualquier acceso por HTTP se redirige automáticamente a HTTPS (aprovechando el certificado que entrega Render/Railway).
- **Archivos de datos con permisos restringidos** (`chmod 600`): en el servidor, solo el propio proceso puede leer `data/usuarios.json` y `data/fichas.json`.
- **Aislamiento de derivaciones**: el backend nunca envía esa información a las cuentas de tutor, ni siquiera si acceden directamente a la API.

### Variable de entorno importante para producción

Al desplegar, define además de `SESSION_SECRET`:

```
NODE_ENV=production
```

Esto activa la redirección a HTTPS y hace que las cookies de sesión solo se envíen por conexión segura.

### Lo que sigue sin cubrir (a considerar si el uso crece)

- Los datos se guardan en archivos JSON planos en el disco del servidor (no cifrados en reposo). Alguien con acceso directo al servidor podría leerlos.
- No hay copias de respaldo automáticas — si el disco se pierde, se pierden los datos. Conviene programar respaldos periódicos del contenido de `data/` y `uploads/`.
- No hay recuperación de clave por correo (el director debe restablecer la clave manualmente desde "Tutores" si alguien la olvida).
- Para un uso institucional prolongado con datos de violencia o salud mental, recomendamos consultar con el equipo de TI / protección de datos de la UCSH, y evaluar migrar a una base de datos real (PostgreSQL) con cifrado en reposo.
