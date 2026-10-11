NEXUS INFINITY ROYALE — Netlify + GitHub

Archivos incluidos
- index.html
- package.json
- netlify.toml
- netlify/functions/roulette.mjs

Qué hace esta versión
- Usa Netlify Functions + Netlify Blobs para compartir cuentas, perfiles, monedas virtuales gratuitas y clasificaciones.
- El servidor verifica inicios de sesión, recompensas de giro, tiempo activo, canje de códigos y transferencias de puntos entre usuarios.
- Los códigos públicos, anuncios y el ajuste global de Halloween requieren el modo dueño en el servidor.
- Las monedas son puntos de entretenimiento gratuitos; no se ofrecen compras por transferencia de dinero real.

Configuración obligatoria en Netlify
1. En Project configuration > Environment variables, añade una variable llamada OWNER_PIN.
2. Como valor, elige un código privado difícil de adivinar. No lo pongas en index.html ni en GitHub y no lo compartas en el chat.
3. Guarda la variable y vuelve a desplegar el sitio.

Publicación mediante el repositorio GitHub ya conectado
1. Reemplaza el index.html del repositorio por el de esta carpeta.
2. Añade package.json y netlify.toml en la raíz del repositorio.
3. Crea la ruta netlify/functions/roulette.mjs y sube ese archivo ahí.
4. Espera a que Netlify termine el nuevo despliegue y abre la URL del sitio.

Importante
- Este paquete debe desplegarse en Netlify como un sitio enlazado al repositorio; abrir index.html directamente desde el teléfono no activa las funciones en la nube.
- Los datos se guardan en Netlify Blobs. Para un proyecto con muchos usuarios o necesidades de transacciones comerciales, conviene migrar a una base de datos transaccional.
- Antes de usarlo con el público, prueba registro, inicio de sesión, recompensas y transferencias con dos cuentas de prueba.
