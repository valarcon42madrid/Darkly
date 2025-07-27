# darkly

*Darkly es un proyecto orientado a la introducción en la ciberseguridad web. Consiste en auditar un sitio web vulnerable con el objetivo de aprender a identificar y entender fallos comunes de seguridad. A lo largo del ejercicio se exploran vulnerabilidades reales basadas en el OWASP, como inyecciones, XSS y fallos de control de acceso. Este proyecto busca concienciar sobre los riesgos que enfrentan las aplicaciones en internet y mostrar cómo muchos frameworks modernos mitigan estos problemas de forma automática.*

*La web se encuentra en una ISO llamada Darkly_i365.iso.*   https://cdn.intra.42.fr/isos/Darkly_i386.iso

**Las vulnerabilidades son:**

1. Brute Force Login via GET Parameters

El formulario envía credenciales por URL (GET), lo que expone usuario/contraseña en logs y permite automatizar ataques de fuerza bruta fácilmente, especialmente si no hay protección (captcha, rate limit, bloqueo).

2. Boolean-Based Blind SQL Injection

El servidor evalúa directamente condiciones lógicas inyectadas por el usuario (1 AND 1=1), lo que permite inferir bit a bit información de la base de datos sin errores visibles, solo por cambios en la respuesta.

3. LFI (Local File Inclusion) con Null Byte Injection

El servidor incluye archivos basándose en parámetros manipulables (?page=...). El uso de %00 (null byte) permite truncar cadenas, ignorando extensiones forzadas y accediendo a archivos sensibles del sistema.

4. Insecure Deserialization

El servidor procesa datos que el cliente controla, deserializándolos sin validación. Esto puede ejecutar código o lógica no intencionada si se manipulan estructuras o propiedades sensibles.

5. Information Disclosure via Exposed Directories

Directorios listados en robots.txt o accesibles sin protección permiten al atacante recorrer carpetas ocultas, ver archivos internos como readme, .htpasswd, configuraciones o flags.

6. Sensitive Information Disclosure via Publicly Accessible Files

Archivos sensibles (.htpasswd, configuraciones, hashes) están en rutas accesibles públicamente. El atacante puede leerlos y usarlos para obtener credenciales o información crítica.

7. Client-Side Hidden Field Manipulation

Campos hidden en formularios (como email=admin) pueden ser modificados por el usuario y el servidor los acepta sin validación, lo que permite suplantar identidades o acceder a funciones restringidas.

8. Client-Side Input Tampering

Inputs como menús desplegables (select) se manipulan en el navegador para enviar valores fuera del rango permitido. El servidor los acepta sin validación, lo que altera la lógica interna.

9. Access Control Bypass via Manipulation of HTTP Headers

El servidor confía en cabeceras como Referer o User-Agent para controlar el acceso. Estas son fácilmente modificables por el cliente, lo que permite evadir restricciones y acceder a recursos protegidos.

10. Autenticación basada en cookies manipulables / Validación débil de tokens

Cookies como I_am_admin=md5("false") se pueden modificar por el cliente sin firma o cifrado. El servidor confía en ese valor, permitiendo escalar privilegios cambiando la cookie.

11. Insecure File Upload (Subida de archivos insegura)

El servidor permite subir archivos sin validar correctamente su contenido o extensión. El atacante sube código (ej. PHP) disfrazado de imagen, que luego se ejecuta si se accede directamente al archivo.

12. Open Redirect

Una funcionalidad de redirección permite enviar al usuario a cualquier URL pasada como parámetro (?site=...). El servidor no valida el destino, facilitando ataques de phishing o redirección maliciosa.

13. SQL Injection (Union-Based SQL Injection)

Los parámetros de usuario se insertan directamente en consultas SQL sin sanitización. Esto permite modificar la consulta, acceder a estructuras internas (information_schema) y extraer datos arbitrarios.

14. Cross-Site Scripting (XSS) mediante inyección en <object> con data: URI

El atacante inserta un data:text/html,<script>... dentro del atributo data de una etiqueta <object>, que el navegador interpreta como HTML, ejecutando JavaScript arbitrario (XSS).

15. Cross-Site Scripting mediante Stored XSS

Stored XSS ocurre cuando una aplicación web almacena datos introducidos por un usuario sin sanitizarlos (por ejemplo, en una base de datos), y luego los muestra en una página web sin escapar el contenido HTML o JavaScript, permitiendo así la ejecución de scripts maliciosos cuando otros usuarios acceden a esa página.

----------------------------------------------------

	NOMBRES DE LAS VULNERABILIDADES Y PREVENCIÓN:

----------------------------------------------------
**1: Brute Force Login via GET Parameters**


🛡️ Cómo se debe solucionar esta vulnerabilidad:

1. A nivel de diseño:
Nunca enviar credenciales vía GET:

Usar POST para enviar datos sensibles.

Evita que se expongan en URLs o logs.

2. Contra fuerza bruta:
Implementar rate limiting:

Limitar intentos por IP o por cuenta en un tiempo dado.

Ejemplo: máximo 5 intentos por minuto por IP.

Implementar CAPTCHA:

Añadir un desafío visual o lógico después de varios intentos fallidos.

Bloqueo temporal de cuentas o IPs:

Bloquear IP o usuario durante X minutos tras N intentos fallidos.

Mensajes de error genéricos:

No revelar si el usuario o la contraseña es incorrecta; solo mostrar:

"Credenciales inválidas"

Monitoreo y alertas:

Registrar intentos de login y detectar patrones sospechosos.

----------------------------------------------------

**2: Boolean-Based Blind SQL Injection**


🛡️ Cómo se debe solucionar esta vulnerabilidad:
	1. Usar consultas preparadas (prepared statements):
Evitan completamente las inyecciones SQL porque separan datos de lógica.

PHP (PDO):

php

$stmt = $pdo->prepare("SELECT * FROM members WHERE id = ?");
$stmt->execute([$id]);
Python (psycopg2):

python

cursor.execute("SELECT * FROM members WHERE id = %s", (id,))

2. Validación de entradas:
Si el campo espera un número (id), asegúrate de que sea numérico:

php

if (!ctype_digit($_GET['id'])) exit("Entrada inválida");

3. No mostrar errores SQL al usuario:
Mostrar mensajes genéricos en vez de:

sql

Unknown column 'test' in 'where clause'
Para evitar ayudar al atacante con retroalimentación directa.

4. Limitar los privilegios del usuario de base de datos:
El usuario del sistema web no debería tener permisos para ver information_schema, ni realizar operaciones peligrosas como DROP, ALTER, etc.

5. Protección adicional:
WAF (Web Application Firewall)

Detección de patrones de inyección

Logs y alertas en sistemas de autenticación y búsqueda

----------------------------------------------------

**3: LFI (Local File Inclusion) con Null Byte Injection**


🛡️ Cómo se debe solucionar esta vulnerabilidad:
Nunca incluir archivos directamente desde parámetros del usuario:

Si necesitas incluir páginas dinámicas, usa una lista blanca:

php

$pages = ['home', 'about', 'contact'];
if (in_array($_GET['page'], $pages)) {
    include("pages/" . $_GET['page'] . ".php");
} else {
    echo "Página no permitida";
}
Desactivar funciones peligrosas si no se necesitan:

allow_url_include=Off

allow_url_fopen=Off

Actualizar a versiones modernas de PHP:

La null byte injection fue corregida desde PHP 5.3+.

Validar y sanitizar cualquier entrada usada para rutas:

Rechazar ../, %00, rutas absolutas, etc.

Aplicar restricciones de acceso al sistema de archivos:

Usar open_basedir para restringir el acceso a directorios específicos.

----------------------------------------------------

**4: Insecure Deserialization**


🛡️ Cómo se debe solucionar esta vulnerabilidad:

No confiar nunca en datos serializados enviados por el usuario.

Usar formatos seguros (como JSON) y validarlos estrictamente antes de usarlos.

En lenguajes como PHP, evitar funciones como unserialize() con datos de entrada controlados por el usuario.

----------------------------------------------------

**5: Information Disclosure via Exposed Directories**


🛡️ Cómo se debe solucionar esta vulnerabilidad:
Nunca subir archivos sensibles accesibles públicamente:

.htpasswd, .git/, .env, backup.sql, etc., deben estar fuera del root público del servidor.

Deshabilitar o restringir el listado de directorios:

En Apache, agregar en .htaccess o config:

mathematica

Options -Indexes
No confiar en robots.txt como mecanismo de seguridad:

Ese archivo no protege rutas, solo sugiere a buscadores que no las indexen.

Cualquier persona puede leerlo y acceder a lo que está listado.

Proteger carpetas sensibles con autenticación o moverlas fuera del root web.

Realizar escaneos regulares de exposición de archivos:

Herramientas como nikto, dirsearch, gobuster, etc., pueden ayudarte a encontrar problemas antes que los atacantes.

----------------------------------------------------

**6: Sensitive Information Disclosure via Publicly Accessible Files**


🛡️ Cómo se debe solucionar esta vulnerabilidad:
Nunca exponer archivos sensibles públicamente:

.htpasswd, .git/, .env, backup.sql, config.php~, etc., deben estar fuera del directorio web (/var/www/html en Apache, por ejemplo).

Eliminar rutas sensibles del robots.txt:

Este archivo solo informa a los bots, no impide el acceso a usuarios.

Nunca incluyas rutas que deban permanecer en secreto.

No almacenar contraseñas en MD5 (inseguro y fácilmente crackeable):

Usar algoritmos más robustos como bcrypt, argon2 o PBKDF2.

MD5 es vulnerable a ataques de diccionario y tiene múltiples colisiones conocidas.

Proteger /admin con múltiples capas:

Autenticación HTTP básica con .htpasswd, pero bien ubicada y no accesible públicamente.

CAPTCHAs, rate limiting, y autenticación de dos factores (2FA) en producción.

Revisar configuraciones del servidor web para evitar acceso a archivos dot-prefixed (.ht*):

En Apache:

apache

<FilesMatch "^\.">
    Require all denied
</FilesMatch>

----------------------------------------------------

**7: Client-Side Hidden Field Manipulation**


🛡️ Cómo se debe solucionar esta vulnerabilidad:
Nunca confiar en valores enviados desde el cliente, aunque estén "ocultos":

Los campos hidden en HTML son fácilmente visibles y modificables por cualquier usuario.

El servidor debe verificar en backend si el usuario autenticado tiene permiso para realizar la acción sobre ese identificador.

Implementar controles de acceso adecuados:

Asegurarse de que solo un usuario autenticado pueda interactuar con sus propios datos.

Verificar que el usuario tenga permiso para solicitar una acción (como recuperación para admin).

Evitar exponer identificadores sensibles o deterministas en el cliente:

Usar tokens temporales o enlaces únicos para flujos de recuperación.

Auditar todo flujo de recuperación o privilegio elevado:

Asegurarse de que cada acción esté autorizada explícitamente, no solo por confiar en los datos del cliente.

----------------------------------------------------

**8: Client-Side Input Tampering**


🛡️ Cómo se debe solucionar esta vulnerabilidad:
Validación de los datos del lado del servidor (nunca confiar en el cliente):

Validar que los valores recibidos estén dentro del rango permitido (por ejemplo, entre 1 y 5).

Si el campo espera una lista fija de opciones, comprobar explícitamente:

php

$valid_scores = [1, 2, 3, 4, 5];
if (!in_array($_POST['score'], $valid_scores)) {
    die("Valor inválido");
}
Evitar usar valores que desencadenen lógica crítica sin autorización adicional.

Registrar y auditar manipulaciones de valores:

En entornos reales, valores fuera de rango pueden indicar intentos de ataque.

No depender del HTML como validación real:

Los campos select, hidden, readonly o incluso los disabled no protegen contra la manipulación por parte del usuario.

----------------------------------------------------

**9: Access Control Bypass via Manipulation of HTTP Headers**


🛡️ Cómo se debe solucionar esta vulnerabilidad:
No confiar en headers manipulables como Referer o User-Agent para controlar el acceso.

Los navegadores los envían, pero el cliente puede modificarlos fácilmente (como hiciste con curl o con un addon).

Implementar control de acceso basado en sesiones, autenticación real o tokens, no en cabeceras HTTP.

Ejemplo seguro:

php

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    die("Acceso denegado");
}
Evitar dejar comentarios HTML que revelen lógica interna o pistas de acceso.

Auditar todos los puntos de acceso no públicos o "ocultos" para evitar accesos indirectos no autorizados.

----------------------------------------------------

**10: Autenticación basada en cookies manipulables / Validación débil de tokens**


Cómo se debería haber protegido:
Nunca confiar en los valores del lado del cliente sin validarlos: Las cookies pueden ser fácilmente manipuladas si no están protegidas.

Firmar las cookies con un secreto del servidor:

Ejemplo en Flask (Python):

python

response.set_cookie("I_am_admin", "false", secure=True, httponly=True, samesite='Strict')
O usar una cookie firmada con itsdangerous o JWT.

Evitar usar información sensible (como is_admin=true) directamente en cookies.

Usar sesiones del lado del servidor:

Almacenar los privilegios del usuario en una sesión mantenida en el backend, y usar un identificador aleatorio en la cookie (session_id) que no se pueda predecir ni modificar.

----------------------------------------------------

**11:  Insecure File Upload (Subida de archivos insegura)**


🛡️ Cómo se debe solucionar este fallo:
Validación del contenido del archivo (no solo el nombre ni el Content-Type):

Usar librerías como ImageMagick, ExifTool, getimagesize() en PHP para verificar si realmente es una imagen.

Eliminar o renombrar la extensión del archivo al guardarlo:

Por ejemplo, cambiar todos los archivos a .jpg sin excepción, o renombrarlos con UUIDs y sin extensión ejecutable.

Guardar los archivos en una ruta no ejecutable:

Configurar el servidor para que NO ejecute código en el directorio de subida (uploads/):

En Apache:

apache

<Directory "/var/www/uploads">
  php_admin_flag engine off
</Directory>

O poner .htaccess en /uploads:

vbnet

RemoveHandler .php .phtml .php3
RemoveType .php .phtml .php3
Evitar confiar en la extensión del archivo enviada por el cliente.

Filtrar la extensión y bloquear doble extensiones:

Rechazar archivos tipo file.php.jpg, shell.php;.jpg, etc.

----------------------------------------------------

**12: Open Redirect (Unvalidated Redirects and Forwards)**


🛡️ Cómo se debe solucionar esta vulnerabilidad:
Validar y limitar los destinos permitidos:

Mantener una lista blanca (whitelist) de dominios externos seguros (por ejemplo, solo permitir facebook.com, twitter.com, etc.).

Ejemplo (en pseudocódigo):

python

if site in ALLOWED_DOMAINS:
    redirect(site)
else:
    show_error()
Usar identificadores internos en vez de URLs completas:

Por ejemplo, en lugar de pasar site=https://facebook.com, usar site=fb y en el servidor traducir fb a https://facebook.com.

Evitar redirecciones externas cuando no son necesarias.

Mostrar una página de advertencia antes de redirigir:

Así el usuario puede ver a dónde será llevado y confirmar si desea continuar.

----------------------------------------------------

**13: SQL Injection (Union-Based SQL Injection)**


🛡️ Cómo se debe solucionar esta vulnerabilidad:
Usar consultas preparadas (prepared statements) con parámetros enlazados:

En PHP (PDO):

php

$stmt = $pdo->prepare("SELECT * FROM list_images WHERE id = ?");
$stmt->execute([$id]);
En Python (SQLite / psycopg2 / MySQLdb):

python

cursor.execute("SELECT * FROM list_images WHERE id = %s", (id,))
Escapar correctamente los parámetros solo si no se puede usar prepared statements (no recomendado).

Limitar el acceso a information_schema en entornos de producción.

Validar y sanitizar todos los inputs del usuario:

Si esperas un número, asegúrate de que realmente sea un número (is_numeric, ctype_digit, etc.).

Deshabilitar mensajes de error detallados en producción:

Los errores SQL detallados ayudan a los atacantes a construir sus payloads.

Aplicar un WAF o filtros adicionales (mod_security, etc.) para detectar patrones típicos de inyecciones.

----------------------------------------------------

**14: Cross-Site Scripting (XSS) mediante inyección en <object> con data: URI**


🛡️ Cómo se debe solucionar esta vulnerabilidad:
Escapar correctamente los valores que se insertan en atributos HTML:

Especialmente si se va a usar dentro de src, data, href, etc.

Restringir el uso de data: URIs si no son estrictamente necesarios.

Muchos navegadores y políticas de seguridad modernas pueden bloquear esto con Content Security Policy (CSP).

Sanitizar y validar el parámetro src:

Solo permitir rutas relativas internas, evitar valores como data:, javascript:, etc.

Por ejemplo:

php

$src = $_GET['src'];
if (!preg_match('/^[\w\/.-]+$/', $src)) {
    die("Ruta inválida");
}
Usar CSP (Content Security Policy) para prevenir carga de contenido malicioso:

http

Content-Security-Policy: default-src 'self'; object-src 'none';
O al menos limitar object-src a dominios específicos.

-----------------------------------------------

**15. Cross-Site Scripting mediante Stored XSS**

🛡️ Cómo se debe solucionar esta vulnerabilidad:

1. Escapar el contenido al mostrarlo

Antes de insertar cualquier entrada del usuario en el HTML de una página, debes escapar caracteres especiales, como <, >, ", ', &. Esto previene que se interpreten como código HTML o JavaScript.

En el backend (por ejemplo en PHP, Python, Node.js, etc.), usa funciones de escape según el framework/lenguaje.

En el frontend, nunca insertes texto del usuario directamente con innerHTML o atributos sin validación.

2. Validar y sanitizar la entrada

No permitas etiquetas HTML en campos que no deben tenerlas. Usa una whitelist si necesitas permitir algunos elementos (como en editores ricos).

Usa bibliotecas como:

PHP: htmlspecialchars()

JavaScript: DOMPurify

Python (Django): |escape en plantillas

3. Content Security Policy (CSP)

Implementa una política CSP adecuada que bloquee la ejecución de scripts inline o no autorizados.

4. Usar atributos seguros

Si vas a mostrar información del usuario como title en una imagen, asegúrate de escapar el valor correctamente o usar funciones de manipulación DOM seguras como element.setAttribute('title', userInput) en lugar de construir HTML manualmente.

