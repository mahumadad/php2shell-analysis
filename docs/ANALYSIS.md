# PHP2Shell — CVE-2026-109618 / CVE-2026-109619
## Análisis técnico completo

### 1. Superficie de ataque

El handler `php_session_rfc1867_callback()` en `ext/session/session.c` se registra
como callback global en `php_rfc1867_callback` durante `MINIT`. Se invoca para
**cada request `multipart/form-data`** cuando `session.upload_progress.enabled = On`
(default). No requiere autenticación ni sesión previa.

### 2. Las dos estructuras cacheadas

La struct `php_session_rfc1867_progress` (php_session.h:122-139) mantiene dos
punteros raw a zvals dentro de HashTables vivas:

```c
typedef struct _php_session_rfc1867_progress {
    // ...
    zval      data;                 /* el array exportado a $_SESSION */
    zval      files;                /* data["files"] */
    zval     *post_bytes_processed; /* → data["bytes_processed"] bucket */
    zval     *current_file_bytes_processed; /* → current_file["bytes_processed"] bucket */
    zval      current_file;
} php_session_rfc1867_progress;
```

### 3. Bug 1 — CVE-2026-109619: `post_bytes_processed`

En `MULTIPART_EVENT_FILE_START` (session.c ~L3316, solo en el primer FILE_START):

```c
if (Z_ISUNDEF(progress->data)) {
    // ... inicializa progress->data con array_init ...
    add_assoc_long_ex(&progress->data, "bytes_processed", ..., data->post_bytes_processed);
    progress->post_bytes_processed = zend_hash_str_find(
        Z_ARRVAL(progress->data), "bytes_processed", ...);
    // ...
}
```

Este puntero se cachea **UNA SOLA VEZ** al primer FILE_START. Nunca se refresca
en FILE_START posteriores (el bloque `if (Z_ISUNDEF(progress->data))` no vuelve
a entrar).

### 4. Bug 2 — CVE-2026-109618: `current_file_bytes_processed`

En `MULTIPART_EVENT_FILE_START` (cada archivo, session.c ~L3342):

```c
array_init(&progress->current_file);
// ... add_assoc_long_ex(..., "bytes_processed", ..., 0) ...
add_next_index_zval(&progress->files, &progress->current_file);  // ZVAL_COPY_VALUE, NO addref
progress->current_file_bytes_processed = zend_hash_str_find(
    Z_ARRVAL(progress->current_file), "bytes_processed", ...);
```

Se refresca en cada FILE_START pero persiste entre chunks (FILE_DATA) de un
mismo archivo. La clave: `add_next_index_zval` hace **ZVAL_COPY_VALUE sin addref**.
El array `current_file` queda con refcount=1, referenciado tanto por el struct
field como por el bucket en `files[]`.

### 5. La cadena de free: `php_session_rfc1867_update()`

La función update (session.c L3161) tiene un throttle basado en `min_freq` (default
1s) y `freq` (default 1%). Cuando el throttle permite:

```c
static void php_session_rfc1867_update(...) {
    // throttle check lee progress->post_bytes_processed (L3168)
    if (Z_LVAL_P(progress->post_bytes_processed) < progress->next_update) {
        return;
    }
    // ... time check con min_freq ...
    
    php_session_initialize();      // ← RE-LEE la sesión
    PS(session_status) = php_session_active;
    IF_SESSION_VARS() {
        zval *sess_var = Z_REFVAL(PS(http_session_vars));
        SEPARATE_ARRAY(sess_var);
        // ...
        Z_TRY_ADDREF(progress->data);
        zend_hash_update(Z_ARRVAL_P(sess_var), progress->key.s, &progress->data);
    }
    php_session_flush(1);
}
```

### 6. El mecanismo del dangling pointer

La cadena en la SEGUNDA llamada a update (post-throttle):

1. `php_session_initialize()` (session.c L407):
   - `php_session_track_init()` (L244): destruye `PS(http_session_vars)` via
     `zval_ptr_dtor` → HashTable destructor itera cada elemento → `zval_ptr_dtor`
     en progress->data → refcount 2→1 (NO freed, progress struct aún lo tiene)
   - Crea nuevo `$_SESSION` vacío
   - `s_read()` lee el archivo de sesión serializado
   - `php_session_decode()` deserializa en el NUEVO array
     - Crea una COPIA DECODIFICADA del progress data en la misma key

2. De vuelta en update:
   - `zend_hash_update(sess_var, key, &progress->data)`:
     - Encuentra la COPIA DECODIFICADA en el bucket existente
     - `ht->pDestructor(decoded_copy)` → **destruye la copia decodificada**
     - El decoded "files[]" con su decoded "current_file[]" se liberan
     - `ZVAL_COPY_VALUE(bucket, &progress->data)` → reemplaza con el original

3. Los chunks liberados de la copia decodificada van al allocator.
   Los arrays internos (`files[]`, `current_file[]`) usaron `add_next_index_zval`
   (ZVAL_COPY_VALUE sin addref), así que sus refcounts son 1. Al
   deserializar/destruir, la copia del tree decodificado puede causar
   inconsistencias en los refcounts de los arrays originales si el
   serializer comparte referencias o si SEPARATE_ARRAY hace COW.

### 7. Explotación: heap feng shui

El exploit controla la reclamación de los chunks liberados:

- Campos de formulario `t[]` con ~149 elementos → `nTableSize` 256 → bins de
  ~320 bytes (matching el tamaño del chunk del HashTable liberado)
- El chunk liberado del decoded tree es reclamado por el array `t[]`
- Las escrituras a través del puntero dangling ahora caen en memoria controlada

### 8. Primitive → RCE

Escrituras controladas:
```c
// FILE_DATA (L3355-3356):
Z_LVAL_P(progress->current_file_bytes_processed) = data->offset + data->length;
Z_LVAL_P(progress->post_bytes_processed) = data->post_bytes_processed;

// FILE_END (L3375):
Z_LVAL_P(progress->post_bytes_processed) = data->post_bytes_processed;
```

El atacante forja un `zend_fcall_info` (64B, param_count en +48) / 
`zend_internal_function` (handler en +88) para redirigir:
`zend_call_function` → `system()`.

Offsets build-específicos (delta `zval_ptr_dtor` → `zend_call_function`):
| Distro    | lsphp82 8.2.34 delta |
|-----------|---------------------|
| bookworm  | 0xc930              |
| noble     | 0xcef0              |
| jammy     | 0xd060              |

### 9. Versiones afectadas y fix

- **Afectadas**: PHP 5.4.0 → 8.5.x (toda versión con session.upload_progress)
- **Fix programado**: 2026-10-21 14:00 UTC → 8.2.35, 8.3.36, 8.4.27, 8.5.12
- **EOL sin fix**: PHP 5.x, 7.x, 8.0, 8.1

### 10. El segundo bug: CVE-2026-109618 (independiente de upload_progress)

Mientras CVE-2026-109619 es el UAF de punteros cacheados en el upload progress
handler (requiere `enabled=On`), CVE-2026-109618 combina **tres defectos
independientes** de `session.upload_progress` para lograr RCE:

#### 10a. `PS(serializer)` no se resetea entre requests FPM

En `php_rinit_session_globals()` (session.c ~L108-121), el campo `PS(serializer)`
**NO se pone a NULL**:

```c
static inline void php_rinit_session_globals(void) {
    PS(id) = NULL;
    PS(session_status) = php_session_none;
    // NO PS(serializer) = NULL;
    ZVAL_UNDEF(&PS(http_session_vars));
}
```

Y en `php_rinit_session()`, solo se asigna si es NULL:
```c
if (PS(serializer) == NULL) {
    PS(serializer) = _php_find_ps_serializer(value);
}
```

En PHP-FPM, un worker que procesa un request a directorio A (configurado con
`session.serialize_handler = php_serialize`) y luego un request a directorio B
(configurado con `session.serialize_handler = php`, el default) usará el
serializador **equivocado** para B porque `PS(serializer)` quedó con el valor
del request anterior.

#### 10b. `__destruct` se ejecuta en fallo de decode

Cuando `php_session_decode()` falla (formato incorrecto por el mismatch de
serializador), se llama `php_session_cancel_decode()`:

```c
static void php_session_cancel_decode(void) {
    php_session_destroy();
    php_error_docref(NULL, E_WARNING,
        "Failed to decode session object. Session has been destroyed");
}
```

`php_session_destroy()` limpia los objetos parcialmente deserializados. Si alguno
tiene un `__destruct`, se ejecuta durante esta limpieza. Esto convierte el fallo
de decode en una primitiva de **object injection**: el atacante controla qué
clases se instancian y sus `__destruct` se ejecutan.

#### 10c. var_destroy → __destruct reentry UAF

Cuando `php_session_track_init()` destruye la sesión anterior:

```c
zval_ptr_dtor(&PS(http_session_vars));  // ← destruye el tree viejo
```

Si un objeto en la sesión tiene `__destruct` que re-entra al sistema de sesiones
(llamando `session_start()`, `session_destroy()`, `session_decode()`, etc.),
causa una re-destrucción del state que está siendo liberado → **heap-use-after-free**
confirmado por ASAN.

#### 10d. Cadena de ataque (sin upload_progress)

1. El servidor tiene dos directorios con serializers distintos (o un `.user.ini`
   inyectado que cambia el serializer)
2. Request 1: a directorio con `php_serialize` → `PS(serializer)` se fija
3. Request 2: a directorio con `php` (default) → `PS(serializer)` NO se resetea,
   usa el serializer equivocado
4. El atacante controla el session ID (cookie) y puede preparar datos de sesión
   con formato `php_serialize` que incluyan objetos serializados
5. El decode con el serializer `php` falla o interpreta los datos de forma distinta
6. `php_session_cancel_decode()` → `php_session_destroy()` → `__destruct`
   en objetos parcialmente deserializados
7. Con una POP gadget chain disponible en la aplicación → **RCE**

**Esta cadena NO requiere `session.upload_progress.enabled = On`.** Funciona en
cualquier deployment PHP-FPM con configuración per-directory de serializers.

### 11. Cadenas de ataque verificadas (resumen)

| Cadena | Tipo | Requiere upload_progress | Condiciones adicionales |
|--------|------|--------------------------|------------------------|
| Session File Injection + LFI | Logic bug | ✅ Sí (enabled=On) | LFI en la app |
| UAF punteros cacheados → RCE | Memory corruption | ✅ Sí (enabled=On) | Offsets del build |
| Handler Mismatch → `__destruct` | Deserialization | ❌ No | Serializers distintos por directorio + POP gadget |
| var_destroy reentry UAF | Memory corruption | ❌ No | Objeto con `__destruct` que re-entre a sesiones |
| Session Fixation via POST | Logic bug | ✅ Sí (enabled=On) | Bypasea `use_only_cookies` |

### 12. CVSS

v4.0 **9.2** (Crítico) — ambos CVEs.
Pre-auth, no requiere interacción del usuario, ejecución arbitraria de código.

### 13. Hallazgos adicionales

1. **Filename sin validar**: `upload_progress.name` almacena el nombre de archivo
   RAW en el archivo de sesión → inyección de código PHP si hay LFI.

2. **Session fixation via POST body**: El handler de upload_progress lee el
   session ID desde un campo POST con el nombre de `session.name` (ej: PHPSESSID),
   bypaseando `session.use_only_cookies = On`.

3. **`PS(serializer)` sticky en FPM**: Leak cross-request del serializer permite
   mismatch de formato entre directorios con distinta config.

4. **SEPARATE_ARRAY en MULTIPART_EVENT_END**: Crea divergencia entre
   `progress->data` (copia nueva) y los punteros cacheados (apuntan al array
   viejo aún en la sesión). Cuando `php_session_initialize()` libera la sesión
   vieja, los punteros quedan dangling.

### 14. Estado del fix

- **Fix embargado**: Al 2026-10-21 (pre-release), el branch `PHP-8.4.27` público
  **NO contiene** cambios en `php_session_rfc1867_callback` ni en el reset del
  serializer. El fix real se publicará con el release oficial (14:00 UTC).
- Los cambios visibles (GC seeding, null-safety de `PS(id)`, error handling en
  `s_create_sid`) son mejoras de robustez pero no el fix del UAF.
- **Mitigación parcial**: `session.upload_progress.enabled = Off` bloquea las
  cadenas 1, 2 y 5, pero NO las cadenas 3 y 4 (handler mismatch, var_destroy
  reentry).
- **Mitigación adicional**: Asegurar `session.serialize_handler` idéntico en
  todos los directorios del servidor, `session.use_strict_mode = On`.
