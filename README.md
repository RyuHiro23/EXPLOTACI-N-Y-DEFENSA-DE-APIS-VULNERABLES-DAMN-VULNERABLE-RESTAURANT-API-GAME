# Proyecto: Explotación y Defensa de APIs Vulnerables – Damn Vulnerable RESTaurant API

## Dikson N. Cantillo, Dayanna A. Garcia.

#### Universidad Cooperativa de Colombia 

Este proyecto tiene como propósito analizar, explotar y corregir vulnerabilidades presentes en una API intencionalmente insegura, basada en el laboratorio Damn Vulnerable RESTaurant.
A través de distintos niveles, se identifican y mitigan fallos comunes en servicios REST, aplicando prácticas seguras de desarrollo y referencia directa a las categorías de OWASP API Security Top 10 (2023).

El objetivo principal es comprender cómo se originan vulnerabilidades reales en APIs modernas *como la falta de control de acceso, errores de autorización, escalamiento de privilegios o solicitudes inseguras al servidor* y demostrar, mediante código corregido, las medidas necesarias para prevenirlas en entornos de producción.

## Entorno de ejecución
Este proyecto fue desarrollado y ejecutado dentro de una máquina virtual Kali Linux, utilizando Docker para desplegar la API vulnerable Damn Vulnerable RESTaurant y sus servicios asociados.

### Requisitos
- Kali Linux (máquina virtual)
- Docker Engine
- Docker Compose
- Python 3 (solo para inspección del código)
- Burp Suite Community Edition
- Visual Studio Code

## Iniciar el entorno
Ejecutar en la terminal dentro del directorio del proyecto:
```bash
docker-compose build
docker-compose up -d
```
Verificar los contenedores:
```bash
docker ps
```
La API estará disponible en:
```bash
http://localhost:8091
```
Documentación automática de FastAPI:
```bash
http://localhost:8091/docs
```
## Herramientas utilizadas
- Burp Suite: interceptación y explotación de endpoints
- cURL: pruebas rápidas desde la terminal
- VS Code: modificación del código fuente y aplicación de parches
- Git: versionado y repositorio del proyecto

Con este entorno se ejecutaron todas las pruebas, explotaciones y validaciones documentadas en este repositorio.

## Vulnerabilidades 

## Level 1 – Unrestricted Menu Item Deletion
### Vulnerabilidad
El endpoint `DELETE /menu/{item_id}` no aplicaba controles de autorización, permitiendo que cualquier usuario eliminara elementos del menú. Clasificada como *OWASP API5:2023 – Broken Function Level Authorization*, esta falla comprometía la integridad y disponibilidad de los datos.
<img width="795" height="564" alt="image" src="https://github.com/user-attachments/assets/43f6801f-024d-4996-95b8-74485133ed57" />

### Código antiguo
```python
@router.delete("/menu/{item_id}")
def delete_menu_item(
    item_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
    # auth=Depends(RolesBasedAuthChecker([UserRole.EMPLOYEE, UserRole.CHEF])),
):
    utils.delete_menu_item(db, item_id)
```
### Explotación
Un usuario sin privilegios podía enviar una solicitud DELETE y eliminar ítems, demostrando la ausencia de validación por rol.
<img width="784" height="510" alt="image" src="https://github.com/user-attachments/assets/81290355-f28a-45bb-a43b-a946f5192598" />
<img width="836" height="413" alt="image" src="https://github.com/user-attachments/assets/46c9a43c-f646-47d9-b4d2-f89428d88b62" />

### Código corregido
```python
@router.delete("/menu/{item_id}")
def delete_menu_item(
    item_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
    auth=Depends(RolesBasedAuthChecker([UserRole.EMPLOYEE, UserRole.CHEF])),
):
    utils.delete_menu_item(db, item_id)
```

### Solución implementada y justificación
Se activó la verificación de roles con `RolesBasedAuthChecker`, limitando la acción solo a EMPLOYEE y CHEF. Esto asegura el control de acceso y evita eliminaciones no autorizadas.

### Intento de explotación con código ya corregido
Se repitió la misma petición con un usuario sin privilegios; sin embargo, la API respondió con un código 403 Forbidden, evidenciando que la vulnerabilidad fue corregida.

<img width="795" height="495" alt="image" src="https://github.com/user-attachments/assets/9f58d3a1-188d-47be-b801-3fb8268dfa5e" />

## Level 2 – Unrestricted Profile Update (IDOR)
### Vulnerabilidad
El endpoint de perfil permitía modificar cualquier cuenta al aceptar un `username` arbitrario. Corresponde a *OWASP API2:2023 – Broken Object Level Authorization (BOLA)*, ya que no se restringía la modificación al usuario autenticado.

### Código antiguo
```python
@router.put("/profile")
def update_profile(user: UserUpdate, current_user, db):
    db_user = get_user_by_username(db, user.username)
    for var, value in user.dict().items():
        if value:
            setattr(db_user, var, value)
    db.commit()
    return db_user
```

### Explotación
Un usuario podía cambiar datos de otra cuenta simplemente modificando el campo `username` en la petición.
<img width="709" height="752" alt="image" src="https://github.com/user-attachments/assets/754f70bf-dac6-430b-a9d7-77b93ddd6d3f" />

### Código corregido
```python
@router.put("/profile")
def update_profile(user_update: UserUpdate, current_user, db):
    db_user = get_user_by_username(db, current_user.username)
    update_data = user_update.dict(exclude_unset=True)
    update_data.pop("username", None)
    for var, value in update_data.items():
        setattr(db_user, var, value)
    db.commit()
    return db_user
```

### Solución implementada y justificación
La actualización ahora se asocia al usuario autenticado y se bloquea el cambio de `username`, evitando la manipulación de perfiles ajenos y protegiendo la integridad de los datos.

### Intento de explotación con el código ya corregido
Al repetir la misma petición autenticada intentando modificar el perfil de otro usuario, la API no aplica los cambios sobre la cuenta objetivo; la actualización afecta únicamente al perfil del usuario que hace la petición, evidenciando que la vulnerabilidad fue mitigada.

<img width="775" height="614" alt="image" src="https://github.com/user-attachments/assets/cef20722-e3b1-491b-877b-0c775ad68426" />

## Level 3 – Privilege Escalation
### Vulnerabilidad
Cualquier usuario podía asignarse roles superiores como CHEF o EMPLOYEE, debido a la falta de validación en el endpoint de actualización de roles. Pertenece a *OWASP API5:2023 – Broken Function Level Authorization*, al permitir acciones administrativas sin privilegios.

### Código antiguo
```python
@router.put("/users/update_role")
async def update_user_role(user, current_user, db):
    db_user = update_user(db, user.username, user)
    return current_user
```

### Explotación 
Un usuario CUSTOMER pudo cambiar su rol a CHEF mediante una simple petición PUT, obteniendo permisos elevados.
<img width="767" height="472" alt="image" src="https://github.com/user-attachments/assets/fb1a4f1a-cd44-48f1-85fd-6e721251f173" />

### Código corregido
```python
if current_user.role == models.UserRole.CUSTOMER:
    raise HTTPException(403, "Customers cannot change roles")
if user.role == models.UserRole.CHEF.value and current_user.role != models.UserRole.CHEF:
    raise HTTPException(403, "Only Chef can assign Chef role")
if current_user.username == user.username:
    raise HTTPException(403, "Users cannot modify their own role")
```

### Solución implementada y justificación
Se agregaron reglas que restringen la asignación de roles según jerarquía, evitando autopromociones y garantizando el principio de mínimo privilegio.

### Intento de explotación con el código ya corregido
Se repitió la misma petición (mismo token Lunnita) desde Burp Repeater tras desplegar la corrección y reiniciar el servicio. El servidor respondió 403 Forbidden (o 401) con mensaje de autorización, y el rol no se modificó en la base de datos.

<img width="772" height="456" alt="image" src="https://github.com/user-attachments/assets/d429946d-faae-458d-8627-473f4a1ff41f" />

## Level 4 - Server-Side Request Forgery
### Vulnerabilidad
El sistema descargaba imágenes desde cualquier URL sin validación, lo que permitía acceder a direcciones internas o servicios privados. Clasificada como *OWASP API7:2023 – Server-Side Request Forgery (SSRF)*.

## Código antiguo
```python
def _image_url_to_base64(image_url):
    response = requests.get(image_url, stream=True)
    return base64.b64encode(response.content).decode()
```

### Explotación
Al enviar un `image_url` con destino interno (`http://localhost:8091/...`), el servidor realizaba la solicitud, exponiendo datos internos.
<img width="775" height="242" alt="image" src="https://github.com/user-attachments/assets/e399d480-f0cb-4255-a5af-eea23260f033" />
<img width="775" height="244" alt="image" src="https://github.com/user-attachments/assets/539c6475-c6f7-44f6-93c5-581a2596bc16" />

### Código corregido
```python
def _validate_image_url(image_url):
    parsed = urlparse(image_url)
    if parsed.scheme != "https":
        raise HTTPException(400, "Only HTTPS allowed")
    ip = socket.gethostbyname(parsed.hostname)
    if _is_private_ip(ip):
        raise HTTPException(400, "Private IPs not allowed")
```
### Solución implementada y justificación
Se añadieron filtros de protocolo, dominios permitidos y detección de IPs privadas. Con ello, el servidor deja de aceptar rutas internas, previniendo la explotación SSRF.

### Intento de explotación con código ya corregido
Se repitió la misma petición (mismo token EMPLOYEE y misma image_url local). El servidor rechazó la solicitud con 400 Bad Request o 403 y detalle indicando validación de URL (o Invalid content type), y no se descargó el recurso interno.

<img width="975" height="342" alt="image" src="https://github.com/user-attachments/assets/2f02a4d0-404b-4c63-a03d-b25311d16c88" />

