import base64
import ipaddress
import requests
from urllib.parse import urlparse
from apis.menu import schemas
from db.models import MenuItem
from fastapi import HTTPException

# Configuración: Dominios permitidos para alojamiento de imágenes
ALLOWED_IMAGE_DOMAINS = [
    "cdn.restaurant.com",
    "images.restaurant.com",
    "s3.amazonaws.com",
    # Agregar otros dominios de CDN/alojamiento de imágenes confiables
]

# Tipos MIME de imágenes permitidos
ALLOWED_IMAGE_TYPES = [
    "image/jpeg",
    "image/jpg", 
    "image/png",
    "image/gif",
    "image/webp"
]

# Tamaño máximo de imagen (10MB)
MAX_IMAGE_SIZE = 10 * 1024 * 1024


def _is_private_ip(ip_str: str) -> bool:
    """Verifica si una dirección IP es privada/interna."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private or 
            ip.is_loopback or 
            ip.is_link_local or
            ip.is_multicast or
            ip.is_reserved
        )
    except ValueError:
        return False


def _validate_image_url(image_url: str) -> None:
    """
    Valida que la URL de la imagen sea segura para descargar.
    
    Lanza HTTPException si la validación falla.
    """
    # Analizar la URL
    try:
        parsed = urlparse(image_url)
    except Exception:
        raise HTTPException(
            status_code=400, 
            detail="Invalid URL format"
        )
    
    # Verificar el esquema - solo permitir HTTPS
    if parsed.scheme != "https":
        raise HTTPException(
            status_code=400,
            detail="Only HTTPS URLs are allowed for security reasons"
        )
    
    # Verificar si el dominio está en la lista permitida
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(
            status_code=400,
            detail="URL must contain a valid hostname"
        )
    
    # Validar contra dominios permitidos
    domain_allowed = False
    for allowed_domain in ALLOWED_IMAGE_DOMAINS:
        if hostname == allowed_domain or hostname.endswith(f".{allowed_domain}"):
            domain_allowed = True
            break
    
    if not domain_allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Image URL must be from one of the allowed domains: {', '.join(ALLOWED_IMAGE_DOMAINS)}"
        )
    
    # Prevenir ataques de DNS rebinding - resolver y verificar IP
    try:
        import socket
        ip_address = socket.gethostbyname(hostname)
        if _is_private_ip(ip_address):
            raise HTTPException(
                status_code=400,
                detail="Cannot fetch images from private IP addresses"
            )
    except socket.gaierror:
        raise HTTPException(
            status_code=400,
            detail="Unable to resolve hostname"
        )


def _image_url_to_base64(image_url: str) -> str:
    """
    Descarga una imagen desde una URL y la convierte a base64.
    
    Implementa medidas de seguridad:
    - Validación de URL y lista de dominios permitidos
    - Validación de dirección IP para prevenir SSRF
    - Validación de Content-Type
    - Límites de tamaño
    - Límites de tiempo de espera
    """
    # Validar URL antes de realizar la solicitud
    _validate_image_url(image_url)
    
    try:
        # Realizar solicitud con medidas de seguridad
        response = requests.get(
            image_url,
            stream=True,
            timeout=10,  # Tiempo de espera de 10 segundos
            allow_redirects=False,  # No seguir redirecciones (previene evasión)
            headers={
                "User-Agent": "RestaurantMenuService/1.0"
            }
        )
        
        # Verificar estado de la respuesta
        if response.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to fetch image: HTTP {response.status_code}"
            )
        
        # Validar Content-Type
        content_type = response.headers.get("Content-Type", "").lower()
        if not any(allowed_type in content_type for allowed_type in ALLOWED_IMAGE_TYPES):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid content type. Must be one of: {', '.join(ALLOWED_IMAGE_TYPES)}"
            )
        
        # Verificar Content-Length si está disponible
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > MAX_IMAGE_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"Image size exceeds maximum allowed size of {MAX_IMAGE_SIZE / (1024*1024)}MB"
            )
        
        # Leer contenido con límite de tamaño
        content = b""
        for chunk in response.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > MAX_IMAGE_SIZE:
                raise HTTPException(
                    status_code=400,
                    detail=f"Image size exceeds maximum allowed size of {MAX_IMAGE_SIZE / (1024*1024)}MB"
                )
        
        # Codificar a base64
        encoded_image = base64.b64encode(content).decode()
        return encoded_image
        
    except requests.exceptions.Timeout:
        raise HTTPException(
            status_code=400,
            detail="Request timeout while fetching image"
        )
    except requests.exceptions.RequestException as e:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to fetch image: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Internal error processing image"
        )


def create_menu_item(
    db,
    menu_item: schemas.MenuItemCreate,
):
    menu_item_dict = menu_item.dict()
    image_url = menu_item_dict.pop("image_url", None)
    db_item = MenuItem(**menu_item_dict)
    if image_url:
        db_item.image_base64 = _image_url_to_base64(image_url)
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item


def update_menu_item(
    db,
    item_id: int,
    menu_item: schemas.MenuItemCreate,
):
    db_item = db.query(MenuItem).filter(MenuItem.id == item_id).first()
    if db_item is None:
        raise HTTPException(status_code=404, detail="Menu item not found")
    menu_item_dict = menu_item.dict()
    image_url = menu_item_dict.pop("image_url", None)
    for key, value in menu_item_dict.items():
        setattr(db_item, key, value)
    if image_url:
        db_item.image_base64 = _image_url_to_base64(image_url)
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item


def delete_menu_item(db, item_id: int):
    db_item = db.query(MenuItem).filter(MenuItem.id == item_id).first()
    if db_item is None:
        raise HTTPException(status_code=404, detail="Menu item not found")
    db.delete(db_item)
    db.commit()
