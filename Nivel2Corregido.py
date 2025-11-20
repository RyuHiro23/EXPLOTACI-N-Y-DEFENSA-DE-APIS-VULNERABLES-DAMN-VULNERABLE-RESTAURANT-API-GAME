from apis.auth.utils import RolesBasedAuthChecker, get_current_user, update_user
from apis.users.schemas import UserRoleUpdate
from db import models
from db.session import get_db
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing_extensions import Annotated

router = APIRouter()

@router.put("/users/update_role", response_model=UserRoleUpdate)
async def update_user_role(
    user: UserRoleUpdate,
    current_user: Annotated[models.User, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    """
    Actualiza el rol de usuario con las verificaciones de autorización apropiadas.
    Reglas de autorización:
    - Solo CHEF puede asignar el rol CHEF
    - Solo EMPLOYEE y CHEF pueden asignar el rol EMPLOYEE
    - CUSTOMER no puede asignar ningún rol
    """
    # Regla 1: Los clientes no pueden cambiar ningún rol
    if current_user.role == models.UserRole.CUSTOMER:
        raise HTTPException(
            status_code=status.HTTP_401_FORBIDDEN,
            detail="Customers are not authorized to change user roles",
        )
    
    # Regla 2: Solo Chef puede asignar el rol Chef
    if user.role == models.UserRole.CHEF.value:
        if current_user.role != models.UserRole.CHEF:
            raise HTTPException(
                status_code=status.HTTP_401_FORBIDDEN,
                detail="Only Chef is authorized to assign Chef role",
            )
    
    # Regla 3: Solo Employee y Chef pueden asignar el rol Employee
    if user.role == models.UserRole.EMPLOYEE.value:
        if current_user.role not in [models.UserRole.EMPLOYEE, models.UserRole.CHEF]:
            raise HTTPException(
                status_code=status.HTTP_401_FORBIDDEN,
                detail="Only Employee or Chef can assign Employee role",
            )
    
    # Prevenir que los usuarios se promocionen a sí mismos (opcional pero recomendado)
    if current_user.username == user.username:
        raise HTTPException(
            status_code=status.HTTP_401_FORBIDDEN,
            detail="Users cannot modify their own role",
        )
    
    # Realizar la actualización
    db_user = update_user(db, user.username, user)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user.username} not found",
        )
    
    return db_user  # Devolver el usuario actualizado, no current_user
