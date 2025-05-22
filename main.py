import os
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional, Dict
import httpx
import stripe
from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field

# =============================
# CONFIGURACIÓN Y DEPENDENCIAS
# =============================

# Clave secreta para firmar tokens JWT
SECRET_KEY = os.getenv("JWT_SECRET", "dev-secret-change-me")
# Algoritmo de cifrado para JWT
ALGORITHM = "HS256"
# Tiempo de expiración del token (en minutos)
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Clave secreta para usar la API de Stripe (modo prueba por defecto)
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "sk_test_xxx")

# URL del servicio de conversión de divisas (CLP a USD)
FX_API = "https://api.exchangerate.host/convert"

# Contexto de encriptación para contraseñas
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Configuración del esquema OAuth2 para autenticación
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# Inicialización de la aplicación FastAPI
app = FastAPI(
    title="Ferremas API",
    description="Servicio web para inventario, pedidos y pagos de Ferremas",
    version="1.0.0",
)

# MODELOS DE DATOS Y ROLES

# Enum para los diferentes roles de usuario
class Role(str, Enum):
    admin = "admin"
    maintainer = "mantenedor"
    store_manager = "jefe_tienda"
    warehouse = "bodega"
    client = "client"
    service = "service_account"

# Modelo de usuario con nombre, contraseña y rol
class User(BaseModel):
    username: str
    hashed_password: str
    role: Role

# Modelo para el token JWT de autenticación
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

# Modelo para una sucursal de Ferremas
class Branch(BaseModel):
    id: int
    name: str
    address: str
    phone: str

# Modelo para un vendedor asociado a una sucursal
class Seller(BaseModel):
    id: int
    name: str
    branch_id: int
    email: EmailStr

# Modelo para un producto en el catálogo
class Product(BaseModel):
    id: int
    name: str
    description: str
    price_clp: float
    is_new: bool = False
    is_promo: bool = False

# Modelo para una orden de compra
class OrderRequest(BaseModel):
    product_id: int
    quantity: int = Field(ge=1)
    currency: str = Field("CLP", pattern="^(CLP|USD)$")

# Modelo para una solicitud de contacto con un vendedor
class ContactRequest(BaseModel):
    seller_id: int
    message: str

# BASE DE DATOS 

# Simulación de usuarios registrados
users_db: Dict[str, User] = {
    "javier_thompson": User(
        username="javier_thompson",
        hashed_password=pwd_ctx.hash("aONF4d6aNBIxRjlgjBRRzrS"),
        role=Role.admin,
    ),
    "ignacio_tapia": User(
        username="ignacio_tapia",
        hashed_password=pwd_ctx.hash("f7rWChmQS1JYfThT"),
        role=Role.client,
    ),
    "stripe_sa": User(
        username="stripe_sa",
        hashed_password=pwd_ctx.hash("dzkQqDL9XZH33YDzhmsf"),
        role=Role.service,
    ),
}

# Sucursales disponibles
branches = [
    Branch(id=1, name="Casa Matriz", address="Santiago Centro", phone="+56 2 2345 6789"),
    Branch(id=2, name="Sucursal Maipú", address="Maipú", phone="+56 2 2123 9876"),
]

# Vendedores de cada sucursal
sellers = [
    Seller(id=1, name="María López", branch_id=1, email="maria@ferremas.cl"),
    Seller(id=2, name="Pedro Díaz", branch_id=2, email="pedro@ferremas.cl"),
]

# Catálogo de productos
products = [
    Product(id=1, name="Taladro Bosch 500W", description="Taladro percutor", price_clp=49990),
    Product(id=2, name="Martillo Stanley", description="16 oz", price_clp=7990, is_new=True),
    Product(id=3, name="Pintura Sika Blanca 1 L", description="Interior", price_clp=5990, is_promo=True),
]

# FUNCIONES DE AUTENTICACIÓN Y ROL

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)

def authenticate_user(username: str, password: str) -> Optional[User]:
    user = users_db.get(username)
    if user and verify_password(password, user.hashed_password):
        return user
    return None

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + expires_delta})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        user = users_db.get(username)
        if user is None:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception

def role_required(*roles: Role):
    async def checker(current: User = Depends(get_current_user)):
        if current.role not in roles:
            raise HTTPException(status_code=403, detail="Permisos insuficientes")
        return current
    return checker

# ENDPOINTS 

@app.post("/auth/login", response_model=Token, tags=["auth"])
# Endpoint para autenticarse y obtener un token JWT
async def login(form: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form.username, form.password)
    if not user:
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos")
    token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return Token(access_token=token)

@app.get("/branches", response_model=List[Branch], tags=["branches"])
# Devuelve todas las sucursales disponibles
async def get_branches():
    return branches

@app.get("/branches/{branch_id}", response_model=Branch, tags=["branches"])
# Devuelve los datos de una sucursal específica
async def get_branch(branch_id: int):
    for b in branches:
        if b.id == branch_id:
            return b
    raise HTTPException(404, "Sucursal no encontrada")

@app.get("/branches/{branch_id}/sellers", response_model=List[Seller], tags=["sellers"])
# Devuelve los vendedores de una sucursal específica
async def get_sellers(branch_id: int):
    return [s for s in sellers if s.branch_id == branch_id]

@app.get("/products", response_model=List[Product], tags=["products"])
# Devuelve todos los productos
async def get_products():
    return products

@app.get("/products/{product_id}", response_model=Product, tags=["products"])
# Devuelve los detalles de un producto específico
async def get_product(product_id: int):
    for p in products:
        if p.id == product_id:
            return p
    raise HTTPException(404, "Producto no encontrado")

@app.get("/products/new", response_model=List[Product], tags=["products"])
# Devuelve los productos marcados como nuevos
async def get_new_products():
    return [p for p in products if p.is_new]

@app.get("/products/promo", response_model=List[Product], tags=["products"])
# Devuelve los productos en promoción
async def get_promo_products():
    return [p for p in products if p.is_promo]

@app.post("/products", response_model=Product, tags=["products"], dependencies=[Depends(role_required(Role.admin, Role.maintainer))])
# Agrega un nuevo producto al catálogo (requiere rol admin o mantenedor)
async def add_product(product: Product):
    products.append(product)
    return product

@app.post("/orders", tags=["orders"])
# Realiza una orden de compra y genera una sesión de pago con Stripe
async def place_order(order: OrderRequest, current: User = Depends(role_required(Role.client, Role.admin, Role.store_manager))):
    product = next((p for p in products if p.id == order.product_id), None)
    if not product:
        raise HTTPException(404, "Producto no encontrado")

    total_clp = product.price_clp * order.quantity

    if order.currency == "USD":
        rate = await convert_clp_to_usd(total_clp)
        amount = rate
        currency = "usd"
    else:
        amount = int(total_clp)
        currency = "clp"

    try:
        checkout = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="payment",
            line_items=[
                {
                    "price_data": {
                        "currency": currency,
                        "product_data": {"name": product.name},
                        "unit_amount": amount,
                    },
                    "quantity": order.quantity,
                }
            ],
            success_url="https://ferremas.cl/checkout/success",
            cancel_url="https://ferremas.cl/checkout/cancel",
            metadata={"user": current.username, "product_id": product.id},
        )
    except stripe.error.StripeError as e:
        raise HTTPException(502, f"Stripe error: {e.user_message}")

    return {"checkout_url": checkout.url}

@app.post("/contact", tags=["contact"])
# Envia un mensaje de contacto a un vendedor
async def contact_seller(request: ContactRequest):
    seller = next((s for s in sellers if s.id == request.seller_id), None)
    if not seller:
        raise HTTPException(404, "Vendedor no encontrado")
    return {"message": f"Se ha enviado tu solicitud a {seller.email}"}

async def convert_clp_to_usd(amount_clp: float) -> int:
# Convierte CLP a USD usando API externa y retorna el valor en dólares
    async with httpx.AsyncClient(timeout=5) as client:
        resp = await client.get(FX_API, params={"from": "CLP", "to": "USD", "amount": amount_clp})
        resp.raise_for_status()
        usd = resp.json()["result"]
        return int(round(usd * 100))

@app.get("/health", tags=["meta"])
# Endpoint para verificar que la API esté activa
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow()}

app = app
