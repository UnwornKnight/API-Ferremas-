Este script es una API REST construida con FastAPI para una empresa ficticia llamada Ferremas, una distribuidora de productos de ferretería en Chile. El propósito de la API es ofrecer funcionalidades básicas para gestionar productos, sucursales, pedidos y pagos desde una plataforma web.

Primero, se configuran las dependencias clave: claves secretas para firmar JWT y autenticar en Stripe, además de un endpoint externo para conversión de divisas de CLP a USD. También se establece el esquema de autenticación OAuth2 con tokens JWT.

Luego se definen los modelos de datos usando Pydantic. Hay modelos para usuarios, sucursales (branches), vendedores (sellers), productos, pedidos y mensajes de contacto. También se define un Enum con roles específicos para cada tipo de usuario: desde administradores hasta cuentas de servicio.

Los datos están simulados en memoria. Hay usuarios de prueba, un par de sucursales, vendedores asignados y un catálogo simple de productos con atributos como nombre, precio, si es nuevo o si está en promoción.

En la sección de seguridad, hay funciones para verificar contraseñas con bcrypt, autenticar usuarios y generar tokens JWT válidos. También hay un decorador que restringe el acceso a ciertos endpoints según el rol del usuario.

Los endpoints expuestos son los siguientes:

/auth/login permite a los usuarios autenticarse y obtener un token JWT.

/branches, /branches/{id}, y /branches/{id}/sellers sirven para consultar las sucursales y sus vendedores.

/products, /products/{id}, /products/new y /products/promo muestran el catálogo completo y filtrado.

/products (POST) permite agregar productos nuevos pero solo si el usuario tiene rol de admin o mantenedor.

/orders genera una orden de compra y redirige al cliente a una sesión de pago de Stripe. Si se selecciona USD como moneda, se realiza una conversión previa usando una API externa.

/contact permite a un cliente enviar un mensaje a un vendedor específico.

Finalmente, el endpoint /health sirve como verificación rápida del estado del sistema.

El flujo de seguridad está bien definido: los usuarios se autentican, obtienen un token JWT, y lo usan para acceder a rutas protegidas. Se aplican restricciones de rol cuando es necesario.