import fastapi as FastAPI
from src.middlewares import error_handler
from src.api import employee, rsa_api, aes_api
from src.api import employee, rsa_api, aes_api, session_api


# Ініціалізація FastAPI
app = FastAPI.FastAPI()

# Підключення маршрутів (ендпоінтів)
app.include_router(employee.router)   # залишилось із ЛР6
app.include_router(rsa_api.router)    
app.include_router(aes_api.router)    
app.include_router(session_api.router)

# Підключення middleware та глобальних обробників помилок
app.add_middleware(error_handler.ErrorHandlerMiddleware)
error_handler.setup_exception_handlers(app)