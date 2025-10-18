import fastapi as FastAPI
from src.middlewares import error_handler
from src.api import employee         
from src.api import rsa_api

app = FastAPI.FastAPI()

# додаємо маршрути з файлу employee.py
app.include_router(employee.router)


# Підключаємо новий роутер
app.include_router(rsa_api.router)

# Додаємо middleware
app.add_middleware(error_handler.ErrorHandlerMiddleware)

# Реєструємо глобальний exception handler
error_handler.setup_exception_handlers(app)

