import fastapi as FastAPI
from src.middlewares import error_handler

app = FastAPI.FastAPI()

# додаємо маршрути з файлу employee.py
app.include_router(employee.router)


# Додаємо middleware
app.add_middleware(error_handler.ErrorHandlerMiddleware)

# Реєструємо глобальний exception handler
error_handler.setup_exception_handlers(app)