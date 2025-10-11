import fastapi as FastAPI

app = FastAPI.FastAPI()

# додаємо маршрути з файлу employee.py
app.include_router(employee.router)
