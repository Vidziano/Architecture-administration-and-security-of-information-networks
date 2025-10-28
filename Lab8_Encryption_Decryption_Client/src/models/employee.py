# src/models/employee.py
from uuid import uuid4, UUID
from pydantic import BaseModel, Field

class Employee(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    firstName: str
    lastName: str
    age: int

from typing import List, Optional

# Singleton EmployeeService
class EmployeeService:
    _instance = None  # Singleton instance

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(EmployeeService, cls).__new__(cls)
            cls._instance.employees = []  # In-memory storage
        return cls._instance

    def create_employee(self, employee: Employee) -> Employee:
        # перевіримо, чи вже існує працівник з такими ж даними
        for e in self.employees:
            if (e.firstName == employee.firstName and
                e.lastName == employee.lastName and
                e.age == employee.age):
                raise ValueError("Employee already exists")
        self.employees.append(employee)
        return employee

    def get_employees(self) -> List[Employee]:
        return self.employees

    def get_employee(self, employee_id: UUID) -> Optional[Employee]:
        return next((e for e in self.employees if e.id == employee_id), None)

    def update_employee(self, employee_id: UUID, updated_employee: Employee) -> Optional[Employee]:
        for idx, e in enumerate(self.employees):
            if e.id == employee_id:
                updated_employee.id = employee_id  # зберігаємо старий id
                self.employees[idx] = updated_employee
                return updated_employee
        return None

    def delete_employee(self, employee_id: UUID) -> bool:
        for idx, e in enumerate(self.employees):
            if e.id == employee_id:
                del self.employees[idx]
                return True
        return False


# Dependency injection for the singleton
def get_employee_service() -> EmployeeService:
    return EmployeeService()
