# src/api/employee.py
from typing import List
from fastapi import APIRouter, HTTPException, Depends
from uuid import UUID

from src.models.employee import Employee, EmployeeService, get_employee_service

router = APIRouter()

# === GET /employees ===
@router.get("/employees", response_model=List[Employee])
def get_employees(service: EmployeeService = Depends(get_employee_service)):
    return service.get_employees()


# === GET /employees/{id} ===
@router.get("/employees/{employee_id}", response_model=Employee)
def get_employee(employee_id: UUID, service: EmployeeService = Depends(get_employee_service)):
    employee = service.get_employee(employee_id)
    if employee is None:
        raise HTTPException(status_code=404, detail="Employee not found")
    return employee


# === POST /employees ===
@router.post("/employees", response_model=Employee)
def create_employee(employee: Employee, service: EmployeeService = Depends(get_employee_service)):
    try:
        return service.create_employee(employee)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# === PUT /employees/{id} ===
@router.put("/employees/{employee_id}", response_model=Employee)
def update_employee(employee_id: UUID, updated_employee: Employee, service: EmployeeService = Depends(get_employee_service)):
    employee = service.update_employee(employee_id, updated_employee)
    if employee is None:
        raise HTTPException(status_code=404, detail="Employee not found")
    return employee


# === DELETE /employees/{id} ===
@router.delete("/employees/{employee_id}")
def delete_employee(employee_id: UUID, service: EmployeeService = Depends(get_employee_service)):
    success = service.delete_employee(employee_id)
    if not success:
        raise HTTPException(status_code=404, detail="Employee not found")
    return {"message": "Employee deleted successfully"}
