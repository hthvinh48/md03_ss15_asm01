package com.example.hrm.config;

import com.example.hrm.entity.Employee;
import com.example.hrm.repository.EmployeeRepository;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.util.List;

@Component
@RequiredArgsConstructor
public class DataSeeder implements CommandLineRunner {
    private final EmployeeRepository employeeRepository;

    @Override
    public void run(String @NonNull ... args) {
        if (employeeRepository.count() > 0) return;

        employeeRepository.saveAll(List.of(
                new Employee(null, "Nguyen Van A", new BigDecimal("15000000")),
                new Employee(null, "Tran Thi B", new BigDecimal("18500000")),
                new Employee(null, "Le Van C", new BigDecimal("22000000"))
        ));
    }
}
