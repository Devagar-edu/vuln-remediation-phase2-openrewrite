package com.example.vulnerable.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.sql.Connection;
import java.util.HashMap;
import java.util.Map;

@RestController
public class DatabaseController {

    @Autowired
    private DataSource dataSource;

    @GetMapping("/db-test")
    public ResponseEntity<Map<String, String>> testDatabase() {
        Map<String, String> response = new HashMap<>();
        
        try (Connection connection = dataSource.getConnection()) {
            if (connection != null && !connection.isClosed()) {
                response.put("status", "SUCCESS");
                response.put("message", "Database connection successful");
                response.put("database", connection.getMetaData().getDatabaseProductName());
            } else {
                response.put("status", "FAILED");
                response.put("message", "Database connection is closed");
            }
        } catch (Exception e) {
            response.put("status", "ERROR");
            response.put("message", "Database connection failed: " + e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }
}
