package com.oracle.moneybagsauth.controllers;

import com.oracle.moneybagsauth.dtos.requests.RegisterRequest;
import com.oracle.moneybagsauth.dtos.response.RegisterResponse;
import com.oracle.moneybagsauth.services.UserService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "http://localhost:8000/")
@AllArgsConstructor
@RestController
@RequestMapping("/api/users")
public class UserController {
    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<? extends RegisterResponse> register(@Valid @RequestBody RegisterRequest req) {
        Long result = userService.register(req);
        if (result != null) {
            return new ResponseEntity<>(
                    new RegisterResponse(result, req.getUsername()),
                    HttpStatus.CREATED
            );
        }
        return  ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
    }
}
