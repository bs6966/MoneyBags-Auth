package com.oracle.moneybagsauth.services;

import com.oracle.moneybagsauth.dtos.requests.RegisterRequest;
import com.oracle.moneybagsauth.models.Authority;
import com.oracle.moneybagsauth.models.Role;
import com.oracle.moneybagsauth.models.User;
import com.oracle.moneybagsauth.repositories.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@AllArgsConstructor
@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public boolean register(RegisterRequest req) {
        if (userRepository.findByUsername(req.getUsername()).isPresent()) {
            return false;
        }

        User user = new User();
        user.setUsername(req.getUsername());
        user.setPassword(passwordEncoder.encode(req.getPassword()));

        Set<Authority> roles = (req.getRoles() == null || req.getRoles().isEmpty())
                ? Set.of(Authority.TELLER)
                : req.getRoles();

        Set<Role> granted = roles.stream().map(a -> {
            Role r = new Role();
            r.setAuthority(a);
            r.setUser(user);
            return r;
        }).collect(Collectors.toSet());

        user.setAuthorities(granted);
        userRepository.save(user);
        return true;
    }
}
