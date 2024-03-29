package com.example.springsecuritydemo.service;

import com.example.springsecuritydemo.entity.Role;
import com.example.springsecuritydemo.entity.User;
import com.example.springsecuritydemo.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Optional;

/**
 * @author Mertcan Özarslan
 */
@AllArgsConstructor
@Service
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> byUsername = userRepository.findByUsername(username);

        return byUsername.orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    public void createUserWithRole() {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String hashedPassword = bCryptPasswordEncoder.encode("test");
        HashSet<Role> roles = new HashSet<>();
        roles.add(new Role("ROLE_ADMIN"));
        User user = new User(1L, "test2", hashedPassword, roles);
        userRepository.save(user);
    }
}

