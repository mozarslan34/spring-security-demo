package com.example.springsecuritydemo.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

/**
 * @author Mertcan Özarslan
 */

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "role_test")
public class Role implements GrantedAuthority {
    @Id
    private String role;

    @Override
    public String getAuthority() {
        return role;
    }
}
