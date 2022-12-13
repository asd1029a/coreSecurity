package io.security.corespringsecurity.domain;

import lombok.Data;

import javax.persistence.*;

@Entity
@Data
public class Account {

    @Id @Column(name = "account_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;
    private String email;
    private String age;
    private String role;
}
