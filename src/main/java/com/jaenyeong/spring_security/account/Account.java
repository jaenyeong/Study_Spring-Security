package com.jaenyeong.spring_security.account;

import org.springframework.security.crypto.password.PasswordEncoder;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity
public class Account {
	@Id @GeneratedValue
	private Integer id;

	@Column(unique = true)
	private String username;

	private String password;

	private String role;

	public Integer getId() {
		return id;
	}

	public Account setId(Integer id) {
		this.id = id;
		return this;
	}

	public String getUsername() {
		return username;
	}

	public Account setUsername(String username) {
		this.username = username;
		return this;
	}

	public String getPassword() {
		return password;
	}

	public Account setPassword(String password) {
		this.password = password;
		return this;
	}

	public String getRole() {
		return role;
	}

	public Account setRole(String role) {
		this.role = role;
		return this;
	}

	public void encodePassword(PasswordEncoder passwordEncoder) {
//		this.password = "{noop}" + this.password;
		this.password = passwordEncoder.encode(this.password);
	}
}
