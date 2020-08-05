package com.jaenyeong.spring_security.springdata;

import com.jaenyeong.spring_security.account.Account;

import javax.persistence.*;

@Entity
public class Book {
	@Id @GeneratedValue
	private Integer id;

	private String title;

	@ManyToOne
	private Account author;

	public Integer getId() {
		return id;
	}

	public Book setId(Integer id) {
		this.id = id;
		return this;
	}

	public String getTitle() {
		return title;
	}

	public Book setTitle(String title) {
		this.title = title;
		return this;
	}

	public Account getAuthor() {
		return author;
	}

	public Book setAuthor(Account account) {
		this.author = account;
		return this;
	}
}
