package com.jaenyeong.spring_security.springdata;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface BookRepository extends JpaRepository<Book, Integer> {
	@Query("SELECT b FROM Book b WHERE b.author.id = ?#{principal.account.id}")
	List<Book> findCurrentUserBooks();
}
