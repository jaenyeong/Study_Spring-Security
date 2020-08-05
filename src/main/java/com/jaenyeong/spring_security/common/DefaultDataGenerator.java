package com.jaenyeong.spring_security.common;

import com.jaenyeong.spring_security.account.Account;
import com.jaenyeong.spring_security.account.AccountService;
import com.jaenyeong.spring_security.springdata.Book;
import com.jaenyeong.spring_security.springdata.BookRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class DefaultDataGenerator implements ApplicationRunner {

	@Autowired
	AccountService accountService;

	@Autowired
	BookRepository bookRepository;

	@Override
	public void run(ApplicationArguments args) throws Exception {
		// jaenyeong - spring
		// noah - hibernate
		Account jaenyeong = createUser("jaenyeong");
		Account noah = createUser("noah");

		createBook("spring", jaenyeong);
		createBook("hibernate", noah);
	}

	private void createBook(String title, Account author) {
		Book book = new Book();
		book.setTitle(title);
		book.setAuthor(author);
		bookRepository.save(book);
	}

	private Account createUser(String username) {
		Account account = new Account();
		account.setUsername(username);
		account.setPassword("123");
		account.setRole("USER");
		return accountService.createNewAccount(account);
	}
}
