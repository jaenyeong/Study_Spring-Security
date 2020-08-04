package com.jaenyeong.spring_security.account;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccountController {

	@Autowired
	AccountService accountService;

	// 예제 회원 가입 URI
//  http://localhost:8080/account/USER/jaenyeong/123
//	http://localhost:8080/account/ADMIN/admin/123
	@GetMapping("/account/{role}/{username}/{password}")
	public Account createAccount(@ModelAttribute Account account) {
		return accountService.createNewAccount(account);
	}
}
