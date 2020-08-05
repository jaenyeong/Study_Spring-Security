package com.jaenyeong.spring_security.account;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/signup")
public class SignupController {

	@Autowired
	AccountService accountService;

	@GetMapping
	public String signupForm(Model model) {
		model.addAttribute("account", new Account());
		return "signup";
	}

	@PostMapping
	public String processSignup(Account account) {
		account.setRole("USER");
		accountService.createNewAccount(account);
		return "redirect:/";
	}
}
