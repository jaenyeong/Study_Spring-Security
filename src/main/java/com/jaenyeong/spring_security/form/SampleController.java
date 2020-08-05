package com.jaenyeong.spring_security.form;

import com.jaenyeong.spring_security.account.AccountRepository;
import com.jaenyeong.spring_security.common.SecurityLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;
import java.util.concurrent.Callable;

@Controller
public class SampleController {

	@Autowired
	SampleService sampleService;

	@Autowired
	AccountRepository accountRepository;

	@GetMapping("/")
	public String index(Model model, Principal principal) {
		if (principal == null) {
			model.addAttribute("message", "Hello Spring Security");
		} else {
			model.addAttribute("message", "Hello ! " + principal.getName());
		}

		return "index";
	}

	@GetMapping("/info")
	public String info(Model model) {
		model.addAttribute("message", "Information Mapping");
		return "info";
	}

	@GetMapping("/dashboard")
	public String dashboard(Model model, Principal principal) {
		model.addAttribute("message", "Dashboard : " + principal.getName());

//		AccountContext.setAccount(accountRepository.findByUsername(principal.getName()));

		sampleService.dashboard();
		return "dashboard";
	}

	@GetMapping("/admin")
	public String admin(Model model, Principal principal) {
		model.addAttribute("message", "Admin : " + principal.getName());
		return "admin";
	}

	@GetMapping("/user")
	public String user(Model model, Principal principal) {
		model.addAttribute("message", "Hello User : " + principal.getName());
		return "user";
	}

	@GetMapping("/async-handler")
	@ResponseBody
	public Callable<String> asyncHandler() {
		// 2개의 SecurityLogger.log는 다른 스레드를 사용하지만 ContextHolder 정보가 같음을 보여줌
		SecurityLogger.log("MVC");

		return () -> {
			SecurityLogger.log("Callable");
			return "Async Handler";
		};

		// 결과 값
		// MVC
		//Thread : http-nio-8080-exec-5
		//Principal : org.springframework.security.core.userdetails.User@620b1fbc: Username: jaenyeong; Password: [PROTECTED]; Enabled: true; AccountNonExpired: true; credentialsNonExpired: true; AccountNonLocked: true; Granted Authorities: ROLE_USER
		//Callable
		//Thread : task-3
		//Principal : org.springframework.security.core.userdetails.User@620b1fbc: Username: jaenyeong; Password: [PROTECTED]; Enabled: true; AccountNonExpired: true; credentialsNonExpired: true; AccountNonLocked: true; Granted Authorities: ROLE_USER
	}

	@GetMapping("/async-service")
	@ResponseBody
	public String asyncService() {
		SecurityLogger.log("MVC, Before async service");
		sampleService.asyncService();
		SecurityLogger.log("MVC, After async service");
		return "Async Service";
	}
}
