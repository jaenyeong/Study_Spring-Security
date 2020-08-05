package com.jaenyeong.spring_security.form;

import com.jaenyeong.spring_security.account.Account;
import com.jaenyeong.spring_security.account.AccountService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class SampleServiceTest {

	@Autowired
	SampleService sampleService;

	@Autowired
	AccountService accountService;

	@Autowired
	AuthenticationManager authenticationManager;

	@Test
	public void dashboard() {
		Account account = new Account();
//		account.setRole("USER");
		// 권한 계층을 이해하지 못함
		// 따라서 권한 계층 설정을 별도로 작성해야 함
		account.setRole("ADMIN");
		account.setUsername("jaenyeong");
		account.setPassword("123");

		accountService.createNewAccount(account);

		// principal
		UserDetails userDetails = accountService.loadUserByUsername("jaenyeong");

		UsernamePasswordAuthenticationToken token =
				new UsernamePasswordAuthenticationToken(userDetails, "123");

		Authentication authentication = authenticationManager.authenticate(token);

		SecurityContextHolder.getContext().setAuthentication(authentication);

		// dashboard 메서드에 @Secured("ROLE_USER") 애노테이션이 태깅되지 않았으면 NullPointerException
		sampleService.dashboard();
	}

	@Test
	@WithMockUser
	public void dashboardWithMockUser() {
		// 테스트가 목적이라면 목 객체 생성 코드들을 @WithMockUser 애노테이션 태깅으로 줄일 수 있음
//		Account account = new Account();
//		account.setRole("USER");
//		account.setUsername("jaenyeong");
//		account.setPassword("123");
//
//		accountService.createNewAccount(account);
//
//		// principal
//		UserDetails userDetails = accountService.loadUserByUsername("jaenyeong");
//
//		UsernamePasswordAuthenticationToken token =
//				new UsernamePasswordAuthenticationToken(userDetails, "123");
//
//		Authentication authentication = authenticationManager.authenticate(token);
//
//		SecurityContextHolder.getContext().setAuthentication(authentication);

		sampleService.dashboard();
	}
}
