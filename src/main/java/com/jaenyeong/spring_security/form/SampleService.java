package com.jaenyeong.spring_security.form;

//import com.jaenyeong.spring_security.account.Account;
//import com.jaenyeong.spring_security.account.AccountContext;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Collection;

@Service
public class SampleService {

	public void dashboard() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		// 인증을 한 사용자 (Principal은 UserDetails 타입)
//		Object principal = authentication.getPrincipal();
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();
		System.out.println("===================================");
		System.out.println(userDetails.getUsername());

		// 인증을 한 사용자가 가진 권한
		Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

		// Password와 같은 인증 시 필요한 증명서 (아마 로그인 후에는 빈 값일 가능성 있음)
		Object credentials = authentication.getCredentials();

		// 사용자 인증 여부
		boolean authenticated = authentication.isAuthenticated();

		// AccountContext
//		Account account = AccountContext.getAccount();
//		System.out.println("===================================");
//		System.out.println(account.getUsername());
	}
}
