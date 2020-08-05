package com.jaenyeong.spring_security.form;

//import com.jaenyeong.spring_security.account.Account;
//import com.jaenyeong.spring_security.account.AccountContext;

import com.jaenyeong.spring_security.common.SecurityLogger;
import org.springframework.scheduling.annotation.Async;
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

	// @Async 애노테이션 태깅시 특정 빈에 메서드 호출 시 별도 스레드를 생성하여 비동기적 호출
	// 하지만 스레드가 동일하기 때문에 @Async 애노테이션을 태깅한다고 바로 비동기 처리가 되지 않음
	// 비동기처리를 하려면 @EnableAsync 애노테이션을 태깅
	@Async
	public void asyncService() {
		try {
			SecurityLogger.log("Async service");
			System.out.println("Async service is called");
			Thread.sleep(3_000L);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
