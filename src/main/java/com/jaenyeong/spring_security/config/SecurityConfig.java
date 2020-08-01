package com.jaenyeong.spring_security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	// 빈으로 등록 되어 있는 경우 명시적으로 알려주지 않아도 됨
//	@Autowired
//	AccountService accountService;

	@Bean
	public PasswordEncoder passwordEncoder() {
		// 사용금지 (평문 그대로 저장되기 때문에)
//		return NoOpPasswordEncoder.getInstance();
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
//		super.configure(http);

		// 메서드 체이닝 방식
//		http.authorizeRequests()
//				.mvcMatchers("/", "info").permitAll()
//				.mvcMatchers("/admin").hasRole("ADMIN")
//				.anyRequest().authenticated()
//				.and()
//				.formLogin()
//				.and()
//				.httpBasic();

		http.authorizeRequests()
				.mvcMatchers("/", "/info", "/account/**").permitAll()
				.mvcMatchers("/admin").hasRole("ADMIN")
				.anyRequest().authenticated();

		http.formLogin();
		http.httpBasic();
	}

	// In-memory에 직접 삽입 처리
//	@Override
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth.inMemoryAuthentication()
//				.withUser("jaenyeong").password("{noop}123").roles("USER")
//				.and()
//				.withUser("admin").password("{noop}!@#").roles("ADMIN");
//	}
//
//	@Bean
//	@Override
//	public AuthenticationManager authenticationManagerBean() throws Exception {
//		return super.authenticationManagerBean();
//	}

	// 빈으로 등록 되어 있는 경우 명시적으로 알려주지 않아도 됨
//	@Override
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth.userDetailsService(accountService);
//	}
}
