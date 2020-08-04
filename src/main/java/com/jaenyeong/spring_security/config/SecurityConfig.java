package com.jaenyeong.spring_security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;

@Configuration
@EnableWebSecurity
@Order(Ordered.LOWEST_PRECEDENCE - 100)
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

	// accessDecisionManager 커스터마이징
//	public AccessDecisionManager accessDecisionManager() {
//		// AccessDecisionManager는 Voter(WebExpressionVoter) 사용
//		// Voter는 Handler(DefaultWebSecurityExpressionHandler) 사용
//		RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
//		roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
//
//		DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
//		handler.setRoleHierarchy(roleHierarchy);
//
//		WebExpressionVoter webExpressionVoter = new WebExpressionVoter();
//		webExpressionVoter.setExpressionHandler(handler);
//
//		List<AccessDecisionVoter<? extends Object>> voters = Collections.singletonList(webExpressionVoter);
//
//		return new AffirmativeBased(voters);
//	}

	// expressionHandler 커스터마이징
	public SecurityExpressionHandler expressionHandler() {
		RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
		roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

		DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
		handler.setRoleHierarchy(roleHierarchy);

		return handler;
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
				.mvcMatchers("/user").hasRole("USER")
				.anyRequest().authenticated()
				// 커스터마이징 accessDecisionManager 설정
//				.accessDecisionManager(accessDecisionManager())
				// 커스터마이징 expressionHandler 설정 (accessDecisionManager 커스터마이징 대신)
				.expressionHandler(expressionHandler())
		;

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
