package com.jaenyeong.spring_security.config;

import com.jaenyeong.spring_security.account.AccountService;
import com.jaenyeong.spring_security.common.LoggingFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;

@Configuration
@EnableWebSecurity
@Order(Ordered.LOWEST_PRECEDENCE - 100)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	// 빈으로 등록 되어 있는 경우 명시적으로 알려주지 않아도 됨
	@Autowired
	AccountService accountService;

	@Bean
	public PasswordEncoder passwordEncoder() {
		// 사용금지 (평문 그대로 저장되기 때문에)
//		return NoOpPasswordEncoder.getInstance();
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	// 리소스 필터 설정
	@Override
	public void configure(WebSecurity web) throws Exception {
//		web.ignoring().mvcMatchers("/favicon.ico");

		web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
		// 이와 같이도 사용 가능
//		web.ignoring().requestMatchers(PathRequest.toH2Console());
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

	// expressionHandler 커스터마이징 (accessDecisionManager 커스터마이징 간소화)
	public SecurityExpressionHandler expressionHandler() {
		RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
		roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

		DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
		handler.setRoleHierarchy(roleHierarchy);

		return handler;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		// 메서드 체이닝 방식
//		http.authorizeRequests()
//				.mvcMatchers("/", "info").permitAll()
//				.mvcMatchers("/admin").hasRole("ADMIN")
//				.anyRequest().authenticated()
//				.and()
//				.formLogin()
//				.and()
//				.httpBasic();

		// 커스터마이징 필터 추가 (맨 앞에 설정)
		http.addFilterBefore(new LoggingFilter(), WebAsyncManagerIntegrationFilter.class);

		http.authorizeRequests()
				.mvcMatchers("/", "/info", "/account/**", "/signup").permitAll()
				.mvcMatchers("/admin").hasRole("ADMIN")
				.mvcMatchers("/user").hasRole("USER")
				// 리소스 설정 추가 (권장하지 않음)
//				.requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
				.anyRequest().authenticated()
				// 커스터마이징 accessDecisionManager 설정
//				.accessDecisionManager(accessDecisionManager())
				// 커스터마이징 expressionHandler 설정 (accessDecisionManager 커스터마이징 대신)
				.expressionHandler(expressionHandler())
		;

		// 로그인 폼 설정
//		http.formLogin();

		// 로그인 폼 커스터마이징
		http.formLogin()
//				.usernameParameter("my-username")
//				.passwordParameter("my-password")
				// 로그인 폼 페이지 설정
				// 설정시 DefaultLoginPageGeneratingFilter, DefaultLogoutPageGeneratingFilter가 빠지게 되어 있음
				.loginPage("/login")
				// permitAll 설정 안하면 리디렉션만 계속 반복
				.permitAll();

		http.httpBasic();

		// CSRF Off 설정
//		http.csrf().disable();

		// Logout 설정
		http.logout()
				// 로그아웃 처리(트리거)하는 URL
				.logoutUrl("/logout")
				// 로그아웃 처리 후 이동할 URL
				.logoutSuccessUrl("/")
				// 추가 처리할 핸들러
//				.addLogoutHandler()
				// 로그아웃 성공시 핸들러 직접 구현하여 설정
//				.logoutSuccessHandler()
				// 로그아웃을 처리(트리거)하는 requestMatcher
//				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
				// 로그아웃 후에 httpSession 무효화 여부 (기본값 true)
				.invalidateHttpSession(true)
				// 로그아웃 후에 쿠키 삭제
				.deleteCookies();

		// 익명 설정
//		http.anonymous().principal("anonymousUser");

		// 세션 변조 설정
		http.sessionManagement()
				// 세션 생성 전략 설정
//				.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // 기본
				.sessionFixation()
				.changeSessionId()
				// 로그 아웃 등 유효하지 않은 세션 경우 설정
				.invalidSessionUrl("/login")
				// 세션 개수 제한 (기존 세션 로그아웃)
				.maximumSessions(1)
				// 세션 만료시
				.expiredUrl("/login")
				// 기존 세션을 지키고 새로운 세션 로그인 방지 (기본값 false)
				// true 설정시 새로운 로그인 막음
				.maxSessionsPreventsLogin(false);

		// 인가 예외 페이지 설정
		http.exceptionHandling()
				.accessDeniedPage("/access-denied")
				// 별도의 클래스로 분리하고 단위 테스트를 추가하는 것이 더 바람직
				.accessDeniedHandler((request, response, accessDeniedException) -> {
					UserDetails principal =
							(UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

					String username = principal.getUsername();
					System.out.println(username + " is denied to access " + request.getRequestURI());
					response.sendRedirect("/access-denied");
				});

		// rememberMe 설정
		http.rememberMe()
				// 2주
				.tokenValiditySeconds(1209600)
				// HTTPS 적용
//				.useSecureCookie(true)
				// 로그인시 파라미터를 같이 넘기지 않더라도 로그인을 기억 시킴 (기본값 false)
				.alwaysRemember(true)
				.userDetailsService(accountService)
				.key("remember-me-sample");

		// 기본적으로 ThreadLocal을 사용
		// 현재 스레드에서 하위 스레드 사용시 SecurityContext가 공유됨
		SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
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
