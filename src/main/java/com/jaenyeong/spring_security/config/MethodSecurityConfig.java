package com.jaenyeong.spring_security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true, jsr250Enabled = true)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {

	// 권한 계층 설정
	// 웹 시큐리티와 일반 시큐리티 설정은 다르게 적용되기 때문에 별도 설정
	@Override
	protected AccessDecisionManager accessDecisionManager() {
		RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
		roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

		AffirmativeBased accessDecisionManager = (AffirmativeBased) super.accessDecisionManager();
		accessDecisionManager.getDecisionVoters().add(new RoleHierarchyVoter(roleHierarchy));
		return accessDecisionManager;
	}
}
