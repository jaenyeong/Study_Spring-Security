package com.jaenyeong.spring_security.account;

import org.springframework.security.test.context.support.WithMockUser;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

// @WithMockUser 커스터마이징한 애노테이션 생성
@Retention(RetentionPolicy.RUNTIME)
@WithMockUser(username = "jaenyeong", roles = "USER")
public @interface WithUser {
}
