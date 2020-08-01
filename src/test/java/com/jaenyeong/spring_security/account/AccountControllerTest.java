package com.jaenyeong.spring_security.account;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class AccountControllerTest {

	@Autowired
	MockMvc mockMvc;

	@Autowired
	AccountService accountService;

	// 범용
	@Test
	@WithAnonymousUser
	public void index_anonymous() throws Exception {
		mockMvc.perform(
				get("/")
//						.with(anonymous())
		)
				.andDo(print())
				.andExpect(status().isOk());
	}

	// 특정 유저 접근
	// 해당 유저로 로그인 되어 있다고 가정한 Mocking
	@Test
//	@WithMockUser(username = "jaenyeong", roles = "USER")
	@WithUser // @WithMockUser 커스터마이징
	public void index_user() throws Exception {
		mockMvc.perform(
				get("/")
//						.with(user("jaenyeong")
//								.roles("USER"))
		)
				.andDo(print())
				.andExpect(status().isOk());
	}

	// 어드민 페이지에 일반 유저 접근
	@Test
//	@WithMockUser(username = "jaenyeong", roles = "USER")
	@WithUser
	public void admin_user() throws Exception {
		mockMvc.perform(
				get("/admin")
//						.with(user("jaenyeong")
//								.roles("USER"))
		)
				.andDo(print())
				.andExpect(status().isForbidden());
	}

	// 어드민 페이지에 어드민 접근
	@Test
	@WithMockUser(username = "admin", roles = "ADMIN")
	public void admin_admin() throws Exception {
		mockMvc.perform(
				get("/admin")
//						.with(user("admin")
//								.roles("ADMIN"))
		)
				.andDo(print())
				.andExpect(status().isOk());
	}

	@Test
	// 동일한 계정을 계속 다른 테스트 메서드에서도 생성하고 있기 때문에 클래스 전체를 테스트시에 에러
	// 따라서 메서드별로 트랜잭션으로 묶어줌
	@Transactional
	public void login() throws Exception {
		String username = "jaenyeong";
		String password = "123";
		String userRole = "USER";

		Account saveUser = createUser(username, password, userRole);

		// success
		mockMvc.perform(
				formLogin()
						.user(username)
						.password(password))
				.andDo(print())
				.andExpect(authenticated());

		// fail
		mockMvc.perform(
				formLogin()
						.user(username)
						.password("12345"))
				.andDo(print())
				.andExpect(unauthenticated());
	}

	@Test
	// 동일한 계정을 계속 다른 테스트 메서드에서도 생성하고 있기 때문에 클래스 전체를 테스트시에 에러
	// 따라서 메서드별로 트랜잭션으로 묶어줌
	@Transactional
	public void login2() throws Exception {
		String username = "jaenyeong";
		String password = "123";
		String userRole = "USER";

		Account saveUser = createUser(username, password, userRole);

		// success
		mockMvc.perform(
				formLogin()
						.user(username)
						.password(password))
				.andDo(print())
				.andExpect(authenticated());

		// fail
		mockMvc.perform(
				formLogin()
						.user(username)
						.password("12345"))
				.andDo(print())
				.andExpect(unauthenticated());
	}

	private Account createUser(String username, String password, String userRole) {
		Account account = new Account();
		account.setUsername(username);
		account.setPassword(password);
		account.setRole(userRole);
		return accountService.createNewAccount(account);
	}
}
