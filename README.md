# Study_Spring-Security
### 인프런 스프링 시큐리티 (백기선)
https://www.inflearn.com/course/%EB%B0%B1%EA%B8%B0%EC%84%A0-%EC%8A%A4%ED%94%84%EB%A7%81-%EC%8B%9C%ED%81%90%EB%A6%AC%ED%8B%B0/dashboard
-----

## [Settings]
#### Project Name
* Study_spring-security
#### java
* zulu jdk 11
#### gradle
* IDEA gradle wrapper
#### Spring boot
* 2.3.2
#### Junit
* build path (No tests found for given includes) 에러 발생시
  * IDEA 툴에서 gradle 설정 변경 (또는 기존 Gradle default 빌드 패스 확인)
  * command + , > Build, Execution, Deployment > Build Tools > Gradle
    * Build and run using, Run tests using을 IntelliJ IDEA로 변경
-----

### Spring Security

#### 예제 설명
* 홈 페이지
  * /
  * 인증된 사용자도 접근할 수 있으며 인증하지 않은 사용자도 접근 가능
  * 인증된 사용자가 로그인 한 경우에는 이름을 출력

* 정보
  * /info
  * 이 페이지는 인증을 하지 않고도 접근할 수 있으며, 인증을 한 사용자도 접근 가능

* 대시보드
  * /dashboard
  * 이 페이지는 반드시 로그인 한 사용자만 접근 가능
  * 인증하지 않은 사용자가 접근할 시 로그인 페이지로 이동

* 어드민
  * /admin
  * 이 페이지는 반드시 ADMIN 권한을 가진 사용자만 접근 가능
  * 인증하지 않은 사용자가 접근할 시 로그인 페이지로 이동
  * 인증은 거쳤으나, 권한이 충분하지 않은 경우 에러 메시지를 출력

#### Spring Security 추가
* 의존성 추가
  * ``` implementation group: 'org.springframework.boot', name: 'spring-boot-starter-security' ```

* 기본 로그인 정보
  * User
    * user
  * Password
    * ``` Using generated security password: f3c87726-e8df-4c6a-944a-de00715978f1 ``` 같이 콘솔에 출력됨

#### Spring Security 설정
* 설정 파일 생성 (SecurityConfig)
  * ```
    @Configuration
    @EnableWebSecurity
    public class SecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // 메서드 체이닝 방식
            http.authorizeRequests()
                    .mvcMatchers("/", "info").permitAll()
                    .mvcMatchers("/admin").hasRole("ADMIN")
                    .anyRequest().authenticated()
                    .and()
                    .formLogin()
                    .and()
                    .httpBasic();
        }
    }
    ```

#### In-memory 사용자 추가
* 기본 생성되던 유저 정보
  * UserDetailsServiceAutoConfiguration
  * SecurityProperties

* Spring Security Properties를 사용해 유저 정보 변경 가능 (권장하지 않음)
  * application.properties(yaml) 파일에 설정
    * spring.security.user.name=admin
    * spring.security.user.password=123
    * spring.security.user.roles=ADMIN
  * 인메모리 설정시 위 방법으로 로그인 못함

* In-memory 설정
  * 설정 파일에 설정 추가 (SecurityConfig)
  * ```
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("jaenyeong").password("{noop}123").roles("USER")
                .and()
                .withUser("admin").password("{noop}!@#").roles("ADMIN");
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    ```

#### JPA 연동
* In-memory가 아닌 DB에 유저 정보를 가져와 처리
  * 개발자 편의대로 UserDetailService를 구현
    * Repository가 아닌 DAO를 사용해 구현해도 무관
      * DB 타입(RDBMS, NoSQL 등)은 상관 없음

* 의존성 추가
  * JPA
    * ``` implementation group: 'org.springframework.boot', name: 'spring-boot-starter-data-jpa' ```
  * H2
    * ``` testImplementation group: 'com.h2database', name: 'h2', version: '1.4.200' ```

* 예제 소스 구현
  * account 패키지 생성
    * Account 클래스
    * AccountRepository 인터페이스
    * AccountService 클래스
    * AccountController 클래스

* 예제 회원 가입 URI
  * http://localhost:8080/account/USER/jaenyeong/123
  * http://localhost:8080/account/ADMIN/admin/123

#### PasswordEncoder
* 단방향 암호화 알고리즘을 사용해 비밀번호 저장
  * 스프링 시큐리티가 제공하는 PasswordEndoer는 특정한 포맷으로 동작
  * {id}encodedPassword
  * 다양한 해싱 전략의 패스워드를 지원할 수 있다는 장점이 있음

* SecurityConfig 파일에 PasswordEncoder 빈 등록
  * NoOpPasswordEncoder 사용 (권장하지 않음)
    * ```
      @Bean
      public PasswordEncoder passwordEncoder() {
          return NoOpPasswordEncoder.getInstance();
      }
      ```
    * 비밀번호가 평문 그대로 저장됨
  * PasswordEncoderFactories 사용 (사용 권장)
    * ```
      @Bean
      public PasswordEncoder passwordEncoder() {
          return PasswordEncoderFactories.createDelegatingPasswordEncoder();
      }
      ```
    * 기본 전략인 bcrypt로 암호화 해서 저장하며 비교할 때는 {id}를 확인해서 다양한 인코딩을 지원

#### Spring Security Test
* 의존성 추가
  * ```
    testImplementation group: 'org.springframework.security', name: 'spring-security-test', version: '5.3.3.RELEASE'
    ```

* RequestPostProcessor를 사용해서 테스트 하는 방법
  * with(user(“user”))
  * with(anonymous())
  * with(user(“user”).password(“123”).roles(“USER”, “ADMIN”))
  * 자주 사용하는 user 객체는 리팩토리으로 빼내서 재사용 가능

* 애노테이션을 사용하는 방법
  * @WithMockUser
  * @WithMockUser(roles=”ADMIN”)
  * 커스텀 애노테이션을 만들어 재사용 가능

* 폼 로그인 / 로그아웃 테스트
  * ``` perform(formLogin()) ```
  * ``` perform(formLogin().user("admin").password("pass")) ```
  * ``` perform(logout()) ```

* 응답 유형 확인
  * ``` authenticated() ```
  * ``` unauthenticated() ```

* 테스트 메서드 마다 동일한 계정 생성, 따라서 테스트 객체 전체 테스트시 에러
  * @Transactional 애노테이션 태깅
  * Spring 패키지와 Javax 패키지 모두 사용 가능
