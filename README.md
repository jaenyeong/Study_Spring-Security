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
-----

### Spring Security Architecture

#### SecurityContextHolder, Authentication
* SecurityContextHolder
  * SecurityContext 제공, 기본적으로 ThreadLocal을 사용
    * ThreadLocal은 한 스레드에 내에서 공유하는 저장소

* SecurityContext
  * Authentication

* Authentication
  * Principal과 GrantAuthority 제공
    * Principal
      * "누구"에 해당하는 정보
      * UserDetailsService에서 반환한 그 객체
      * 객체는 UserDetails 타입
    * GrantAuthority
      * "ROLE_USER", "ROLE_ADMIN"등 Principal이 가지고 있는 "권한"을 나타냄
      * 인증 이후, 인가 및 권한 확인할 때 이 정보를 참조

* UserDetails
  * 애플리케이션이 가지고 있는 유저 정보와 스프링 시큐리티가 사용하는 Authentication 객체 사이의 어댑터
* UserDetailsService
  * 유저 정보를 UserDetails 타입으로 가져오는 DAO (Data Access Object) 인터페이스

#### AuthenticationManager, Authentication
* AuthenticationManager (스프링 시큐리티에서 인증(Authentication) 처리)
  * Authentication 생성, 관리, 인증 처리 등
  * 부모 AuthenticationManager를 가지고 있음
  * ``` Authentication authenticate(Authentication authentication) throws AuthenticationException; ```
    * AuthenticationManager 인터페이스에는 authenticate 메서드 1개 밖에 없음 
    * 인자로 받은 Authentication이 유효한 인증인지 확인하고 Authentication 객체를 반환
    * 인증을 확인하는 과정에서 비활성 계정, 잠긴 계정, 잘못된 비번 등의 에러를 던질 수 있음
      * DisableException
      * LockedException
      * BadCredentialException

* AuthenticationManager 구현체
  * 일반적으로 ProviderManager 사용 (기본 구현체)
  * AuthenticationManager 인터페이스를 직접 구현하여 사용 가능

* ProviderManager (AuthenticationManager 인터페이스 구현체)
  * 로그인 처리 (authenticate 메서드)
  * 직접 인증 처리를 하는 것이 아니라 AuthenticationProvider에게 위임
  * 넘겨받은 Authentication 객체를 처리할 AuthenticationProvider를 찾기 위해 AuthenticationProvider 목록 순회
    * ProviderManager는 AnonymousAuthenticationProvider를 가지고 있음
    * AnonymousAuthenticationProvider는 인증 처리 못함
  * 적절한 Provider를 못찾은 경우 부모 ProviderManager에게 인증 요청
    * 부모 ProviderManager는 DaoAuthenticationProvider를 가지고 있음
    * AbstractUserDetailsAuthenticationProvider
    * DaoAuthenticationProvider의 authenticate 호출
      * UserDetailService(UserDetails)를 사용해 인증하는 Provider
        * UserDetails를 로드하여 로드된 정보(비밀번호 등)와 입력된 정보를 비교하여 인증 처리
      * 예제에서 작성한 UserDetailsService를 구현한 AccountService 사용

* 인자로 받은 Authentication
  * 정확히는 Authentication 인터페이스의 구현체
    * 기본적으로 UsernamePasswordAuthenticationToken 객체
  * 사용자가 입력한 인증에 필요한 정보(username, password)로 만든 객체 (폼 인증인 경우)
  * Authentication
    * Principal
      * jaenyeong
    * Credentials
      * 123

* 유효한 인증인지 확인
  * 사용자가 입력한 password가 UserDetailsService를 통해  
    읽어온 UserDetails 객체에 들어있는 password와 일치하는지 확인
  * 해당 사용자 계정이 잠겨 있진 않은지, 비활성 계정은 아닌지 등 확인

* Authentication 객체 반환
  * Authentication
    * Principal
      * UserDetailsService에서 리턴한 그 객체 (User)
    * Credentials
      * Null
    * GrantedAuthorities

#### ThreadLocal
* Java.lang 패키지에서 제공하는 스레드 범위 변수 (즉, 스레드 수준의 데이터 저장소)
  * 같은 스레드내에서만 공유
  * 스레드 영역 변수 (스레드마다 독립적)
  * 따라서 같은 스레드라면 해당 데이터를 메서드 매개변수로 넘겨줄 필요 없음
  * SecurityContextHolder의 기본 전략

* ```
  public class AccountContext {
      private static final ThreadLocal<Account> ACCOUNT_THREAD_LOCAL = new ThreadLocal<>();
  
      public static void setAccount(Account account) {
          ACCOUNT_THREAD_LOCAL.set(account);
      }
  
      public static Account getAccount() {
          return ACCOUNT_THREAD_LOCAL.get();
      }
  }
  ```

#### Authentication, SecurityContextHolder
* 최종적으로 반환된 Authentication 객체는 SecurityContextHolder에 삽입됨
  * 앱 전반에 걸쳐 사용

* UsernamePasswordAuthenticationFilter
  * 폼 인증을 처리하는 시큐리티 필터
  * 인증된 Authentication 객체를 SecurityContextHolder에 넣어주는 필터
  * 부모 필터로 전달 doFilter 실행
    * AbstractAuthenticationProcessingFilter
  * SecurityContextHolder.getContext().setAuthentication(authentication)
  * 예제
    * 인증 후 원래 접근하려던 대시보드 페이지로 리다이렉트

* SecurityContextPersistenceFilter
  * SecurityContext를 HTTP session에 캐시(기본 전략)하여 여러 요청에서 Authentication을 공유하는 필터
    * HttpSessionSecurityContextRepository에서 SecurityContext를 가져옴
    * 매 요청마다 SecurityContext를 넣어주고 요청이 끝날 때마다 비움
    * HTTP session이 날라가면 인증 정보가 날라감
  * SecurityContextRepository를 교체하여 세션을 HTTP session이 아닌 다른 곳에 저장하는 것도 가능
    * stateless
  * 예제
    * 인증 후 대시보드 페이지로 접근 시 SecurityContextPersistenceFilter가 다시 필터링

#### Spring Security Filter, FilterChainProxy
* Spring Security Filter가 AuthenticationManager(ProviderManager) 사용

* 스프링 시큐리티가 제공하는 필터 목록
  * 서블릿 필터를 구현했으나 서블릿에 등록되지 않고 스프링 내부적으로 사용되는 필터
    * WebAsyncManagerIntegrationFilter
    * SecurityContextPersistenceFilter
    * HeaderWriterFilter
    * CsrfFilter
    * LogoutFilter
    * UsernamePasswordAuthenticationFilter
    * DefaultLoginPageGeneratingFilter
    * DefaultLogoutPageGeneratingFilter
    * BasicAuthenticationFilter
    * RequestCacheAwareFilter
    * SecurityContextHolderAwareRequestFilter
    * AnonymousAuthenticationFilter
    * SessionManagementFilter
    * ExceptionTranslationFilter
    * FilterSecurityInterceptor

* Security Config
  * 시큐리티 필터 체인을 만드는 데 사용됨
  * 하나의 거대한 SecurityFilterChain이라고 볼 수 있음

* 위 모든 필터는 FilterChainProxy가 호출
  * doFilterInternal 메서드
    * getFilters 메서드
      * 반복하여 SecurityFilterChain(체인 안에 필터 목록)을 찾음
      * VirtualFilterChain

#### DelegatingFilterProxy, FilterChainProxy
* DelegatingFilterProxy
  * 일반적인 서블릿 필터
    * 서블릿에 등록됨
  * 서블릿 필터 처리를 스프링에 들어있는 빈으로 위임하고 싶을 때 사용하는 서블릿 필터
  * 타겟 빈 이름을 설정
  * 스프링 부트 없이 스프링 시큐리티 설정
    * AbstractSecurityWebApplicationInitializer를 사용해 등록
  * 스프링 부트를 사용할 때는 자동으로 등록됨 (@EnableAutoConfiguration을 이용)
    * SecurityFilterAutoConfiguration 클래스 로드, springSecurityFilterChain 빈 등록

* FilterChainProxy
  * 일반적으로 "springSecurityFilterChain" 이라는 이름의 빈으로 등록
  * 구체적으로 DelegatingFilterProxy가 처리를 FilterChainProxy 클래스에게 위임
  * 여러 필터체인 목록을 가지고 있음
    * 필터 목록을 순회하면서 필터링

#### AccessDecisionManager
* AccessDecisionManager (스프링 시큐리티에서 인가(Authorize) 처리)
  * 이미 인증된 사용자가 특정 리소스에 접근시 허용 여부를 판단하는 인터페이스
  * Access Control 결정을 내리는 인터페이스로 구현체 3가지를 기본으로 제공
    * AffirmativeBased (기본 전략)
      * 여러 Voter중에 한명이라도 허용하면 허용
        * Voter
          * 권한을 체크(판단)하는 객체
    * ConsensusBased
      * 다수결
    * UnanimousBased
      * 만장일치

* AccessDecisionVoter
  * 해당 Authentication이 특정한 Object에 접근할 때 필요한 ConfigAttributes를 만족하는지 확인
    * ConfigAttributes (권한)
      * HasROLE, permitAll 등
  * WebExpressionVoter
    * 웹 시큐리티에서 사용하는 기본 구현체 (ROLE_Xxxx가 매칭되는지 확인)
  * RoleHierarchyVoter
    * 계층형 ROLE 지원
    * ADMIN > MANAGER > USER

* AccessDecisionManager 또는 Voter를 커스터마이징 하는 방법
  * 계층형 ROLE 설정
    * ```
      @Configuration
      @EnableWebSecurity
      public class SecurityConfig extends WebSecurityConfigurerAdapter {
      
          public SecurityExpressionHandler expressionHandler() {
              RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
              roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
      
              DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
              handler.setRoleHierarchy(roleHierarchy);
      
              return handler;
          }
      
          @Override
          protected void configure(HttpSecurity http) throws Exception {
              http.authorizeRequests()
                      .mvcMatchers("/", "/info", "/account/**").permitAll()
                      .mvcMatchers("/admin").hasRole("ADMIN")
                      .mvcMatchers("/user").hasRole("USER")
                      .anyRequest().authenticated()
                      .expressionHandler(expressionHandler());
              http.formLogin();
              http.httpBasic();
          }
      }
      ```

#### FilterSecurityInterceptor
* AccessDecisionManager를 사용하여 Access Control 또는 예외 처리 하는 필터
  * 대부분의 경우 FilterChainProxy에 제일 마지막 필터로 들어있음

#### ExceptionTranslationFilter
* 필터 체인에서 발생하는 AccessDeniedException과 AuthenticationException을 처리하는 필터

* AuthenticationException 발생한 경우
  * AuthenticationEntryPoint 실행
  * AbstractSecurityInterceptor 하위 클래스에서 발생하는 예외만 처리
    * 예를 들어 FilterSecurityInterceptor
  * UsernamePasswordAuthenticationFilter에서 발생한 인증 에러는 내부적으로 처리됨
    * ExceptionTranslationFilter가 처리하지 않음
    * 세션에 에러를 담아둠
    * DefaultLoginPageGeneratingFilter가 로그인 페이지를 담아둘 때 세션에 담아둔 에러를 같이 보여줌

* AccessDeniedException 발생한 경우
  * 익명 사용자라면 AuthenticationEntryPoint 실행
    * 로그인 페이지로 이동 등
  * 익명 사용자가 아니면 AccessDeniedHandler에게 위임

#### 정리
* SecurityContextHolder
  * SecurityContext
    * Authentication
      * Principal
        * 사용자 정보
      * GrantedAuthorities
        * 권한

* 서블릿 컨테이너에 요청이 들어오면
  * 서블릿 필터중 DelegatingFilterProxy가 FilterChainProxy에게 위임
    * DelegatingFilterProxy
      * 스프링 부트 사용시 자동으로 등록됨
      * 스프링 시큐리티 적용시 AbstractSecurityWebApplicationInitializer를 사용해 등록
      * 스프링 빈에게 처리를 위임하는 필터
    * FilterChainProxy (필터 체인)
      * springSecurityFilterChain 이라는 이름으로 등록됨
      * 시큐리티 필터(체인) 목록을 가지고 있음
      * 필터(체인)은 WebSecurity로 만들어짐 (WebSecurityConfigurerAdapter)
        * 만들 때 HttpSecurity를 같이 사용해 만들어짐
  * UsernamePasswordAuthenticationFilter 필터가 인증 처리
    * 인증 (AuthenticationManager 사용)
      * AuthenticationManager
        * 인증 인터페이스
        * 일반적으로 구현체는 ProviderManager 사용
          * ProviderManager
            * 여러 AuthenticationProvider를 가지고 있음
            * AuthenticationProvider에게 위임하여 인증 처리
            * 대표적으로 DaoAuthenticationProvider
              * UserDetailsService 인터페이스를 사용
                * 데이터에서 읽어온 유저 정보를 사용해 입력된 정보와 비교해 인증
                * 인증시 SecurityContextHolder에 삽입하여 앱 전반에 걸쳐 사용
  * FilterSecurityInterceptor 필터가 인가 처리
    * 인가 (AccessDecisionManager 사용)
      * AccessDecisionManager
        * 인가 인터페이스
        * 일반적으로 affirmativeBased 사용 (기본 전략)
          * AccessDecisionVoter 목록으로 인가 처리를 위임
            * 인가를 판단하는 객체
          * WebExpressionVoter
            * SecurityExpressionHandler
-----
