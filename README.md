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

### Web Application Security

#### Spring Security ignoring()
* WebSecurity의 ignoring()을 사용해서 시큐리티 필터 적용을 제외할 요청 설정 가능
  * SecurityConfig 파일 설정
    * ```
      @Override
      public void configure(WebSecurity web) throws Exception {
          web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
      }
      ```
    * 스프링 부트가 제공하는 PathRequest를 사용해 정적 자원 요청을 스프링 시큐리티 필터를 적용하지 않도록 설정

* 다른 방법으로 동일한 설정
  * SecurityConfig 파일 설정
    * ```
      http.authorizeRequests()
          .requestMatchers(PathRequest.toStaticResources()
          .atCommonLocations()).permitAll();
      ```
    * 위 설정도 같은 결과이지만 스프링 시큐리티 필터가 적용된다는 차이가 있음
      * 동적 리소스
        * http.authorizeRequests()에서 처리하는 것을 권장
        * 사용자에 대한 정보를 SecurityContextHolder에 담는 등 처리
      * 정적 리소스
        * WebSecurity.ignore()를 권장
        * 예외적인 정적 자원 (인증이 필요한 정적자원이 있는 경우)는 http.authorizeRequests() 사용 가능

#### [1] WebAsyncManagerIntegrationFilter (Async 웹 MVC를 지원하는 필터)
* 스프링 MVC의 Async 기능을 사용할 때에도 SecurityContext를 공유하도록 도와주는 필터
  * Async 기능
    * 핸들러에서 Callable을 리턴할 수 있는 기능
  * SecurityContext는 ThreadLocal을 사용하기 때문에 같은 스레드에서만 공유됨
    * Async 기능 사용시 다른 스레드를 사용하게 되는데 이때도 SecurityContext를 공유
  * PreProcess
    * SecurityContext를 설정
  * Callable
    * 비록 다른 스레드지만 그 안에서는 동일한 SecurityContext 참조 가능
  * PostProcess
    * SecurityContext를 정리(clean up)
      * SecurityContext는 요청이 끝나면 반드시 정리가 되어야 함

##### Spring Security, @Async
* @Async를 사용한 서비스를 호출하는 경우
  * 스레드가 다르기 때문에 SecurityContext를 공유받지 못함

* 예제
  * @Async 애노테이션 태깅시 특정 빈에 메서드 호출 시 별도 스레드를 생성하여 비동기적 호출
  * 하지만 스레드가 동일하기 때문에 @Async 애노테이션을 태깅한다고 바로 비동기 처리가 되지 않음
  * 비동기처리를 하려면 SpringSecurityApplication 클래스에 @EnableAsync 애노테이션을 태깅
  * SecurityContext 에러
    * principal 공유 에러 (NullPointerException)

* 해결
  * SecurityConfig 파일에 SecurityContextHolder 스트래티지 설정
    * protected void configure(HttpSecurity http) throws Exception 메서드
    * ```
      SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
      ```
    * SecurityContext를 하위(자식) 스레드에도 공유하는 전략
    * @Async를 처리하는 스레드에서도 SecurityContext를 공유받을 수 있음

#### [2] SecurityContextPersistenceFilter (SecurityContext 영속화 필터)
* SecurityContextRepository를 사용해 기존의 SecurityContext를 읽어오거나 초기화
  * 일반적으로 HTTP Session을 사용 (기본 전략)
  * Spring-Session과 연동하여 세션 클러스터를 구현 가능

* 동작 원리
  * SecurityContextPersistenceFilter가 SecurityContextRepository 인터페이스에게 위임하여 데이터를 읽어옴
    * 기본적으로 HttpSessionSecurityContextRepository 구현체 사용
  * HttpSession에 SecurityContext가 이미 저장되어 있다면 가져와 사용
    * 없다면 비어 있는 SecurityContext를 생성
  * 다른 인증 필터들보다 반드시 위에 선언 되어 있어야 함 (따라서 위치가 2번째)
    * 커스터마이징이 필요한 경우 위치 확인

#### [3] HeaderWriterFilter (시큐리티 관련 헤더 추가 필터)
* 응답 헤더에 시큐리티 관련 헤더를 추가해주는 필터
  * XContentTypeOptionsHeaderWriter
    * 마임 타입 스니핑 방어
      * 스니핑(Sniffing)
        * 해킹 유형 중 하나
        * 타인들의 패킷 교환을 엿듣는 해킹 방법 (네트워크 트래픽 도청 등)
  * XXssProtectionHeaderWriter
    * 브라우저에 내장된 XSS 필터 적용
  * CacheControlHeadersWriter
    * 캐시 히스토리 취약점 방어
  * HstsHeaderWriter
    * HTTPS로만 소통하도록 강제
  * XFrameOptionsHeaderWriter
    * Clickjacking 방어
      * Clickjacking
        * 웹 사용자가 자신이 클릭하고 있다고 인지하는 것과 다른 어떤 것을 클릭하게 속이는 악의적인 기법

* ```
  Cache-Control: no-cache, no-store, max-age=0, must-revalidate
  Content-Language: en-US
  Content-Type: text/html;charset=UTF-8
  Date: Sun, 04 Aug 2019 16:25:10 GMT
  Expires: 0
  Pragma: no-cache
  Transfer-Encoding: chunked
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  X-XSS-Protection: 1; mode=block
  ```

* 참고
  * X-Content-Type-Options
  * Cache-Control
  * X-XSS-Protection
  * HSTS
  * X-Frame-Options

#### [4] CsrfFilter (CSRF 공격 방지 필터)
* CSRF 공격 방지 필터 (의도한 사용자만 리소스를 변경할 수 있도록 허용하는 필터)
  * 인증된 유저의 계정을 사용해 악의적인 변경 요청을 만들어 보내는 기법
  * CORS를 사용할 때 특히 주의 해야함
    * 타 도메인에서 보내오는 요청을 허용하기 때문에
  * CSRF 토큰을 사용하여 방지
    * CSRF 토큰 값이 일치하는지 확인

* CSRF (Cross-site Request Forgery)
  * 사이트 간 요청 위조
  * 사용자의 의도와 무관하게 공격자가 의도한 행동을 수행
    * 특정 페이지에 보안을 취약하게 한다거나 수정, 삭제 등의 작업을 하게 만드는 공격 기법

* 사용하지 않을 때 설정
  * SecurityConfig 파일 설정
    * ```
      http.csrf().disable();
      ```

##### CSRF 토큰 사용 예제
* JSP에서 스프링 MVC가 제공하는 <form:form> 태그  
  또는 타임리프 2.1+ 버전을 사용할 때 폼에 CSRF 히든 필드가 기본 생성

* 예제
  * Signup.html
    * ```
      <!DOCTYPE html>
      <html lang="en" xmlns:th="http://www.thymeleaf.org">
      <head>
          <meta charset="UTF-8"/>
          <title>Signup page</title>
      </head>
      <body>
      <form action="/signup" th:action="@{/signup}" th:object="${account}" method="post">
          <p>Username :
              <label>
                  <input type="text" th:field="*{username}"/>
              </label></p>
          <p>Password :
              <label>
                  <input type="text" th:field="*{password}"/>
              </label></p>
          <p><input type="submit" value="signup"></p>
      </form>
      </body>
      </html>
      ```
  * SignupController
    * ```
      package com.jaenyeong.spring_security.account;
      
      import org.springframework.beans.factory.annotation.Autowired;
      import org.springframework.stereotype.Controller;
      import org.springframework.ui.Model;
      import org.springframework.web.bind.annotation.GetMapping;
      import org.springframework.web.bind.annotation.ModelAttribute;
      import org.springframework.web.bind.annotation.PostMapping;
      
      @Controller
      public class SignupController {
      
          @Autowired
          AccountService accountService;
      
          @GetMapping("/signup")
          public String signUpForm(Model model) {
              model.addAttribute("account", new Account());
              return "signup";
          }
      
          @PostMapping("/signup")
          public String processSignUp(@ModelAttribute Account account) {
              account.setRole("USER");
              accountService.createNew(account);
              return "redirect:/";
          }
      }
      ```
  * SignupControllerTest
    * ```
      @RunWith(SpringRunner.class)
      @SpringBootTest
      @AutoConfigureMockMvc
      public class SignupControllerTest {
      
          @Autowired
          MockMvc mockMvc;
      
          @Test
          public void signUpForm() throws Exception {
              mockMvc.perform(get("/signup"))
                      .andDo(print())
                      .andExpect(content().string(containsString("_csrf")));
          }
      
          @Test
          public void procesSignUp() throws Exception {
              mockMvc.perform(post("/signup")
                  .param("username", "jaenyeong")
                  .param("password", "123")
                  .with(csrf()))
                      .andExpect(status().is3xxRedirection());
          }
      }
      ```

* Get 요청인 경우 토큰 값을 확인하지 않음
  * Post 요청인 경우 토큰 값 확인

* Postman 요청시 401 error
   
#### [5] LogoutFilter (로그아웃 처리 필터)
* 로그아웃 처리 필터
  * 여러 LogoutHandler를 사용하여 로그아웃시 필요한 처리를 함
  * 이후에는 LogoutSuccessHandler를 사용하여 로그아웃 후처리

* 로그아웃 페이지 (Get 요청시)
  * DefaultLogoutPageGeneratingFilter

* LogoutHandler (Composite 타입)
  * CsrfLogoutHandler
  * SecurityContextLogoutHandler

* LogoutSuccessHandler
  * SimpleUrlLogoutSuccessHandler (기본)

* 로그아웃 필터 설정
  * SecurityConfig 파일 설정
    * ```
      // Logout 설정
      http.logout()
              // 로그아웃 처리(트리거)하는 URL
              .logoutUrl("/logout")
              // 로그아웃 처리 후 이동할 URL
              .logoutSuccessUrl("/")
              // 추가 처리할 핸들러
              // .addLogoutHandler()
              // 로그아웃 성공시 핸들러 직접 구현하여 설정
              // .logoutSuccessHandler()
              // 로그아웃을 처리(트리거)하는 requestMatcher
              // .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
              // 로그아웃 후에 httpSession 무효화 여부 (기본값 true)
              .invalidateHttpSession(true)
              // 로그아웃 후에 쿠키 삭제
              .deleteCookies();
      ```

#### [6] UsernamePasswordAuthenticationFilter (폼 인증 처리 필터)
* 폼 로그인을 처리하는 인증 필터
  * 사용자가 폼에 입력한 username과 password로 Authentcation을 생성
    * 생성한 Authentcation을 AuthenticationManager를 사용하여 인증을 시도
  * AuthenticationManager (ProviderManager)는 여러 AuthenticationProvider를 사용하여 인증을 시도
    * 그 중에 DaoAuthenticationProvider는 UserDetailsServivce를 사용하여  
      UserDetails 정보를 가져와 사용자가 입력한 password와 비교

* UsernamePasswordAuthenticationFilter 절차
  * 로그인 시도시 UsernamePasswordAuthenticationToken을 생성 (폼에 입력한 username, password 정보)
  * ProviderManager에서 여러 AuthenticationProvider를 순회하면서 처리할 수 있는 provider를 찾음
    * ProviderManager가 인증을 못한다면 상위(부모) ProviderManager에게 처리를 위임
  * 인증을 처리하는 provider(예를 들어 DaoAuthenticationProvider) UserDetails 정보를 가져와(DB 등) 비교
    * UsernamePasswordAuthenticationToken과 비교

#### [7] DefaultLoginPageGeneratingFilter (로그인 폼 페이지 필터)
* 기본 로그인 폼 페이지를 생성해주는 필터
  * GET /login 요청을 처리

* 커스터마이징
  * SecurityConfig 파일 설정
    * ```
      http.formLogin()
         .usernameParameter("my-username")
         .passwordParameter("my-password");
      ```
  * DefaultLoginPageGeneratingFilter, DefaultLogoutPageGeneratingFilter가 제거
    * 따라서 페이지(로그인, 로그아웃)를 직접 구현해야 함

##### 로그인/로그아웃 폼 커스터마이징
* 페이지 구현
  * login.html
    * ```
      <!DOCTYPE html>
      <html lang="en" xmlns:th="http://www.thymeleaf.org">
      <head>
          <meta charset="UTF-8"/>
          <title>Login page</title>
      </head>
      <body>
          <h1>Login</h1>
          <div th:if="${param.error}">
              Invalid username or password
          </div>
          <form action="/login" method="post" th:action="@{/login}">
              <p>Username :
                  <label>
                      <input type="text" name="username" />
                  </label>
              </p>
              <p>Password :
                  <label>
                      <input type="password" name="password" />
                  </label>
              </p>
              <p><input type="submit" value="login"></p>
          </form>
      </body>
      </html>
      ```
  * logout.html
    * ```
      <!DOCTYPE html>
      <html lang="en" xmlns:th="http://www.thymeleaf.org">
      <head>
          <meta charset="UTF-8"/>
          <title>Logout page</title>
      </head>
      <body>
          <h1>Logout</h1>
          <form action="/logout" method="post" th:action="@{/logout}">
              <p><input type="submit" value="logout"></p>
          </form>
      </body>
      </html>
      ```

* 시큐리티 설정
  * SecurityConfig 파일 설정
    * ```
      http.formLogin()
          .loginPage("/signin")
          .permitAll();
      ```
    * 직접 설정시 permitAll 설정

#### [8] DefaultLogoutPageGeneratingFilter (로그아웃 폼 페이지 필터)
* 기본 로그아웃 폼 페이지를 생성해주는 필터

#### [9] BasicAuthenticationFilter (Basic 인증 처리 필터)
* HttpBasic 인증 처리
  * 요청 헤더에 username, password를 담아 전송 브라우저 또는 서버가 그 값을 읽어서 인증하는 방식
    * Authorization
      * jaenyeong:123 
        * amFlbnllb25nOjEyMw== (BASE 64 인코딩 값)
  * 일반적으로 브라우저 기반 요청이 클라이언트의 요청을 처리할 때 자주 사용
  * 보안에 취약하기 때문에 반드시 HTTPS를 사용할 것을 권장
    * 요청이 스니핑 당한다면 인증 정보가 유출되어 위험

* curl 사용
  * ``` curl -u jaenyeong:123 http://localhost:8080 ```
    * 결과
      * ```
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8" />
            <title>Index page</title>
        </head>
        <body>
            <h1>Hello ! jaenyeong</h1>
        </body>
        </html>
        ```
  * ``` curl  http://localhost:8080/dashboard ```
    * 401 에러
      * ```
        {"timestamp":"2020-08-05T03:48:24.307+00:00",
         "status":401,
         "error":"Unauthorized",
         "message":"","path":"/dashboard"
        }%
        ```

* Base64 Encoding (인코딩)
  * Encoding 정의
    * 정보의 형태나 형식을 변환하는 처리, 처리 방식
    * 사용자가 입력한 정보(문자나 기호 등)를 컴퓨터가 이용할 수 있는 신호로 만드는 것
  * Base64 Encoding 정의 (64진법)
    * Binary Data를 Text로 변경하는 인코딩
    * Base64는 문자 코드의 영향을 받지 않는(ASCII 중 제어문자와 일부 특수문자를 제외)  
      공통 64개의 ASCII 영역의 문자(안전한 출력 문자)들로 이루어진 문자열로 변경
    * 8비트 이진 데이터(실행 파일이나, ZIP 파일 등)를  
      문자 코드에 영향을 받지 않는 공통 ASCII 영역의 문자들로만  
      이루어진 일련의 문자열로 바꾸는 인코딩 방식을 가리키는 개념
    * ASCII 문자들을 써서 표현할 수 있는 가장 큰 진법
  * 인코딩 방식
    * 일반적으로 처음 62개는 알파벳 A-Z, a-z와 숫자 0-9를 사용하며 마지막 두 개의 기호 차이만 존재
    * 처리 과정
      * 24비트의 버퍼 생성, 위쪽부터 바이트 데이터를 삽입
        * 24비트(3바이트)의 연속된 청크로 배열
      * 버퍼의 위쪽부터 6비트 단위로 잘라 Base64 테이블의 ASCII 문자로 변환
      * 남은 바이트가 3바이트(24비트) 미만이라면 버퍼의 남은 부분에 패딩 비트(0)가 추가됨
        * 인코딩 결과물에 ASCII에 없는 '=' 문자가 삽입된 것을 확인할 수 있음
      * 바이트로 구성된 3개의 문자를 인코딩하면 4개의 문자열을 얻을 수 있음
        * 3개의 octet을 4개의 인코딩된 문자로 변환
          * octet
            * 8개의 비트가 한데 모인 것 (초기 컴퓨팅 역사에서는 1바이트가 꼭 8비트를 의미하지 않았음)
            * 8비트를 명확히 표현하기 위해 사용했으나 현재는 바이트와 같은 의미
        * 예시
          * Man > TWFu
      * 디코딩은 반대 절차
  * 단점
    * Base64 인코딩은 본래 데이터에 비해 약 33%나 데이터 양이 증가
  * 사용 목적
    * 목적
      * 모든 바이트 값을 신뢰할 수 없는 통신 채널을 통해 Binary Data를 안전하게 전송할 수 있게 하는 것
      * 통신 과정에서 바이너리 데이터의 손실을 막기위해 사용됨
    * 기존 문제점
      * 문자를 전송하기 위한 Media(HTML, Email 등)를 이용해 플랫폼 독립적으로 바이너리 데이터를 전송할 때 문제 발생
        * ASCII는 7 bits 인코딩인데 나머지 1 bit를 처리하는 방식이 시스템 별로 상이
        * 일부 제어문자 (e.g. Line ending)의 경우 시스템 별로 다른 코드값을 가짐
      * 위 문제로 ASCII는 시스템간 데이터를 전달하기에 안전하지 않음
        * ASCII 유형에 데이터를 수신 후 바로 처리하는 것은 프로토콜, 시스템간 해석이 달라 데이터가 왜곡될 여지가 있음
    * Base64 사용시
      * Base64는 문자를 위한 Media(HTML, Email 등)에 바이너리 데이터를 포함해야 될 필요가 있을 때 사용
        * 포함된 바이너리 데이터가 시스템 독립적으로 동일하게 전송 또는 저장되는걸 보장하기 위해 사용
  * 주의
    * 텍스트를 ASCII로 인코딩하면 텍스트 문자열로 시작하여 일련의 바이트로 변환
    * Base64로 데이터를 인코딩하면 일련의 바이트로 시작하여 텍스트 문자열로 변환

#### [10] RequestCacheAwareFilter (요청 캐시 필터)
* 현재 요청과 관련 있는 캐시된 요청이 있는지 찾아서 적용하는 필터
  * 캐시된 요청이 없다면, 현재 요청 처리
  * 캐시된 요청이 있다면, 해당 캐시된 요청 처리

* 예시
  * localhost:8080/dashboard 접속시
    * 인증정보 판단 후 로그인 페이지로 이동
    * 로그인 후에 원래 접속하려던 대시보드 페이지로 이동할 때 사용됨

#### [11] SecurityContextHolderAwareRequestFilter (시큐리티 관련 서블릿 스펙 구현 필터)
* 시큐리티 관련 서블릿 API를 구현해주는 필터
  * HttpServletRequest#authenticate(HttpServletResponse)
    * 인증 여부 판단
  * HttpServletRequest#login(String, String)
    * 로그인 (authenticationManager를 사용하여 인증 처리)
  * HttpServletRequest#logout()
    * 로그아웃 (LogoutHandler 사용)
  * AsyncContext#start(Runnable)
    * SecurityContextHolder 지원
    * SecurityContext 정보를 하위 스레드에게 복사해서 공유

#### [12] AnonymousAuthenticationFilter (익명 인증 필터)
* 익명 Authentication을 생성해주는 필터
  * 현재 SecurityContext에 Authentication이 Null인 경우
    * "익명 Authentication"을 생성 후 삽입
  * Null이 아닌 경우
    * 아무일도 하지 않음
  * Null Object 패턴

* 커스터마이징
  * SecurityConfig 파일 설정
    * ```
      http.anonymous().principal("anonymousUser");
      ```

#### [13] SessionManagementFilter (세션 관리 필터)
* 세션 변조
  * 공격자가 특정 웹 서버에 접속하여 세션(쿠키) 아이디를 할당 받음
  * 공격자가 할당받은 세션(쿠키) 아이디를 일반 사용자에게 몰래 넘겨 일반 사용자가 그걸 이용하여 웹 서버에 접속하게 됨
  * 웹 서버는 공격자와 일반 사용자를 동일 세션으로 인식
  * 공격자는 일반 사용자 정보 취득 가능

* 세션 변조 방지 전략 설정 (sessionFixation)
  * none
  * newSession
    * 기존 세션에 담겨 있던 값(key, value 속성)들을 가져오지 않음
  * migrateSession (서블릿 3.0 이하 버전 컨테이너 사용시 기본값)
    * 인증이 됐을 때 새로운 세션 아이디를 생성
    * 기존 세션에 담겨 있던 값(key, value 속성)들을 새로운 세션에 복사
  * changeSessionId (서브릿 3.1 이상 버전 컨테이너 사용시 기본값)
    * 세션 아이디만 변경함

* 유효하지 않은 세션을 리다이렉트 시킬 URL 설정
  * invalidSessionUrl
    * 로그아웃 등

* 동시성 제어 (maximumSessions)
  * 추가 로그인을 막을지 여부 설정 (기본값, false)

* 세션 생성 전략 (sessionCreationPolicy)
  * IF_REQUIRED (기본 값)
    * 필요시 생성
  * NEVER
    * 만들지 않음, 기존에 있으면 사용
    * 세션을 아예 사용하지 않는 것이 아님
  * STATELESS
    * 세션을 사용하지 않을 때 (예를 들어 JWT 같은 토큰 사용시)
    * 캐시 등을 이용할 때 문제가 발생할 수 있음
      * 예를 들어 RequestCacheAwareFilter가 제대로 동작하지 않을 수 있음
      * 캐시를 세션에 저장하기 때문
  * ALWAYS
    * 항상 세션 생성

* 세션 변조 설정
  * SecurityConfig 파일 설정
   * ```
     http.sessionManagement()
             // 세션 생성 전략 설정
     //      .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // 기본
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
     ```

#### [14] ExceptionTranslationFilter (인증/인가 예외 처리 필터)
* 인증, 인가 에러 처리를 담당하는 필터
  * AuthenticationEntryPoint
  * AccessDeniedHandler

* ExceptionTranslationFilter가 FilterSecurityInterceptor 보다 앞에 있어야 함
  * FilterSecurityInterceptor를 감싸 실행되어야 함
  * FilterSecurityInterceptor
    * AccessDecisionManager 인터페이스(AffirmativeBased 구현체)를 사용하여 인가 처리
      * AuthenticationException (인증 예외)
        * AuthenticationEntryPoint를 사용해 예외 처리
        * 인증이 가능한 페이지로 이동시킴
      * AccessDeniedException (인가 예외)
        * AccessDeniedHandler를 사용해 예외 처리
        * 403 에러 등을 반환

* 설정
  * SecurityConfig 파일 설정
    * ```
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
      ```
  * access-denied 페이지 구현
    * ```
      <!DOCTYPE html>
      <html lang="en" xmlns:th="http://www.thymeleaf.org">
      <head>
          <meta charset="UTF-8" />
          <title>Access Denied page</title>
      </head>
      <body>
          <h1>
              <span th:text="${name}">Name</span>, you are not allowed to access to the page
          </h1>
      </body>
      </html>
      ```
  * AccessDeniedController 컨트롤러 구현
    * ```
      @Controller
      public class AccessDeniedController {
         
          @GetMapping("/access-denied")
          public String accessDenied(Principal principal, Model model) {
              model.addAttribute("name", principal.getName());
              return "access-denied";
          }
      }
      ```

#### [15] FilterSecurityInterceptor (인가 처리 필터)
* HTTP 리소스 시큐리티 인가 처리를 담당하는 필터
  * AccessDecisionManager를 사용하여 인가를 처리

* HTTP 리소스 시큐리티 설정
  * SecurityConfig 파일 설정
    * ```
      http.authorizeRequests()
                .mvcMatchers("/", "/info", "/account/**", "/signup").permitAll()
                .mvcMatchers("/admin").hasRole("ADMIN")
                .mvcMatchers("/user").hasRole("USER")
                // 리소스 설정 추가 (권장하지 않음)
      //		.requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                .anyRequest().authenticated()
                // 커스터마이징 accessDecisionManager 설정
      //		.accessDecisionManager(accessDecisionManager())
                // 커스터마이징 expressionHandler 설정 (accessDecisionManager 커스터마이징 대신)
                .expressionHandler(expressionHandler())
      ;
      ```
  * mvcMatchers (대표적인 패턴 매처)
    * 스프링 MVC 패턴 매처
    * regexMatcher, andMatcher 등과 조합
  * permitAll
    * 모두에게 허용
  * hasRole
    * 특정 Role 설정
  * hasAuthority
    * hasRole의 상위 개념 (좀 더 범용적인 개념)
  * anonymous
    * 익명 사용자만 지정
  * authenticated
    * 권한 상관 없이 인증만 되면 접근 가능
  * rememberMe
    * 사용자 세션이 종료된 후에 자동 로그인 처리하는 기능
  * fullyAuthenticated
    * rememberMe로 로그인한 사용자에게 다시 로그인을 요구

#### [16] RememberMeAuthenticationFilter (토큰 기반 인증 필터)
* 세션이 사라지거나 만료가 되더라도 쿠키 또는 DB를 사용하여 저장된 토큰 기반으로 인증을 지원하는 필터

* 설정
  * login.html 파일 수정 (체크박스 추가)
    * ```
      <p>Remember :
          <label>
              <input type="checkbox" name="remember-me" />
          </label>
      </p>
      ```
  * SecurityConfig 파일 설정
    * ```
      http.rememberMe()
              // 2주
              .tokenValiditySeconds(1209600)
              // HTTPS 적용
      //	  .useSecureCookie(true)
              // 로그인시 파라미터를 같이 넘기지 않더라도 로그인을 기억 시킴 (기본값 false)
              .alwaysRemember(true)
              .userDetailsService(accountService)
              .key("remember-me-sample");
      ```

#### 커스텀 필터 추가
* common 패키지에 LoggingFilter 클래스 구현
  * ```
    public class LoggingFilter extends GenericFilterBean {
    
    	private final Logger logger = LoggerFactory.getLogger(this.getClass());
    
    	@Override
    	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
    			throws IOException, ServletException {
    
    		StopWatch stopWatch = new StopWatch();
    		stopWatch.start(((HttpServletRequest) request).getRequestURI());
    
    		// 체인에게 요청 처리
    		// 다음 필터로 요청을 전달
    		chain.doFilter(request, response);
    
    		stopWatch.stop();
    		logger.info(stopWatch.prettyPrint());
    	}
    }
    ```
  * SecurityConfig 파일 설정
    * ```
      http.addFilterBefore(new LoggingFilter(), WebAsyncManagerIntegrationFilter.class);
      ```

#### 정리
* 순서
  1) WebAsyncManagerIntegrationFilter (Async 웹 MVC를 지원하는 필터)
  2) SecurityContextPersistenceFilter (SecurityContext 영속화 필터)
  3) HeaderWriterFilter (시큐리티 관련 헤더 추가 필터)
  4) CsrfFilter (CSRF 공격 방지 필터)
  5) LogoutFilter (로그아웃 처리 필터)
  6) UsernamePasswordAuthenticationFilter (폼 인증 처리 필터)
  7) DefaultLoginPageGeneratingFilter (로그인 폼 페이지 필터)
  8) DefaultLogoutPageGeneratingFilter (로그아웃 폼 페이지 필터)
  9) BasicAuthenticationFilter (Basic 인증 처리 필터)
  10) RequestCacheAwareFilter (요청 캐시 필터)
  11) SecurityContextHolderAwareRequestFilter (시큐리티 관련 서블릿 스펙 구현 필터)
  12) AnonymousAuthenticationFilter (익명 인증 필터)
  13) SessionManagementFilter (세션 관리 필터)
  14) ExceptionTranslationFilter (인증/인가 예외 처리 필터)
  15) FilterSecurityInterceptor (인가 처리 필터)
  16) RememberMeAuthenticationFilter (토큰 기반 인증 필터)
-----

### 기타

#### 타임리프 스프링 시큐리티 확장팩
* Thymeleaf extras SpringSecurity5 의존성 추가
  * ```
    implementation group: 'org.thymeleaf.extras', name: 'thymeleaf-extras-springsecurity5', version: '3.0.4.RELEASE'
    ```

* index html 파일 수정
  * ```
    <!DOCTYPE html>
    <html lang="en" xmlns:th="http://www.thymeleaf.org">
    <head>
        <meta charset="UTF-8" />
        <title>Index page</title>
    </head>
    <body>
        <h1 th:text="${message}">Hello !!</h1>
        <div th:if="${#authorization.expr('isAuthenticated()')}">
            <h2 th:text="${#authentication.name}">Name</h2>
            <a href="/logout" th:href="@{/logout}">Logout</a>
        </div>
        <div th:unless="${#authorization.expr('isAuthenticated()')}">
            <a href="/login" th:href="@{/login}">Login</a>
        </div>
    </body>
    </html>
    ```

#### sec 네임스페이스
* Sec 네임스페이스 등록
  * ``` xmlns:sec="http://www.thymeleaf.org/extras/spring-security" ```

* Sec 네임스페이스 사용
  * index html 파일 수정
    * ```
      <!DOCTYPE html>
      <html lang="en" xmlns:th="http://www.thymeleaf.org" xmlns:sec="http://www.thymeleaf.org/extras/spring-security">
      <head>
          <meta charset="UTF-8" />
          <title>Index page</title>
      </head>
      <body>
          <h1 th:text="${message}">Hello !!</h1>
      
          <div sec:authorize-expr="isAuthenticated()">
              <h2 sec:authentication="name">Name</h2>
              <a href="/logout" th:href="@{/logout}">Logout</a>
          </div>
          <div sec:authorize-expr="!isAuthenticated()">
              <a href="/login" th:href="@{/login}">Login</a>
          </div>
      </body>
      </html>
      ```

#### 메서드 시큐리티
* @EnableGlobalMethodSecurity
  * ```
    @EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true, jsr250Enabled = true)
    ```

* @Secured, @RollAllowed
  * 위 두 애노테이션은 해당 메서드를 호출하기 전에 권한 검사
  * 스프링 EL을 사용하지 못함
  * @Secured({"ROLE_USER", "ROLE_ADMIN"})
    * 위와 같이 설정하여 권한 계층을 별도로 설정하지 않고 모두 허용하여 인가 가능

* @PreAuthorize, @PostAuthorize
  * @PreAuthorize 애노테이션은 해당 메서드 호출하기 전 권한 검사
  * @PostAuthorize 애노테이션은 해당 메서드 실행 이후에 인가 확인
  * 메서드 호출 이전 @있다

* MethodSecurityConfig 파일 생성
  * ```
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
    ```

#### @AuthenticationPrincipal (아규먼트 리졸버)
* 웹 MVC 핸들러 아규먼트로 Principal 객체를 받을 수 있음

* 그 동안 예제에서 넘겨 받은 Principal은 자바 스펙
  * 스프링 시큐리티에서 제공해준 것이 아님

* userService에서 제공하는 UserDetails 타입 객체가 Principal
  * userService에서 제공하는 UserDetails 타입 객체를 수정하면  
    컨트롤러에서 꺼내 사용하는 Principal(SecurityContextHolder 안에 있는 Principal)이 변경될 수 있음
    * ```
      SecurityContextHolder.getContext().getAuthentication().getPrincipal();
      ```

* 예제 구현
  * 커스텀 유저 클래스
    * ```
      public class UserAccount extends User {
          private Account account;
      
          public UserAccount(Account account) {
              super(account.getUsername(),
                      account.getPassword(),
                      List.of(new SimpleGrantedAuthority("ROLE_" + account.getRole())));
              this.account = account;
          }

          public Account getAccount() {
              return account;
          }
      }
      ```
  * AccountService 수정
    * ```
      @Override
          public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
              Account account = accountRepository.findByUsername(username);
              if (account == null) {
                  throw new UsernameNotFoundException(username);
              }
      
              // Account 도메인 자체를 반환하여 사용하려면
      		  // Account가 시큐리티에 User 클래스를 상속하거나 UserDetails 인터페이스를 구현해야 함
              return new UserAccount(account);
          }
      ```

* @AuthenticationPrincipal 애노테이션 적용 예제
  * [1]
    * ```
      @AuthenticationPrincipal UserAccount userAccount
      ```
    * UserDetailsService 구현체에서 리턴하는 객체를 매개변수로 받을 수 있음
    * 그 안에 들어있는 Account객체를 getter를 통해 참조 가능
  * [2]
    * ```
      @AuthenticationPrincipal(expression = "#this == 'anonymousUser' ? null : account") Account userAccount
      ```
    * 익명 Authentication인 경우 (“anonymousUser”)에는 null 아닌 경우에는 account 필드를 사용
    * Account를 바로 참조 가능
  * [3]
    * ```
      @CurrentUser Account account
      ```
    * @AP를 메타 애노테이션으로 사용하여 커스텀 애노테이션을 만들어 사용 가능

* @CurrentUser
  * ```
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.PARAMETER)
    @AuthenticationPrincipal(expression = "#this == 'anonymousUser' ? null : account")
    public @interface CurrentUser {
    }
    ```

#### 스프링 데이터 연동
* @Query 애노테이션에서 SpEL로 principal 참조할 수 있는 기능 제공

* Spring Security Data 의존성 추가
  * ```
    implementation group: 'org.springframework.security', name: 'spring-security-data', version: '5.3.3.RELEASE'
    ```

* @Query에서 principal 사용
  * ```
    @Query("select b from Book b where b.author.id = ?#{principal.account.id}")
    List<Book> findCurrentUserBooks();
    ```

* 타임리프 리스트 참조
  * ```
    <tr th:each="book : ${books}">
        <td><span th:text="${book.title}"> Title </span></td>
    </tr>
    ```

