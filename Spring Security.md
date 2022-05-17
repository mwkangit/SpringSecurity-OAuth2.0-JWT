# Spring Security



```yaml
server:
  port: 8080
  servlet:
    context-path: /
    encoding:
      charset: UTF-8
      enabled: true
      force: true
      
spring:
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/security?serverTimezone=Asia/Seoul
    username: cos
    password: cos1234
    
  mvc:
    view:
      prefix: /templates/
      suffix: .mustache

  jpa:
    hibernate:
      ddl-auto: update #create update none
      naming:
        physical-strategy: org.hibernate.boot.model.naming.PhysicalNamingStrategyStandardImpl
    show-sql: true
```



## Mustache

src/main/resources/를 기본 폴더로 한다.

뷰 리졸버 설정 : templates (prefix), .mustache(suffix). Default 이므로 설정 안해도 된다.

.mustache가 아닌 .html로 리졸버가 작용하도록 하기 위해서 config 파일을 만든다.

```java
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    @Override
    public void configureViewResolvers(ViewResolverRegistry registry) {
        MustacheViewResolver resolver = new MustacheViewResolver();
        resolver.setCharset("UTF-8");
        resolver.setContentType("text/html; charset=UTF-8");
        resolver.setPrefix("classpath:/templates/");
        resolver.setSuffix(".html");

        registry.viewResolver(resolver);

    }
}
```

- 내가 만드는 뷰의 인코딩 방식은 UTF-8이다.
- 내가 던지는 파일은 html이며 UTF-8이다.
- classpath:/는 본인 프로젝트라고 생각하면 된다.
- suffix를 .html로 바꾸라고 명령한다.



## Security Config

Spring Security로 인해 `localhost:8080/login`, `localhost:8080/logout` 이 이미 생성되어 있다.

Spring Security가 `/login` url을 낚아채서 직접 생성한 컨트롤러로 접근이 안되고 있다.

로그인한 사용자만 다른 url에 접근하게 하기 위해 security config 파일을 생성한다.

```java
@Configuration
@EnableWebSecurity // spring security 필터가 스프링 필터체인에 등록된다.
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/login");

    }
}
```

- `@EnableWebSecurity`로 spring security 필터가 스프링 필터체인에 등록이 된다.
- csrf()를 비활성화 한다.
- antMatcher은 페이지에 접근 할때 권한을 부여하는 것이다. authenticated()는 로그인 사람 모두 가능한 것이며 access는 어떠한 권한이 있는 사람만 접근이 가능하다는 뜻이다.
- anyRequest()는 나머지 요청을 가리키며 permitAll()은 모두 허용한다는 뜻이다.
- 이제 권한 없는 곳으로 갈 경우 `403 권한 없음` 상태코드가 발생한다.
- 이제 `/login` 요청 시 spring security가 낚아채지 않고 직접 생성한 컨트롤러가 실행된다.
- `.and().formLogin().loginPage("")` 를 통해 권한이 없는 페이지 접근 시 로그인 페이지로 가게 한다. 하지만 아직 로그인 폼이 나오지 않으며 @ResponseBody로 텍스트만 응답한다.



## Security Database

yaml 파일에 보면 `security` 라는 데이터베이스로 들어가는 것을 볼 수 있다.

현재 로그인 페이지로 이동하지만 로그인은 불가하다.

```java
@Entity
@Data
public class User {
    @Id // primary key
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String username;
    private String password;
    private String email;
    private String role; // ROLE_USER, ROLE_ADMIN
    @CreationTimestamp
    private Timestamp createDate;
}
```

모델을 생성해야 한다. User 클래스를 생성한다. 즉, Entity를 생성하는 것이다.



```java
public interface UserRepository extends JpaRepository<User, Integer> {
}
```

Login, Join form 까지 생성 후 repository를 만든다.

UserRepository에 JpaRepository<User, Integer>를 상속받아서 생성한다. 현재 타입은 User이며 primary key는 Integer이다.

JpaRepository는 기본적으로 CRUD 함수를 들고 있다.

@Repository라는 어노테이션이 없어도 IoC가 된다. 이유는 JpaRepository를 상속했기 때문이다.

사용자가 생성한 User 객체의 id, createDate은 @Id, @CreationTimeStamp 의 영향으로 자동으로 생성된다.



```java
// 회원 가입 완료시 가는 url
@PostMapping("/join")
public @ResponseBody String join(User user){
    System.out.println(user);
    user.setRole("ROLE_USER");
    userRepository.save(user);
    return "join";
}
```

회원가입은 잘 된다. 하지만 비밀번호 : 1234 일 경우 -> 시큐리티로 로그인을 할 수 없다. 이유는 패스워드가 암호화가 안되었기 때문이다.



```java
// 패스워드 암호화
// 해당 메소드의 리턴되는 오브젝트를 IoC로 등록해준다.
@Bean
public BCryptPasswordEncoder encodePwd(){
    return new BCryptPasswordEncoder();
}
```

패스워드를 암호화하여 저장해야 한다.

SecurityConfig에 작성한다.



```java
// 회원 가입 완료시 가는 url
@PostMapping("/join")
public String join(User user){
    System.out.println(user);
    user.setRole("ROLE_USER");
    //        userRepository.save(user); // 회원가입 잘 된다. but 비밀번호 : 1234 일 경우 -> 시큐리티로 로그인을 할 수 없다. 이유는 패스워드가 암호화가 안되었기 때문이다.
    String rawPassword = user.getPassword();
    String encPassword = bCryptPasswordEncoder.encode(rawPassword);
    user.setPassword(encPassword);
    userRepository.save(user);

    return "redirect:/loginForm";
}
```



## Login

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable();
    http.authorizeRequests()
        .antMatchers("/user/**").authenticated()
        .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
        .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN')")
        .anyRequest().permitAll()
        .and()
        .formLogin()
        .loginPage("/loginForm")
        .loginProcessingUrl("/login")
        .defaultSuccessUrl("/"); // /login이라는 주소가 호출되면 시큐리티가 낚아채서 대신 로그인을 진행한다.

}
```

loginProcessingUrl 을 이용하면 `/login`을 요청하면 /login이라는 주소가 호출되면 시큐리티가 낚아채서 대신 로그인을 진행한다.

로그인이 완료되면 defaultSuccessUrl에 지정한 url로 이동한다.



```java
// 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
// 로그인을 진행이 완료가 되면 시큐리티 session을 만들어준다.
// session 공간은 같은데 시큐리티가 자신만의 시큐리티 세션 공간을 가지게 되며 키값으로 구분한다.(Security ContextHolder라는 키값에 세션 정보를 저장한다.)
// session에 들어갈 수 있는 정보(오브젝트 타입)는 정해져 있다. => Authentication 타입 객체
// Authentication 안에 User 정보가 있어야 한다.
// User 오브젝트 타입 => UserDetails 타입 객체이어야 한다.
// 그래서 UserDetails를 상속받는다.
// 이제 PrincipalDetails는 UserDetails와 같은 타입이다.

// Security Session 에 정보를 저장하는데 여기에 저장할 수 있는 객체는 Authentication 객체이며 이 객체에 유저 정보를 저장할 때 유저 정보는 UserDetails 타입이어야 한다.
// security session에 있는 정보를 꺼내면 Authentication객체가 나오면 그 안에서 userDetails로 유저 정보를 볼 수 있다.

public class PrincipalDetails implements UserDetails {

    // 현재 유저 정보는 User 오브젝트가 가지고 있다.
    private User user; // 콤포지션

    public PrincipalDetails(User user) {
        this.user = user;
    }

    // 해당 User의 권한을 리턴하는 곳
    // 현재 user.getRole()의 리턴 타입은 String이어서 변환해서 반환해야 한다.
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // ArrayList는 컬렉션의 자식이다.
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            // 여기서 String을 리턴할 수 있다.
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    // 해당 User의 패스워드를 리턴하는 곳
    @Override
    public String getPassword() {
        return user.getPassword();
    }

    // 해당 User의 유저이름을 리턴하는 곳
    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 해당 User의 계정이 만료되었는지 리턴 - 아니오
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 해당 User의 계정이 잠겼는지 리턴 - 아니오
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 해당 User의 계정의 비밀번호가 많이 사용했는지 리턴 - 아니오
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 해당 User가 활성화 되어있는지 리턴 - 아니오
    @Override
    public boolean isEnabled() {

        // false 하는 경우
        // 우리 사이트에서 1년동안 회원이 로그인을 안하면 휴면 계정으로 하기로 했다.
        // 현재시간 - 최근 로그인 시간이 1년 초과시 return false하면 휴면이라고 저장된다.

        return true;
    }
}
```

Security 세션의 Authentication에 집어넣을 UserDetails 객체를 생성하는 과정이다.



```java
// @Service 로 운영한다.
// 시큐리티 설정에서 loginProcessingUrl("/login");을 해놓은 상태이다.
// 그러므로 /login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC되어 있는 loadUserByUsername 함수가 실행된다.
// 즉, @Service로 PrincipalDetailsService 가 자동으로 IoC 등록이 된다. 그래서 자동 호출 되는 것이다.
// loadUserByUsername의 파라미터인 username은 폼의 username과 동일해야 한다. 즉, 폼에서 username2로 코드를 변경하면 매칭이 안된다. 만약 바꾸고 싶다면 SecurityConfig에 .usernameParameter("username2");를 작성해야 한다.
// 여기선 폼에서 그냥 username으로 하여 기본값을 사용한다.

@Service
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    // 시큐리티 session(내부 Authentication(내부 UserDetails))
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // username이라는 이름으로 저장된 것이 있는지 확인하는 작업이다.
        User userEntity = userRepository.findByUsername(username);
        // 유저가 있으면 UserDetails로 반환한다.
        if(userEntity != null){
            return new PrincipalDetails(userEntity);
        }
        // 없으면 null 반환한다.
        return null;
    }
}
```

Authentication을 구현한 UserDetailsService 이다.

여기서 UserDetails가 리턴되면 Authentication내부에 저장이 된다.

또한, session 내부에 Authentication이 저장된다.

즉, 현재 PrincipalDetails가 리턴될 때 Session내부에 Authentication이 자동으로 만들어진다.

이제 로그인하면 권한을 가지며 로그인 상태로 웹을 들어갈 수 있다.

이때 특정 url에 접근하려는데 login해야 한다는 표시가 떠서 로그인을 하면 바로 접근하려던 특정 url로 redirect 된다. 즉, SecurityConfig 클래스에서 .defaultSuccessUrl은 `/loginForm`으로 직접 접근시 경로를 지정하는 것이며 다른 특정 경로로 가면 그쪽으로 redirect 해주는 것이다.

현재 `localhost:8080/manager`로는 권한이 없어서 접근하지 못한다.



## Manager & Admin Authorization

```java
@Configuration
@EnableWebSecurity // spring security 필터가 스프링 필터체인에 등록된다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화, preAuthorize 어노테이션 활성화, postAuthorize 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 패스워드 암호화
    // 해당 메소드의 리턴되는 오브젝트를 IoC로 등록해준다.
    @Bean
    public BCryptPasswordEncoder encodePwd(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated() // 인증만 되면 들어갈 수 있는 주소!!
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/"); // /login이라는 주소가 호출되면 시큐리티가 낚아채서 대신 로그인을 진행한다.

    }
}
```

```java
// IndexController
// @Secured 없을 때에는 SecurityConfig의 permitAll로 인해 로그인 안해도 접근 가능하다.
@Secured("ROLE_ADMIN")
@GetMapping("/info")
public @ResponseBody String info(){
    return "개인정보";
}
```

@EnableGlobalMethodSecurity(securedEnabled = true)를 추가한다. 이렇게 secured 기능을 활성화하여 @Secured를 사용할 수 있게 된다.

@Secured는 특정 메소드에 권한 설정을 할 때 사용한다.

prePostEnable=true는 @preAuthorize를 활성화 한다.

@PreAuthorize는 여러개의 권한을 부여할 수 있다. 하나일 때에는 @Secured를 사용하는 것이 좋지만 여러개일 때에는 @PreAuthorize를 사용한다.

pre 다음에는 post가 걸리지 않기 때문에 prePostEnable = true를 이용하며 @PostAuthorize를 사용가능하게 한다.

@PostAuthorize 보다는 pre를 많이 사용하지만 secured도 많이 사용하는 추세이다.

권한을 특정 url에만 주는 것이 아니면 SecurityConfig처럼 글로벌로 처리한다.



# OAUTH 2.0



## Google



구글 로그인 완료 시 구글 서버에서 인증이 되었다는 코드을 반환한다. 이때 코드를 받고 다시 access token을 요청하게 된다. 이 access token은 사용자 대신 서버가 구글 서버에 사용자의 개인정보 등 접근할 수 있는 권한이다. access token을 얻기 위해 필요한 것이 code인데 이 code를 받을 수 있는 주소가 redirection uri이다. `http://localhost:8080/login/oauth2/code/google`

예전에 직접적으로 다 구현하면 redirection uri가 크게 의미가 없는데 oauth client 라는 라이브러리를 쓰게 되면 redirection uri는 고정이다. 다른 주소를 사용할 수 없다. 앞의 8080까지는 자유롭게  작성해도 되지만 login/oauth2/code는 고정되어 있다. 그 다음에는 google, facebook 등 사용할 서버를 입력하면 된다.

그리고 이 주소에 대한 컨트롤러는 만들 필요가 없다. 내가 저 요청값을 처리하는 것이 아닌 라이브러리가 알아서 처리하기 때문이다.

Spring Boot Starter에서 oauth2 client라는 라이브러리가 주소를 낚아채면 되는데 아직 이것을 활성화하지 않았다.

```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
```

위와 같이 pom.xml에 추가하여 oauth2 client를 활성화한다.



```yml
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: 364919719093-savm4hobdvd706i81uvaombi5573riom.apps.googleusercontent.com
            client-secret: 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
            scope:
            -
```

application.yml 파일 하단에 spring: 이후에 작성한다.

client-id는 미리 복사해둬야 하며 client-secret은 google developer console에서 사용자 인증 정보, oauth 2.0 클라이언트에 있다.

scope에는 email, profile, openId가 있는데 openId는 무시한다.

아래에 facebook과 같은 oauth도 저장 가능하다.



```html
<a href="/oauth2/authorization/google">구글 로그인</a>
```

이 주소도 oauth client라는 라이브러리를 사용하면 고정이므로 마음대로 바꾸면 안된다.

이렇게 구글 oauth 인증을 받게 된다.

현재 404 상태가 발생한다.해당 주소에 대해 매핑된 것이 없기 때문이다.



```java
// SecurityConfig
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable();
    http.authorizeRequests()
        .antMatchers("/user/**").authenticated() // 인증만 되면 들어갈 수 있는 주소!!
        .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
        .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
        .anyRequest().permitAll()
        .and()
        .formLogin()
        .loginPage("/loginForm")
        .loginProcessingUrl("/login")
        .defaultSuccessUrl("/")
        .and()
        .oauth2Login()
        .loginPage("/loginForm")// /login이라는 주소가 호출되면 시큐리티가 낚아채서 대신 로그인을 진행한다.

}
```

로그인 페이지를 똑같은 형식으로 했다. oauth 로그인이나 일반적인 로그인 페이지나 똑같이 만들었다("/loginForm"). 즉, 인증이 필요한 url 접속시 동일하게 "/loginForm"으로 이동하게 한 것이다.

아직 인가가 없어서 manager에는 접근하지 못하고 있다. 즉, 인증 후 후처리가 필요하다.

oauth 순서

1. 코드 받기(인증됨) 
2. 엑세스토큰 받기(시큐리티 서버가 구글 로그인한 사용자의 정보에 접근 가능한 권한 생긴 것이다.) 
3. 사용자 프로필 정보를 가져오고 

4-1.그 정보를 토대로 회원가입을 자동으로 진행시키기도 함.

4-2. (정보가 부족할 수 있다.) 구글 제공하는 사용자 프로필에 이메일, 전화번호, 이름, 아이디가 있을 때 쇼핑몰을 운영하면 추가적으로 집주소 등이 필요하다. or 백화점 -> vip등급, 일반등급. 이때 추가적인 회원가입 창으로 추가 정보 입력하게 해야한다. 하지만 정보가 충분하다면 구글 제공 정보로 회원가입 다 한다.



```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable();
    http.authorizeRequests()
        .antMatchers("/user/**").authenticated() // 인증만 되면 들어갈 수 있는 주소!!
        .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
        .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
        .anyRequest().permitAll()
        .and()
        .formLogin()
        .loginPage("/loginForm")
        .loginProcessingUrl("/login")
        .defaultSuccessUrl("/") // /login이라는 주소가 호출되면 시큐리티가 낚아채서 대신 로그인을 진행한다.
        .and()
        .oauth2Login()
        .loginPage("/loginForm") // 구글 로그인이 완료된 뒤의 후처리가 필요함. 아직 인가가 안됌.
        .userInfoEndpoint() // oauth 순서 -> 1. 코드 받기(인증됨) 2.엑세스토큰 받기(시큐리티 서버가 구글 로그인한 사용자의 정보에 접근 가능한 권한 생긴 것이다.) 3. 사용자 프로필 정보를 가져오고 4-1. 그 정보를 토대로 회원가입을 자동으로 진행시키기도 함. 4-2. (정보가 부족할 수 있다.) 구글 제공하는 사용자 프로필에 이메일, 전화번호, 이름, 아이디가 있을 때 쇼핑몰을 운영하면 추가적으로 집주소 등이 필요하다. or 백화점 -> vip등급, 일반등급. 이때 추가적인 회원가입 창으로 추가 정보 입력하게 해야한다. 하지만 정보가 충분하다면 구글 제공 정보로 회원가입 다 한다.
        .userService(null);// Tip. 구글 로그인이 완료되면 코드를 받는 것이 아닌 엑세스토큰 + 사용자프로필정보를 한번에 받는다.

}
```

userService(); 매개변수 타입이 Oauth2UserService이어야 한다. 지금은 null로 한다.



```java
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {


    // 구글로 부터 받은 userRequest 데이터에 대한 후처리 되는 함수이다.
    @Override
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("getClientRegistration = " + userRequest.getClientRegistration());
        System.out.println("getAccessToken = " + userRequest.getAccessToken().getTokenValue());
        System.out.println("getAttributes = " + super.loadUser(userRequest).getAttributes());
        return super.loadUser(userRequest);
    }
}

// 출력 : getClientRegistration = ClientRegistration{registrationId='google', clientId='364919719093-savm4hobdvd706i81uvaombi5573riom.apps.googleusercontent.com', clientSecret='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', clientAuthenticationMethod=org.springframework.security.oauth2.core.ClientAuthenticationMethod@4fcef9d3, authorizationGrantType=org.springframework.security.oauth2.core.AuthorizationGrantType@5da5e9f3, redirectUri='{baseUrl}/{action}/oauth2/code/{registrationId}', scopes=[email, profile], providerDetails=org.springframework.security.oauth2.client.registration.ClientRegistration$ProviderDetails@6d6b959f, clientName='Google'}
// getAccessToken = ya29.a0ARrdaM-QkYZUeQwl38uSiJqf1YXKIWl_Ni3Kk5nbHq0Q8-4hEODBmO8UzWOUayO8U0esjUiEuFCkIzfKBGBGC_kaDyKvEavUo17XrKM_5FGlAnMVFqlhvbmQZcu1mv5cqg7q4ATNW_Yf5U5ESlk2jYs06r1n
// getAttributes = {sub=107850419880594031570, name=강민우, given_name=민우, family_name=강, picture=https://lh3.googleusercontent.com/a/AATXAJwyluAepQY9N7Ef_xzVhkpzRMIQoxiWfzH4VMjx=s96-c, email=cabookis@gmail.com, email_verified=true, locale=ko}

```

PrincipalOauth2UserService 클래스를 생성 후 DefaultOAuth2UserService를 상속 받는다.

또한, @Service로 IoC를 해준다.

그 후 SecurityConfig에 @Autowired로 PrincipalOauth2UserService를 가져온 후 userService()의 매개변수로 넣는다.

현재 PrincipalOauth2UserService가 후처리를 진행하는 클래스이다. 함수는 loadUser을 사용한다.

getClientRegistration, super.loadUser(userRequest), getAccessToken 뒤에 .을 붙여서 더 안쪽의 데이터에 접근할 수 있다.

인증 후 엑세스토큰 + 사용자프로필을 한꺼번에 받은 것을 볼 수 있다.

엑세스토큰을 이용해서 사용자프로필을 다시 가져오는 수고가 없어졌다.

getAttributes()에서 sub는 구글에 회원가입한 아이디 이다. 즉, primary key 같은 아이디 넘버이다.

이제 이메일을 내 서버 회원가입 정보로 넣을 것이다.

entity에서 username에는 sub를 넣는다. 즉, google_107850419880594031570 형식으로 넣으면 중복이 될 일이 없다. 
password는 우리 서버만 아는 "겟인데어"를 암호화해서 넣는다. 사실 oauth로 로그인 할 것이어서 password에는 null만 아닌 아무 값을 넣어도 된다. 
email은 구글에서 제공한 데이터를 그대로 입력한다.
role은 일단 ROLE_USER을 입력한다.

현재 이렇게 회원을 정의하면 일반 사용자인지 oauth 로그인한 사용자인지 구분이 안간다. 그래서 entity에 속성을 추가한다.

```java
private String provider;
private String providerId;
```

provider에는 "google"을 입력한다.

providerId에는 구글에서 사용하고 있는 아이디인 sub를 입력한다.

이렇게 하여 getAttributes()로 강제 회원가입을 시키는 것이다.



현재 registrationId로 어떤 oauth로 로그인 했는지 확인가능하다.

순서 : 구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인을 완료 -> code를 리턴(oauth-client 라이브러리가 받는다) -> 바로 자동으로 코드를 통해 AccessToken을 요청 -> AccessToken을 받는 것까지 userRequest의 정보이다.

userRequest 정보를 통해 -> 회원프로필을 받아야함(이때 사용되는 함수가 loadUser이며 loadUser함수를 호출한다) -> 구글로부터 회원프로필을 받음

즉, loadUser은 구글로부터 회원 프로필을 받는 역할을 한다.



```java
// indexController

// 일반 사용자 정보 접근
@GetMapping("/test/login")
public @ResponseBody String loginTest(
    Authentication authentication,
    @AuthenticationPrincipal PrincipalDetails userDetails){ // Authentication으로 DI(의존성 주입)
    // @AuthenticationPrincipal로 세션 정보에 접근할 수 있다.
    // 이때 @AuthenticationPrincipal은 UserDetails 타입을 받기 때문에 UserDetails를 상속받은 PrincipalDetails로 바로 받을 수 있다.
    // 즉, Authentication을 DI하는 방법과 어노테이션을 이용하여 정보에 접근하는 방법으로 2가지 접근법이 있다.
    // 둘다 같은 데이터를 가진다.
    System.out.println("/test/login ============");
    PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
    // getUser은 PrincipalDetails의 User 객체 정보를 가져오는 것이다.
    System.out.println("authentication: " + principalDetails.getUser());

    System.out.println("userDetails: " + userDetails.getUser());
    return "세션 정보 확인하기";
}

// OAuth의 정보 접근
@GetMapping("/test/oauth/login")
public @ResponseBody String testOauthLogin(
    Authentication authentication,
    @AuthenticationPrincipal OAuth2User oauth){ // Authentication으로 DI(의존성 주입)
    // @AuthenticationPrincipal로 세션 정보에 접근할 수 있다.
    // 이때 @AuthenticationPrincipal은 UserDetails 타입을 받기 때문에 UserDetails를 상속받은 PrincipalDetails로 바로 받을 수 있다.
    // 즉, Authentication을 DI하는 방법과 어노테이션을 이용하여 정보에 접근하는 방법으로 2가지 접근법이 있다.
    // 둘다 같은 데이터를 가진다.
    // OAuth로 접근하면 UserDetails가 아닌 OAuth2User로 받는다.
    System.out.println("/test/login ============");
    OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
    // getUser은 PrincipalDetails의 User 객체 정보를 가져오는 것이다.
    System.out.println("authentication: " + oAuth2User.getAttributes());
    System.out.println("oauth2User: " + oauth.getAttributes());

    return "OAuth 세션 정보 확인하기";
}
```

```java
@Data
public class PrincipalDetails implements UserDetails, OAuth2User {}
```

getPrincipal()의 리턴 타입은 object이다.

이때 PrincipalDetails 클래스에 @Data를 부여한다. getter을 부여하는 것이다.

주석참조.

스프링 시큐리티는 자신만의 시큐리티 세션이 있다. 물론 서버 자체에 있는 세션 내부에 시큐리티가 관리하는 세션이 있는 것이다.

시큐리티 세션가 관리하는 세션에 들어갈 수 있는 타입은 Authentication 객체만 허용된다. 이 Authentication 객체에 바로 주입하는 DI를 controller에서 해줄 수 있다. Authentication에 들어갈 수 있는 두 가지 타입이 있다. 첫 번째로 UserDetails이고 두 번째는 OAuth2User이 들어갈 수 있다. 즉, 시큐리티가 관리하는 세션에는 무조건 Authentication 객체만 들어갈 수 있으며 이것이 들어가는 순간 로그인이 완료된 것이며 이 Authentication에는 UserDetails, OAuth2User 타입만 들어갈 수 있다.

일반 로그인을 하면 UserDetails 타입으로 Authentication에 들어간다.

OAuth 로그인을 하면 OAuth2User 타입이 Authentication 객체에 들어간다.

이 Authentication이 들어가면 세션이 생긴 것이므로 로그인이 된 것이다.

하지만 현재 일반 로그인, OAuth 로그인일 때 다르게 처리한다.

이때 UserDetails, OAuth2User을 모두 implements한 객체 클래스를 만들어서 모두 허용하게 만들어서 해결한다. 이 객체를 Authentication에 담는다.

현재 PrincipalDetails는 UserDetails를 implements 했으며 PrincipalDetailsService의 loadUserByUsername 실행하여 리턴될 때 Authentication에 들어간다. 즉, `return new PrincipalDetails(userEntity);` 로 Authentication에 들어가는 것이다.

PrincipalDetails가 OAuth2User까지 implements하면 Controller에서 DI 받을 때 PrincipalDetails로 통일할 수 있다.

OAuth2User, UserDetails에는 User 객체가 없기 때문에 PrincipalDetails에 User 객체를 넣고 UserDetails를 implements 한 것이다. 이때 Oauth2User도 implements 한다.



```java
@Data
public class PrincipalDetails implements UserDetails, OAuth2User {
    
    private User user;
    private Map<String, Object> attributes;
 
    //일반 로그인
    public PrincipalDetails(User user) {
        this.user = user;
    }

    // OAuth 로그인
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }
    
    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return null;
    }
}
```

getName은 attributes.get("sub")해도 되지만 잘 사용하지 않으므로 null을 return하게 한다.

Principal 정보를 Authentication에 저장할 때 attributes도 저장하게 한다. 이 때 attributes는 사용자 정보를 저장하게 된다.

이제 attributes 정보를 토대로 User 객체를 만들 것이다.



```java
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {


    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    // 구글로 부터 받은 userRequest 데이터에 대한 후처리 되는 함수이다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 내 서버의 기본정보가 있다.
        // registrationId로 어떤 oauth로 로그인 했는지 확인가능하다.
        System.out.println("getClientRegistration = " + userRequest.getClientRegistration());
        // 이미 사용자프로필을 가져와서 엑세스토큰은 의미가 없긴하다.
        System.out.println("getAccessToken = " + userRequest.getAccessToken().getTokenValue());

        OAuth2User oAuth2User = super.loadUser(userRequest);

        // 이 정보로 회원가입을 진행한다.
        // 순서 : 구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인을 완료 -> code를 리턴(oauth-client 라이브러리가 받는다) -> 바로 자동으로 코드를 통해 AccessToken을 요청 -> AccessToken을 받는 것까지 userRequest의 정보이다.
        // userRequest 정보를 통해 -> 회원프로필을 받아야함(이때 사용되는 함수가 loadUser이며 loadUser함수를 호출한다) -> 구글로부터 회원프로필을 받음
        System.out.println("getAttributes = " + oAuth2User.getAttributes());

        String provider = userRequest.getClientRegistration().getRegistrationId(); // google
        String providerId = oAuth2User.getAttribute("sub"); // 구글에서 Id는 sub이다. 107850419880594031570
        // 사실 OAuth로 로그인하면 username, password가 필요없는데 형식상 만드는 것이다.
        String username = provider+"_"+providerId; // google_107850419880594031570
        String password = bCryptPasswordEncoder.encode("겟인데어");
        String email = oAuth2User.getAttribute("email"); // cabookis@gmail.com
        String role = "ROLE_USER";

        // 이미 회원가입이 되어있을 수 있으므로 UserRepository @AutoWired하여 가져온다.
        User userEntity = userRepository.findByUsername(username);

        if(userEntity == null){
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }


        // 리턴 타입이 OAuth2User이므로 가능하다.
        // 이 객체가 시큐리티 세션의 Authentication에 들어간다.
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
```

loadUser로 후처리를 하면서 강제 회원가입을 진행한다.

이때 bean cycle의 영향으로 BCryptPasswordEncoder에 대한 식을 main에 작성한다.

User entity에는 @NoArgsConstructor로 default 생성자를 만든다.



```java
// OAuth 로그인을 해도 PrincipalDetails로 받는다.
// 일반 로그인을 해도 PrincipalDetails로 받는다.
@GetMapping("/user")
@ResponseBody
public String user(@AuthenticationPrincipal PrincipalDetails principalDetails){
    System.out.println("principalDetails : " + principalDetails.getUser());
    return "user";
}
```

이제 OAuth2User, UserDetails를 모두 허용한다.

이때 앞과 다르게 다운캐스팅을 하지 않아도 된다.

@AuthenticationPrincipal 이 언제 실행되는지 알아보자.

일단 PrincipalDetailsService의 loadUserByUsername, PrincipalOauth2UserService의 loadUser 은 오버라이딩하지 않아도 실행한다. 즉, 알아서 로그인 된다.

굳이 이 메소드를 오버라이딩해서 구현하는 이유는 PrincipalDetails 타입으로 반환하기 위해서이다. loadUserByUsername은 기본 반환이 UserDetails, loadUser는 기본 반환이 OAuth2User 이다.

현재 OAuth 로그인 시에만 강제 회원가입 시킨다.

이 두 함수 종료시 @AuthenticationPrincipal이 만들어진다.



## Facebook



시작하기를 누른 후 앱을 기타로 생성한다.

localhost:8080으로 생성한 뒤 모두 기본 설정값으로 한다.



```yaml
facebook:
            client-id: 680098016626499
            client-secret: e59ec1a5e4768684ecc11b4e9dd3cde5
            scope:
              - email
              - public_profile
```

기본설정에 들어가서 client-id, client-secret을 가져와서 application.yml에 입력한다.

scope에서 profile대신 public_profile로 한다.

oauth client 라이브러리를 사용하면 주소가 고정이 되어 있어서 html의 href 시 google 은 `/oauth2/authorization/google`, facebook은 `/oauth2/authorization/facebook` 이다.

facebook은 sub이 아닌 getAttribute("id")로 가져와야 providerId를 확인할 수 있다. 그래서 providerId, username에 null이 만들어진다.



```java
public interface OAuth2UserInfo {
    String getProviderId();
    String getProvider();
    String getEmail();
    String getName();
}
```

```java
public class GoogleUserInfo implements OAuth2UserInfo{

    private Map<String, Object> attributes; // PrincipalOauth2UserService의 oauth2User.getAttributes()를 받게되는 객체이다.

    public GoogleUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {
        return (String) attributes.get("sub");
    }

    @Override
    public String getProvider() {
        return "google";
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }
}
```

```java
public class FacebookUserInfo implements OAuth2UserInfo{

    private Map<String, Object> attributes; // PrincipalOauth2UserService의 oauth2User.getAttributes()를 받게되는 객체이다.

    public FacebookUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {
        return (String) attributes.get("id");
    }

    @Override
    public String getProvider() {
        return "facebook";
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }
}
```

```java
// PrincipalOauth2UserService

OAuth2UserInfo oAuth2UserInfo = null;
if(userRequest.getClientRegistration().getRegistrationId().equals("google")){
    System.out.println("구글 로그인 요청");
    oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
}else if(userRequest.getClientRegistration().getRegistrationId().equals("facebook")){
    System.out.println("페이스북 로그인 요청");
    oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
} else{
    System.out.println("구글, 페이스북 로그인만 지원합니다!");
}

// 구글, 페이스북 로그인 시 사용
String provider = oAuth2UserInfo.getProvider();
String providerId = oAuth2UserInfo.getProviderId();
// 사실 OAuth로 로그인하면 username, password가 필요없는데 형식상 만드는 것이다.
String username = provider+"_"+providerId;
String password = bCryptPasswordEncoder.encode("겟인데어");
String email = oAuth2UserInfo.getEmail();
String role = "ROLE_USER";
```

위 사항에 의해 oauth 패키지에 provider 패키지를 생성하고 OAuth2UserInfo 인터페이스, GoogleUserInfo 클래스, FacebookUserInfo 클래스를 생성한다.

이 방법은 유지보수가 좋다. 다른 oauth를 추가하기 좋기 때문이다.



## Naver



현재 OAuth-Client라는 라이브러리를 이용 중이다.

Provider은 OAuth-Client를 제공하는 제공자이다. 즉, 구글, 페이스북, 트위터 등 이 있다.

네이버나 카카오는 Provider이 아니다. 너무 많은 OAuth에 이것들은 아직 포함되지 않는다. 스프링이 모든 다른 정보 제공법을 알 수 없다(id, sub).

그래서 대표적으로 구글, 페이스북, 트위터 등만 provider로 제공한다. 네이버는 provider이 아니다.



```yaml
naver:
            client-id:
            client-secret:
            scope:
            - name
            - email
```

구글과 같은 인덴트에 추가하여 네이버 oauth를 사용하며 `-profile_image`를 추가할 수 있다.

우리가 사용하는 oauth 방법은 코드를 부여받는 방법이다. 코드로 인증이 되며 코드로 엑세스토큰을 가져온 후 사용자프로필에 접근할 수 있다. 네이버도 이 방식을 사용한다.

`authorization-grant-type: authorization_code`는 위 방식을 따른다는 뜻이다. 

Client Credentials Grant Type 방식은 react나 javascript로 서버를 구현할 때 사용한다.

구글, 페이스북은 작성하지 않아도 되지만 네이버는 provider이 아니므로 `redirect-url: http://localhost:8080/login/oauth2/code/naver`를 작성해야 한다. 마음대로 만들어도 되지만 규칙에 맞게 하는게 좋다.

'네이버 개발자' 검색 후 로그인한다.
어플리케이션 등록으로 간 뒤 네이버 로그인을 선택한다.
pc 웹을 선택하고 `http://localhost:8080`, `http://localhost:8080/login/oauth2/code/naver` 을 입력한다. 그래서 2번째 url은 마음대로 작성해도 되지만 다른 oauth랑 통일하는 것이 좋다.

현재 실행시 오류가 발생한다.

```
UnsatisfiedDependencyException: Error creating bean with name 'org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration$EnableWebMvcConfiguration': Unsatisfied dependency expressed through method 'setConfigurers' parameter 0; nested exception is org.springframework.beans.factory.UnsatisfiedDependencyException: Error creating bean with name 'org.springframework.security.config.annotation.web.configuration.OAuth2ClientConfiguration$OAuth2ClientWebMvcSecurityConfiguration': Unsatisfied dependency expressed through method 'setClientRegistrationRepository' parameter 0; nested exception is org.springframework.beans.factory.BeanCreationException: Error creating bean with name 'clientRegistrationRepository' defined in class path resource [org/springframework/boot/autoconfigure/security/oauth2/client/servlet/OAuth2ClientRegistrationRepositoryConfiguration.class]: Bean instantiation via factory method failed; nested exception is org.springframework.beans.BeanInstantiationException: Failed to instantiate [org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository]: Factory method 'clientRegistrationRepository' threw exception; nested exception is java.lang.IllegalStateException: Provider ID must be specified for client registration 'naver'
```

네이버는 provider이 아니기 때문에 오류가 authorizedClientRepository라는 클래스에 naver을 저장할 수 없다. 그래서 오류 발생한다. 즉, oauth client 라이브러리가 가지고 있는 provider이 아닌 것이다.



```yaml
naver:
            client-id: 39cG7nkfabEx1TaENicP
            client-secret: nadDQQx6t4
            scope:
            - name
            - email
            client-name: Naver
            authorization-grant-type: authorization_code
            redirect-uri: http://localhost:8080/login/oauth2/code/naver

        provider:
          naver:
            authorization-uri: https://nid.naver.com/oauth2.0/authorize
            token-uri: https://nid.naver.com/oauth2.0/token
            user-info-uri: https://openapi.naver.com/v1/nid/me
            user-name-attribute: response # 회원정보를 json으로 받는데 response라는 키값으로 네이버가 리턴해준다.
```

`user-name-attributes: response`는 회원정보를 json으로 받는데 response라는 키값으로 네이버가 리턴해준다.

[네이버doc](https://developers.naver.com/docs/login/devguide/devguide.md#2-2-1-%EC%86%8C%EC%85%9C-%EB%A1%9C%EA%B7%B8%EC%9D%B8) 

`https://nid.naver.com/oauth2.0/authorize`주소로 요청하면 네이버 로그인 창이 뜬다.

`https://nid.naver.com/oauth2.0/token`주소로 요청하면 토큰을 받을 수 있다.

`https://openapi.naver.com/v1/nid/me` 주소로 요청하면 프로필 정보를 받을 수 있다.

이제 작성한 provider이 naver을 provider로 등록해줄 것이다.

이제 html의 `/oauth2/authorization/naver`를 호출하면 authorization-uri로 등록된 주소를 요청하게 된다.

PrincipalOauth2UserService의 getAttributes를 통해 response의 의미를 알아보자.
getAttributes = {resultcode=00, message=success, response={id=-PNv-b2PVDe5qF2l8IlGt7CPHvj9K578HvJisvCZ6aU, email=cabookis@naver.com, name=강민우}}



```java
package com.cos.security1.config.oauth.provider;

import java.util.Map;

public class NaverUserInfo implements OAuth2UserInfo{

    private Map<String, Object> attributes; // PrincipalOauth2UserService의 oauth2User.getAttributes()를 받게되는 객체이다.

    public NaverUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {
        return (String) attributes.get("id");
    }

    @Override
    public String getProvider() {
        return "naver";
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }
}
```

```java
// PrincipalOauth2UserService

else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")){
            System.out.println("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map) oAuth2User.getAttributes().get("response"));
        }
```

`NaverUserInfo((Map) oAuth2User.getAttributes().get("response"));` 로 접근해야 한다.

현재 스프링부트 기본 로그인 + OAuth2.0 로그인을 통합해서 구현을 했다.

이제 웹 어플리케이션을 만들면 된다.
