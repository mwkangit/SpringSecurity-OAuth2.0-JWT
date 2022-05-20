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



# Spring Security Web Security



JWT = JSON WEB TOKEN

왜 사용하고 어디에 쓰는지 알아보자.



## Session



`www.naver.com`을 요청하면 서버가 헤더에 `쿠키: 세션ID(1234)`를 주고 브라우저는 `쿠키: 세션ID(1234)`를 저장한다. 이것은 최초 요청 시 이루어진다.

이후 요청 시 브라우저는 헤더에 세션ID를 넣어서 보낸다. 서버는 세션ID를 다시 생성하지 않고 그대로 응답에 넣어서 보낸다.

서버는 세션ID를 브라우저에서 전송하지 않으면 처음 접근한 것 처럼 인지한다. 보내주면 이전에 접근한 적이 있는 것으로 판단한다.

세션ID를 만들어주면 서버가 저장하고 있으며 특정 브라우저의 유저에게만 부여되고 보여질 수 있다. 이때 세션ID를 '겟인데어'라고 부르겠다. 처음 서버에 접근하는 브라우저가 세션ID를 전송하면 서버는 저장소에 세션ID가 없어서 위조한 것을 알 수 있다.

세션ID가 언제 사라지는지 알아보자.

세션ID는 서버에서 세션ID를 없애거나 브라우저를 닫을 때 사라진다. 브라우저를 닫아서 서버의 세션ID는 저장되어 있는 상태인데 브라우저 쿠키에 세션ID가 사라져서 처음 요청한 브라우저처럼 서버가 인식하게 된다. 남아있는 세션ID는 특정 시간이 지나면 사라진다(보통 30분). 또한, 특정 시간(보통 30분)이 지나면 서버측에서 세션ID가 사라져서 브라우저가 그대로 세션ID를 전송해도 처음 요청한 것처럼 서버가 판단한다.

세션은 로그인 요청(인증) 시 많이 사용된다.

로그인과 요청의 순서를 알아보자.

`www.naver.com`에 요청 시 세션ID를 받으며 이후 로그인할 때 이 세션ID를 사용한다. 유저 정보를 검사 후 세션ID에 user 정보(객체)를 저장한다. 이 다음부터 브라우저가 인증이 필요한 페이지(유저정보 페이지)를 요청하면 서버는 세션ID를 확인하고 ,user정보가 저장되어 있으면 인가가 되어 브라우저가 요청한 정보를 응답한다. 즉, 세션을 통해 인증과 인가가 가능하다.

세션의 단점을 알아보자.

클라이언드가 많고 동시 접속자가 300명인데 서버는 100명만 처리할 수 있다면 나머지 200명은 기다려야 한다. 서버가 3개여야 모두 수용 가능하다. 이때 로드밸런싱을 사용하여 부하를 나눌 수 있다. 이 때 서버1에 세션ID를 만들어놨지만 로드밸런싱으로 인해 서버2로 요청을 보내면 서버2는 처음 요청을 보낸 것으로 판단하게 된다.

위의 문제를 해결할 수 있는 방법을 알아보자.

이때 스티키 서버(sticky session)을 이용하여 브라우저가 최초로 요청을 보낸 서버와만 통신을 하게 하는 방법을 이용할 수 있긴하다. 또한, 세션 저장소에 세션ID가 생성될 때마다 다른 서버의 세션 저장소에도 복제를 하는 방법이 있다. 하지만 연속적으로 복제하는 것은 귀찮고 오래걸린다. 마지막으로는 세션 저장소를 각 서버에서 운영하는 것이 아닌 한 데이터베이스에 세션 값을 넣고 공유해서 사용하는 방법이 있다. 하지만 세션을 위해 메모리가 아닌 데이터베이스에 접근해야 하기 때문에 시간이 오래걸린다. RAM은 전기적 신호로 접근하여 random access와 I/O가 발생하지 않고 원하는 위치로 direct 접근 가능하지만 하드디스크는 direct 접근이 불가능하며 원판을 돌리면서(풀스캔 한다) 찾게 되어 느리다. 그래서 보통 데이터베이스가 아닌 메모리 공유 서버를 이용한다(RAM). 이게 redis라는 서버이다.

그렇다면 JWT는 무엇이고 왜 사용하고 언제 쓰는가? - 위 세션의 문제점을 모두 해결하기 때문이다.



## TCP



OSI 7 Layer - 물데네트세프용(물리, 데이터링크, 네트워크, 트랜스포트, 세션, 프리젠테이션, 응용)

롤을 하면서 야스오 궁을 사용한다고 할때

응용 : 롤 프로그램 사용 중이며 궁이라는 데이터를 전송한다.

프리젠테이션 : 궁이라는 데이터를 암호화한다. 즉, 프리젠테이션은 중요 데이터를 암호화하거나 사진을 압축하는 역할을 한다.

세션 : 상대방 쪽으로 데이터를 보낼 수 있는지 인증이 있는지 체크한다. 세션은 상대방 컴퓨터가 켜져 있는지, 켜져 있다면 접근할 수 있는 권한이 있는지 등 체크한다.

트랜스포트 : TCP, UDP 통신을 결정한다. 전화 시 udp 통신한다(그래서 지지직 거리는 것이 있다). 물론 동영상도 udp 가능하다(tcp도 가능). 하지만 비밀번호 전송 시 정확히 전송해야 하기 때문에 tcp 한다. 즉, 사람이 이해 가능한 영역은 udp 해도 되지만 아닌 경우는 tcp이다. 롤은 tcp이다(아니면 버그 발생한다).

네트워크 : IP. IP를 알아야 상대방을 찾을 수 있다.

데이터링크 : 네트워크 계층 위는 WAN(wireless로 원거리 통신), 데이터링크부터는 LAN(근거리 통신) 이다. 공유기 내무 통신을 담당하며 상대의 공유기에서 어디로 가야 목적지로 가는지를 나타낸다.

물리 : 전기선을 찾아낸다(거기까지 가는 경로)(광케이블).

여기서 웹은 TCP 통신을 한다.

TCP는 보안적으로 어떤 문제점이 있는지 알아보자.



## CIA



CIA의 C는 Confidential(기밀성), I는 Integrity(무결성), A는 Availability(가용성)이다. 

중간에 누군가가 데이터를 탈취해서 보면 기밀성이 훼손된 것이며 그 데이터를 변경하면 무결성이 깨진 것이다. 이러한 방식으로 목적지에 전달되면 가용성이 깨진 것이다. 즉, 내가 원하는 데이터가 위조 되었으므로 접근을 하지 못하게 되어 가용성이 깨진 것이다.

위와 같이 데이터를 그냥 보내게 되면 CIA가 모두 깨지게 된다.

데이터를 암호화하면 가용성이 깨질 수 있어도 기밀성은 유지되게 된다. 그렇게 되면 가용성도 확보될 수 있다.

하지만 이때 데이터 전체를 탈취하고 새로운 데이터를 심을 수 있다. 그래서 반드시 목적지에 전달되도록 만들어야 한다.

이때 목적지는 암호화된 데이터를 열 수 있는 키를 송신하는 곳으로 부터 받아야하는데 이 키를 탈취당할 수 있는 문제가 발생한다.

위 사항이 키 전달 문제이다.

두 번째 문제는 송신이 수신한테 데이터를 보낼 때 탈취되어 위조된 데이터가 목적이에 도착하거나 위조된 응답이 송신으로(ack) 도착할 수 있다. 또한, 수신단의 응답이 탈취되어 데이터가 소실되거나 위조될 수 있다.

이때 데이터가 어디서부터 왔는지 알아야 한다.

위의 키만 전달 잘 되면 데이터 위조는 불가능하다. 하지만 데이터 탈취 후 새로운 위조된 데이터를 만들어서 수신단에 전달하는 경우를 방지하려면 어디서부터 왔는지 알아야 한다.

즉, 키 전달 문제, 어디서 부터 왔는지를(인증) 해결하면 보안 문제 해결이 가능하다.

이 문제들을 해결하는 방법을 알아보자.



## RSA



암호화이며 public key, private key를 가진다.

public key : 공개키

private key : 개인키

공개키는 공개해도 되지만 개인키는 공개하면 안된다.

키 하나로 암호화하고 복호화하는 것을 symmetric key라고 한다. 열고 닫는 키여서 대칭키라고 한다.

암호화 키와 복호화 키가 다른 것을 비대칭키라고 한다.

A : 송신, B : 수신 이라고 생각하자.

A는 A공개키, A개인키가 있으며 B도 B공개키, B개인키가 있다.

A는 데이터를 B공개키로 암호화한다.

B공개키는 공개되어 있으므로 A는 B공개키로 암호화 가능하다.

이러면 중간에 데이터를 탈취당해도 B개인키가 없어서 데이터를 열어볼 수 없다.

이 방식으로 키 전달 문제를 해결한다.

B가 전송하면 A공개키로 데이터를 암호화하면 된다.

A개인키로 암호화하면 A공개키로 복호화가 가능하다. 즉, 탈취 가능하다. 하지만 여기서는 암호화가 중요하게 적용하는 것이 아닌 A가 이 데이터를 만들어서 전송했다는 사실이 중요한 것이다. 즉, B는 A의 공개키로 데이터를 열어보게 되며 이러면 A개인키로 암호화한 데이터는 A의 공개키로만 복호화 가능하기 때문에 A가 작성했다는 것을 확신할 수 있다(A만 A의 개인키로 암호화 가능하기 때문이다). 

전자 문서에서 서명으로 사용되며 개인키로 암호화하는 것은 인증의 목적으로 사용한다. 완전한 암호화로 사용되는 것은 공개키를 적용한다.

공개키 -> 개인키 (암호화)

개인키 -> 공개키 (전자 서명)(인증)

정확한 순서를 알아보자.

데이터를 B공개키로 암호화 후 이 데이터를 A개인키로 한번 더 암호화하여 전송한다.

B는 A의 공개키로 열어보고 열리면 인증이 해결되는 것이다. 안열리면 인증이 되지 않고 위조됬다고 판단한다.

위에서 인증이 되면 B의 개인키로 열어서 데이터를 확인한다.

이렇게 되면 인증, 데이터 암호화가 가능하다. 즉, CIA 문제를 해결했다.



## RFC



RFC 1번 문서는 데이터 전송시 `?name=abc` 처럼 `?` 뒤에는 데이터가 오며 파싱해야 한다는 규칙을 정한 것이다. 이러한 RFC 문서를 프로토콜이라고 한다.

이렇게 서로 데이터를 통신하기 위해 연결되면서 규약을 정하고 작성한 문서가 RFC이다.

이러한 네트워크 및 문서가 계속 모여서 만들어진 것이 WWW(World Wide Web)이라고 한다. 즉, WWW는 RFC 문서 규약으로 만들어져 있는 것이다. 이 약속의 프로토콜이 http 프로토콜이다.

이제 새로운 약속을 RFC에 정의하려고 해도 이미 있는 RFC 문서가 동의해야 정의가 될 수 있어서 어렵다.

RFC 7519 약속이 JWT이다.



# JWT



JWT는 JSON객체로 안전하게 정보를 전송하기 위한 방법이다. 이정보는 디지털 서명이 되어 있어서 신뢰 가능하다.

JWT는 암호화 메시지를 보낼 수 있지만 JWT 핵심은 서명된 토큰에 중점을 두는 것이다. 즉, 내가 작성한 JWT가 내가 쓴 것이 맞느다는 서명의 기능이다. 서명된 토큰 안에 클레임(정보, 요구사항)의 무결성을 확인할 수 있게 해준다.

JWT는 `xxxxx.yyyyy.zzzzz`로 이루어져있으며 각각 header(헤더), payload(유효 탑재량(정보)), signature(서명)로 이루어져 있다.

```json
// header
{
  "alg": "HS256", // 암호화 알고리즘
  "typ": "JWT" // 타입(jwt)
}
```

헤더는 어떤 알고리즘을 사용하여 서명했는지를 명시한다.

JSON은 Base64Url로 인코딩되어 있는데 Base64는 암호화하고 복호화 할 수 있는 암호이다.

해싱을 하면 암호화가 되지만 복호화는 되지 않는다. 하지만 Base64는 복호화가 가능하다.

Payload는 정보 부분으로 등록된 클레임, 개인 클레임으로 이루어진다.

등록된 클레임은 권장 사항으로 없어도 된다.

개인 클레임에 유저 정보에 접근 가능한 primary key와 같은 정보를 저장한다.

```json
// payload
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```

`admin : true`는 등록된 클레임이 아닌 내가 원할 때 만들 수 있는 key, value 형식의 개인 클레임이다. 여기에 유저 아이디, 유저 이름 등을 넣는다.

payload 부분에는 정보를 담는다.

```json
// signature
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

signature에는 헤더, 페이로드, 개인키를 HMAC SHA256(위 헤더의 HS256)으로 암호화한다.

JWT 순서를 알아보자.

클라이언트가 `ssar, 1234` 아이디와 패스워드로 로그인을 시도하면 서버가 header, payload, signature을 만든다.

header는 `hs256`으로 서명한다는 것이 적혀있으며 payload에는 `{username : ssar}`이 들어간다(payload는 내가 변경할 수 있다). signature에는 header + payload에 서버만 아는 키값(여기서는 cos라고 예를 들자)인 cos를 더해서 hs256으로 암호화 한다.

SHA256은 해쉬를 하는 것으로 복호화할 수 없는 키값을 만드는 것이다.

HMAC은 시크릿 키를 포함한 암호화 방식이다. 즉, 위의 signature은 cos라는 시크릿 키를 포함하여 암호화 했으므로 HMAC이다.

HS256으로 암호화 후 header, payload, signature 각각을 base64로 인코딩 한다.

이 후 클라이언트에게 전송한다. 물론 이 과정은 서버에서 인증이 완료 되면 발생한다.

이 정보를 클라이언트 웹 브라우저의 local storage 영역에 저장한다.

이 후 클라이언트가 서버에 "내 개인정보 줘" 하면서 local storage에 있는 jwt도 전송한다.

서버는 이 jwt가 신뢰할 수 있는지 검증 과정을 거쳐야 한다. 서버는 전송받은 header + 전송받은 payload + 자신이 가지고 있는 시크릿 키(cos)를 하여 똑같이 hs256으로 암호화 해본다. 이것을 signature과 비교하여 같으면 로그인했던 사람이라고 인증하는 것이 가능하다.

이제 "내 개인정보 줘"라는 요청에 응답해야 하는데 이것은 payload의 `username`정보를 이용하여 데이터베이스에 접근하여 필요한 데이터를 응답한다.

RSA의 경우 서버는 header + payload를 개인키로 암호화하여 signature 생성 후 클라이언트에게 응답한다.

클라이언트가 서버에 다시 요청할 때 서버는 검증 시 공개키로 signature을 열어보기만 하면 된다. 즉, 공개키로 서명을 검증한는 것이다.

RSA보다 hs256을 더 많이 사용하는 추세이다.

즉, 전반적으로 보면 header, payload는 복호화 가능하게 base64로 인코딩 했으므로 암호화 목적이 아닌 서명, 무결성이 목적인 것이다.

JWT는 세션을 사용하지 않고 검증이 이루어지기 때문에 로드밸런싱으로 어느 서버에 들어가도 인증이 가능하다. 서버들은 동일한 시크릿 키(cos)만 알고 있으면 된다. 그리고 JWT는 서버만 만들 수 있으므로 그 서버의 시크릿 키만 사용가능하다.

이제 JWT를 코드로 구현해보자.

JWT서버를 만들면서 oauth 사용하고 싶으면 예전 방법이 아닌 다른 방법을 사용해야 한다.

JWT 토큰을 하나하나 base64로 인코딩, HMAC 암호화해서 만들어도 되지만 그것을 만들어주는 라이브러리가 존재한다.

[jwt](https://mvnrepository.com/artifact/com.auth0/java-jwt)

3.10.2를 선택하고 pom.xml에 입력한다.

```xml
<!-- https://mvnrepository.com/artifact/com.auth0/java-jwt -->
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>3.10.2</version>
</dependency>
```

JWT의 구조를 알아보자.

base64(header).

base64(payload).

base64(hs256암호화(header+payload+secret_key))

각 요소가 base64로 인코딩되며 `.`으로 구분된다.
signature은 base64된 string 형식의 header, payload, secret_key를 더한 후 hs256으로 암호화하고 base64로 인코딩 한 것이다.

위 활동을 jwt 라이브러리로 한번에 해결한다.



## SecurityConfig & CorsConfig



```java
@Configuration // IoC할 수 있게 만든다.
@EnableWebSecurity // 이 시큐리티를 활성화 한다.
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // CorsConfig에서 등록한 CorsFilter을 이용한다.
    private final CorsFilter corsFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        // jwt설정의 기본이다.
        // stateless 서버로 만들겠다는 뜻이다.
        // 세션을 사용하지 않겠다는 뜻이다.
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // @CrossOrigin은 인증이 없을 때 실행되고 시큐리티 필터에 필터를 등록해야 인증이 있을 때 실행된다.
                // 이걸로 이제 요청 시 시큐리티의 로그인 창이 뜨지 않는다.
                .addFilter(corsFilter)
                // jwt 서버이므로 폼 로그인을 하지 않은다.
                .formLogin().disable()
                // 기본적인 http 로그인 방식을 사용하지 않는 것이다.
                .httpBasic().disable()
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();

    }
}
```

```java
// 이 설정을 SecurityConfig의 configure에 넣는다.
@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter(){
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        // 내 서버가 응답할 때 json을 자바스크립트에서 처리할 수 있게 할지를 설정하는 것이다.
        // false이면 자바스크립트로 요청했을 때 응답하지 않는다.
        config.setAllowCredentials(true);
        // 어디서든지 허용해주게 하는 것이다.
        // 모든 ip에 응답을 허용하는 것이다.
        config.addAllowedOrigin("*");
        // 모든 헤더 허용한다.
        // 모든 헤더에 응답을 허용한는 것이다.
        config.addAllowedHeader("*");
        // 모든 http 메소드 허용한다.
        // 모든 post, get, put, delete, patch 요청을 허용하는 것이다.
        config.addAllowedMethod("*");
        // "/api/**"로 들어오는 것은 이 config 설정을 따르게 하라.
        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);
    }
}
```

```java
@Entity
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    // 이렇게 하면 mysql을 사용하면 auto increment 된다.
    private long id;
    private String username;
    private String password;
    private String roles; // USER, ADMIN

    // roles 스트링에 "USER, ADMIN"들어간 경우 ','로 나눠서 리스트로 반환한다.
    public List<String> getRoleList(){
        if(this.roles.length() > 0){
            return Arrays.asList(this.roles.split(","));
        }
        return new ArrayList<>();
    }

}
```

현재 필터를 생성하여 인증이 필요한 시점에도 사용되고 자바스크립트의 요청을 json으로 허용할 수 있게 되었다.

필터로 시큐리티의 로그인 창이 사라졌다.

주석 참조하라.

원래 웹은 stateless인데 stateful처럼 사용하기 위해 session, cookie를 만드는데 `http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)`는 그 방식을 사용하지 않겠다고 하는 것이다.

`formLogin().disable`은 폼으로 로그인하는 것을 하지 않겠다는 것이다.

자바스크립트로 210.10.10.5(예시) ip에서 요청을 보내면 쿠키는 웹브라우저에 저장되어있는 쿠키는 전송되지 않는다. 그래서 쿠키를 강제로 코드로 담아서 요청할 수 있다. 하지만 요즘 대부분 서버는 쿠키가 `http only`로 설정되어 있어서 http가 아닌 자바스크립트 등은 쿠키 자체를 건들 수 없게 되어있다.
이때 서버에서 `http only`를 해제하면 쿠키가 서버에 도착하긴 한다. 하지만 `http only`를 풀면 자바스크립트로 이상한 요청을 하여 서버의 보안 측면에서 좋지 않다.

쿠키 방식을 사용하고 서버가 많아질수록 확장성이 많이 떨어지고 관리하기 어려워진다.
헤더에 `Authorization : ID, PW`를 담에서 요청하는 방식이 `http basic`방식이다. 이렇게 요청하면 매번 ID, PW를 달고 요청하게 된다. 이것은 요청할 때마다 계속 인증하는 것이므로 쿠키 세션이 필요 없어진다. 확장성은 좋아지지만 ID, PW는 암호화가 되지 않기 때문에 요청 도중에 노출될 수 있다. 이때 노출 안되게 하기 위해 `https`를 사용해야 한다. 그러면 ID, PW가 암호화 되어 전송된다.

우리가 하려는 방식은 `Authorization`에 토큰을 넣는 방식이다. 토큰은 노출되어도 ID, PW가 아니므로 위험 부담이 적다. 이 토큰은 ID, PW를 통해 만든 것이다. 이렇게 토큰을 달고 요청하는 방식이 `Bearer` 방식이다. 로그인 시마다 서버에서 새로운 토큰을 다시 만들지만 ID, PW는 한번 노출되면 위험하다는 차이가 있다. 이 토큰은 유효시간이 있어서 특정 시간이 지나면 노출되어도 인증이 안된다. 물론 이 토큰을 탈취하면 다른 사람이 이 토큰을 이용하여 로그인 요청을 할 수 있긴하다.

이 토큰 방식을 쓸 때 JWT 토큰을 만든다. 그래서 stateless 로 `session`방식을 사용하지 않고 `http basic` 방식도 사용하지 않는다고 선언하는 것이다. 즉, `Bearer` 방식을 사용하는 것이다.



## Filter



```java
// SecurityConfig

@Override
protected void configure(HttpSecurity http) throws Exception {
    // addFilter을 하면 addFilterBefore이나 addFilterAfter을 사용해서 시큐리티 필터 시작 전이나 후에 실행되게 하라고 한다.
    // 아래 BasicAuthenticationFilter를 쓰면 SpringFilterChain의 이 필터가 실행되기 전에 내가 만든 필터가 실행된다는 뜻이다.
    // 하지만 시큐리티 필터에 생성한 필터를 걸어줄 필요없이 IoC로 필터를 적용할 수 있다.
    // 만약 시큐리티 필터보다 먼저 내 필터를 실행하고 싶으면 before로 시큐리티 필터의 가장 앞을 설정하면 된다.
    http.addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class);
}
```

```java
public class MyFilter1 implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("필터1");
        // 여기서 PrintWriter out = response.getWriter();
        // out.print("안녕"); 이라고 하면 여기서 걸리면서 프로그램이 끝난다.
        // chain에 넘겨줘야 프로그램이 진행된다.
        filterChain.doFilter(servletRequest, servletResponse);
    }
}
```

```java
// 이때 시큐리티 필터가 모두 실행된 후 이 필터들이 실행된다.
// addFilterAfter로 설정해도 이 클래스의 필터가 나중에 실행된다.
@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<MyFilter1> filter1(){
        FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
        // 모든 요청에 대해 다 하라.
        bean.addUrlPatterns("/*");
        // 우선 순위 설정으로 낮은 번호가 필터 중에서 가장 먼저 실행된다.
        bean.setOrder(0);
        return bean;
    }

    @Bean
    public FilterRegistrationBean<MyFilter2> filter2(){
        FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
        // 모든 요청에 대해 다 하라.
        bean.addUrlPatterns("/*");
        // 우선 순위 설정으로 낮은 번호가 필터 중에서 가장 먼저 실행된다.
        bean.setOrder(1);
        return bean;
    }
}
```

시큐리티 필터라는 것이 존재한다.

직접 생성한 필터를 적용할 때 두 가지 방법이 존재한다.

SecurityConfig의 addFilterBefore(), addFilterAfter()로 시큐리티 필터 중 하나 이전이나 이후에 실행되게하거나 직접 IoC로 필터를 등록 할 수 있다.

IoC로 필터를 등록하게 되면 항상 시큐리티 필터보다 나중에 실행된다.

시큐리티 필터보다 먼저 실행되고자 하면 시큐리티 필터 중 가장 먼저 실행되는 객체를 기준으로 before를 사용한다.



```java
public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("필터3");
        // 여기서 PrintWriter out = response.getWriter();
        // out.print("안녕"); 이라고 하면 여기서 걸리면서 프로그램이 끝난다.
        // chain에 넘겨줘야 프로그램이 진행된다.
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse res = (HttpServletResponse) servletResponse;

        // cos라는 이름의 토큰을 생성하였다고 가정하자.
        // cos 토큰이 도착한 것이 아니면 인증을 하지 않고 컨트롤러로 들어가지 못하게 한다.
        // 이 필터는 시큐리티 필터가 적용되기 전에 실행되어야 한다.
        // id, pw가 정상적으로 들어와서 로그인이 완료 되면 토큰을 만들어주고 그걸 응답해줘야 한다.
        // 이후 다음 요청에 토큰이 넘어오면 토큰을 검증하면 된다. (RSA, HS256)
        if(req.getMethod().equals("POST")){
            System.out.println("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);

            if (headerAuth.equals("cos")){
                filterChain.doFilter(req, res);
            }else{
                PrintWriter out = res.getWriter();
                out.println("인증안됨");
            }
        }
    }
}
```

```java
// SpringSecurity

@Override
protected void configure(HttpSecurity http) throws Exception {
    http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
}
```

필터에 요청이 왔을 때 Authorization 헤더에 정확한 토큰이 있는지 간단하게 검증하는 로직이다.

필터 등록 시 시큐리티 필터보다 먼저 실행되어야 한다는 것에 주의하자.



