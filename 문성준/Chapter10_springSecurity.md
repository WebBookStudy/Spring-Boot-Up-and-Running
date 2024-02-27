# ch10 App security

---

---

# 서론

인증과 인가(권한부여)의 차이를 명확히 이해해야 security App을 구축하고 사용자 확인과 접근 제어를 위한 기반을 마련할 수 있습니다.

spring security는 Authentication(인증)과 Authorization(인가)를 위한 옵션을 HTTP 방화벽, 필터 체인, IETF와 **W3C**(World Wide Web Consortium) 표준의 광범위한 사용, 교환 옵션과 같은 메커니즘과 결합해 app security을 높입니다.

---


---

## 10.1 인증 및 인가부여

### 인증

어떤 것을 실제, 사실 또는 진짜로 보여주는 행위, 프로세스나 방법, 무언가를 입증하는 행위나 과정

### 인가(권한 부여)

1 : 권한을 부여하는 행위

2: 권한을 부여하는 수단
    ‘인가’의 첫 번째 정의는 더 많은 정보에 권한을 부여하는 것을 의미한다.

### 인가하다

1 : 오랜 시간에 걸쳐 인가된 관습을 인정하거나 적절한 권위(관습, 증거, 개인 권리나 규제 같은)로 승인, 권한 부여, 정당화하거나 허용하는 것

2 : 특히 법적 권위 부여 : 권한부여

3 : 고전적 의미 : 정당화
즉, ‘인가하다’의 정의는 더 많은 정보를 정당화하는 것을 의미한다.

이러한 정의들이 있지만, 사실상 이해하기 어렵고 어떤 것들에 대해서의 정의는 떄때론 다른 의미이기도 합니다.
예를 들면, 도메인 입니다.

도메인은 어떤 아키텍처, 또는 모델에 적용하냐에 따라 도메인이라는 고유의 정의가 달라지기 때문입니다.
따라서, 제가 생각하기엔 해당 용어에 대해 ‘스프링부트의 인가’라고 하면 해당 기술에 따라서 이해하는 바를 다르게 하여 이해해야 한다는 것입니다. 정의로 명확하게 표현할 수 없기 때문입니다. (나의 생각)

<aside>
📌 **정리**
- 인증 : 누군가가 자신이 주장하는 사람임을 증명하기 (신분증 같은 거)
- 인가 : 누군가가 특정 리소스나 작업에 접근할 수 있는지 확인하기

</aside>

---

### 10.1.1 인증

인증은 증명하는 것이라고 생각하면 쉽습니다.

### 10.1.2 인가

일단 사용자가 인증을 받으면, 한 명 이상의 개인에게 허용된 사용 가능한 리소스 및/또는 작업에 접근할 수 있다.
개인은 신원이 입증되면 app에 대한 일반 수준의 접근 인가를 얻는다. 이제 인증된 app 사용자는 무언가에 대한 접근을 요청한다. 그러면 app은 해당 리소스에 대한 사용자의 접근 아니면 인가 여부를 어떻게든 결정해야 한다.
사용자의 인가가 확인되면 사용자에게 접근 권한이 부여된다. 그렇지 않은 경우, 접근 권한 부족으로 요청이 거부됐음을 사용자에게 알린다.

---

## 10.2 스프링 시큐리티의 3가지 주요 기능

### 10.2.1 HTTP 방화벽

스프링 시큐리티 5.0버전부터는 문제가 있는 형식의 모든 인바운드 요청을 살펴보는 HTTP 방화벽이 내장되었다.
잘못된 헤더값이나 형식 등 요청에 문제가 있는 경우 요청을 폐기한다.
개발자가 오버라이드하지 않는 한, 사용되는 기본 구현은 이름에 걸맞은 StrictHttpFireWall로 빈틈을 메운다.

### 10.2.2 보안 필터 체인

요청이 필터와 일치하면, 해당 조건을 평가하고 요청의 이행 여부를 결정한다.
예) 특정 API 엔드포인트에 대한 요청이 도착하고 필터 체인의 필터 조건과 일치하면, 사용자가 요청된 리소스에 접근할 수 있는 적절한 역할/인가가 있는지 확인한다. 

만약, 요청이 체인에 정의된 모든 필터와 일치하지 않고 지나치면, 요청은 삭제된다.

### 10.2.3 요청 및 응답 헤더

---

## 10.3 스프링 시큐리티 폼 기반 인증 및 인가 구현

스프링 시큐리티는 자동 설정과 이해하기 쉬운 추상화로 비밀번호 인증을 지원하는 뛰어난 OOTB(즉시 사용가능한)를 스프링 부트 애플리케이션에 제공한다. 

### 10.3.1 의존성 추가하기

새로운 app을 만들 때 추가 설정 없이 최상위 보안 수준을 활성화하기는 매우 간단하다.
스프링 이니셜라이저를 이용해 Spring Security 의존성만 추가하면, 다른 설정 없이 최상위 보안 수준을 활성화한다.

해당 path의 엔드포인트를 지정하게 된다면, 지정한 엔드포인트만이 app의 정보에 액세스하는 유일한 수단이다.원치 않는 액세스로부터 완전히 보호되지만 어떻게 이런 일이 발생하고 어떻게 유효한 사용자가 원하는 접근을 하도록 복원하는지 그 방법을 모두 이해해야한다.

스프링 시큐리티는 스프링 시큐리티를 사용할 때 모든 수준(아무 설정도 하지 않을 때조차)에서 ‘최대의 보안이 기본값’이라는 사고 방식을 채택한다. 즉, 프로젝트에 스프링 시큐리티가 포함되면 app에 보안 목표가 있음을 의미한다.

→ 스프링 부트 + 시큐리티 자동 설정은 상당수의 필수적인 빈을 생성한다 → 왜? 어떻게 ??? → 사용자 id와 pw를 이용하는 사용자 인가와 폼 인증을 기반으로 한 기본 보안 기능을 구현하기 위해서.

그렇다면, 의아할 것이다. 도대체 어떤 사용자 id와 pw를 기본으로 하는 것인가?

app에 사용자 id와 pw가 지정되지 않았거나 액세스할 다른 수단이 제공되지 않은 경우, 보안이 활성화된 스프링 부트 app은 기본적으로 ***user***라는 사용자 id와 함께 ***고유 pw***가 있는 단일 계정을 생성하고, pw는 app이 시작될 때마다 새로 생성된다. 터미널 창에 제공된 pw를 사용해 app에 접근 시도를 테스트 해보면 알 수 있따.

- 캐시 제어
Cache-Control 헤더는 no-cache, no-store, max-aged=0, must-revalidate 지시문으로 설정된다.
Pragma 헤더는 no-cahce 지시문과 함께 반환되고, Expires 헤더에는 0값이 제공된다.
모든 메커니즘은 브라우저/사용자 에이전트 기능 적용 범위에서 발생할 만한 빈틈을 제거해 캐싱에 대한 최상의 제어를 최상의 캐싱 제어를 보장하기 위해 지정된다. 
즉, 사용자가 사이트에서 로그아웃하면, 적대적인 행위자가 단순히 브라우저의 ‘뒤로 버튼’을 클릭해 피해자의 인증 정보로 로그인된 보안 사이트로 돌아가지 못하도록 캐싱을 무효화한다.
- 콘텐츠 유형 옵션 
X-Content-Type-Options : 스프링 시큐리티는 기본적으로 nosniff 설정을 제공해 공격 경로를 막음.

---

### 10.3.2 인증 추가하기

스프링 시큐리티 인증 기능의 핵심은 UserDetailService 개념이다.

UserDetailService는 단일 메서드 loadUserByUsername(String username)가 있는 인터페이스로, (구현 시) UserDetails 인터페이스를 충족하는 객체를 반환하고 이 인터페이스에서 주요 정보를 얻는다.

여기서 말하는 주요 정보란 사용자 이름, 비밀번호, 사용자에게 부여된 인가와 계정 상태 등이다. 이러한 유연성 덕분에 다양한 기술로 수많은 구현이 가능해진다. UserDetailsService가 UserDetails를 반환하는 한, app은 기본 구현의 세부 정보를 알 필요가 없다.

UserDetailService 빈을 생성하기 위해 빈 생성 메서드를 정의할 설정 클래스를 생성한다.

<aside>
👉 빈 생성

</aside>

먼저 SecurityConfig라는 클래스를 만들고 @Configuration 어노테이션을 달아 스프링 부트가 내부에서 빈 생성 메서드를 찾고 실행하도록 한다.

인증에 필요한 빈은 `UserDetailsService` 인터페이스를 구현한 빈이므로 해당 빈을 생성하고 반환하기 위해 `authentication()` 메서드를 생성한다.

다음은 의도적으로 완성하지 않은드이다.

```java
@Configuration
public class SecurityConfig{
/**
얘를 추가해줌으로써 비밀번호 암호화.
private final PasswordEncoder pwEncoder = 
				PasswordEncoderFactories.createDelegatingPasswordEncoder();	
*/

	@Bean
	UserDetailsService authentication(){
		UserDetails peter = User.builder()
						.username("peter")
						.password("ppassword") // .password(pwEncoder.encode("ppassword"))
						.roles("USER")
						.build();
	
	UserDetails jodie = User.builder()
						.username("jodie")
						.password("jpassword")
						.roles("USER", "ADMIN")
						.build();

	sout(peter.getPassword());
	sout(jodie.getPassword());

	return new InMemoryUserDetailsManager(peter, jodie);
}}
```

UserDetailsService authentication() 메서드 내에서, User 클래스의 builder() 메서드를 사용해 사용자의 이름, 비밀번호, 역할/인가를 지정해서 UserDetails 인터페이스 요구사항을 구현하는 객체를 두 개 만든다. 그런 다음 이 사용자를 build()하고 지역 변수에 할당한다.

다음에는 시연용으로만 비밀번호를 표시한다. 개념을 설명하기 위함이다.

<aside>
⁉️ 참고
비밀번호 로깅은 최악의 안티패턴이다.
프로덕션 app에는 절대로 비밀번호를 기록하면 안된다.

</aside>

위 전체코드를 실행한다면 비밀번호는 인코딩되지 않은 일반 텍스트로 나오게 된다.
보안성 있는 인증을 위해서는 다음과 같이 SecurityConfig 클래스 내에서 사용할 비밀번호 인코더를 추가해준다.

```java
private final PasswordEncoder pwEncoder = 
				PasswordEncoderFactories.createDelegatingPasswordEncoder();
```

인코더를 추가했으니 인코더를 사용해 사용자 pw를 암호화하면 된다. 비밀번호 인코더의 encode() 메서드에 일반 텍스트로 된 비밀번호를 전달한 후 호출하면, 암호화된 결과를 반환한다.

<aside>
📌 Tip,
암호화를 할 때는 현재 권장되는 스프링 시큐리티 인코더를 선택하거나 아니면
PasswordEncoderFactories.createDelegatingPasswordEncoder()에서 제공하는 기본 인코더를 선택하면 된다.

</aside>

인코딩된 비밀번호를 확인하기 위해 IDE의 출력된 로깅을 보면, 로깅된 값은 두 예제 비밀번호가 BCrypt를 사용해 위임된 비밀번호 인코더에 의해 성공적으로 인코딩됐음을 보여준다.

지금까지 암호화를 배웠다. 이 암호화는 암호화 자체에 보안성이 있기 때문에 “키값이 알고리즘을 나타내니 복호화하기가 더 쉽지 않을까?”라는 의견에 당당히 “아니오”라고 할 수 있게 된다.

---

### 10.3.3 인가

이제 사용자를 성공적으로 인증하고 해당 사용자에게만 노출된 API 접근을 허용한다.
그러나 현재 보안 설정에는 심각한 결함이 있다. 사용자가 API의 일부에 접근할 수 있다면, 사용자가 소유한 역할/인가와 관계없이, 더 정확하게는 소유하지 않은 역할과 관계없이 모든 API에도 접근할 수 있다.

<aside>
❓ 위 설명은 스프링 시큐리티에서의 역할 기반 접근 제어(RBAC)에 대한 중요한 개념을 다루고 있습니다. 여기서 언급하는 '심각한 결함'은 사용자가 특정 API에 접근 권한을 가지고 있다는 것이, 그 사용자가 시스템 내의 모든 API에 접근할 수 있음을 의미한다는 점입니다. 즉, 역할 또는 권한을 기반으로 세밀한 접근 제어를 하지 않는 한, 인증된 사용자가 모든 리소스에 접근할 수 있는 상태를 의미합니다.

스프링 시큐리티는 인증과 인가를 통해 보안을 관리합니다

- **인증(Authentication)**: 사용자가 누구인지 확인하는 과정입니다. 예를 들어, 사용자 이름과 비밀번호를 제공하여 자신이 주장하는 사람임을 증명합니다.
- **인가(Authorization)**: 인증된 사용자가 수행할 수 있는 작업을 결정하는 과정입니다. 이는 주로 사용자의 역할이나 권한에 따라 다릅니다.

문제의 핵심은 인증 절차를 성공적으로 통과한 사용자가 있더라도, 해당 사용자에게 적절한 역할이나 권한이 부여되지 않았다면, 그들이 시스템 내에서 수행할 수 있는 작업을 제한해야 한다는 것입니다. 그렇지 않으면, 사용자가 시스템의 모든 부분에 접근할 수 있게 되어 보안 위험이 발생할 수 있습니다.

예를 들어, '`**ADMIN**`' 역할을 가진 사용자만이 사용자 관리 기능에 접근할 수 있어야 합니다. 만약 인증된 모든 사용자가 이러한 관리 기능에 접근할 수 있다면, 이는 심각한 보안 결함이 됩니다. 따라서, 스프링 시큐리티를 사용할 때는 다음과 같이 역할 또는 권한을 기반으로 접근 제어를 설정해야 합니다.

```java
http.authorizeRequests()
    .antMatchers("/admin/**").hasRole("ADMIN") // 'ADMIN' 역할을 가진 사용자만 /admin/** 경로에 접근 가능
    .antMatchers("/user/**").hasRole("USER") // 'USER' 역할을 가진 사용자만 /user/** 경로에 접근 가능
    .anyRequest().authenticated(); // 그 외 모든 요청은 인증된 사용자에게만 허용
```

이러한 방식으로, 스프링 시큐리티는 세밀한 접근 제어를 통해 애플리케이션의 보안을 강화할 수 있습니다.

</aside>

이 결함의 아주 간단한 예로, PositionController 클래스의 기존 getCurrentAircraftPositions() 메서드를 복제하고, 이름 변경 후 다시 매핑해 진행중인 앱의 두 번째 엔드 포인트를 추가한다. 

목표는 ADMIN 역할을 하는 사용자만 두 번째 메서드인 getCurrentAircraftPositionsAdminPrivs()에 접근할 수 있게 하는 것이다. 이 예제에서 반환된 값은 getCurrentAircraftPositions()에서 반환된 값과 동일하지만, app 확장 시 반환 값이 그대로 유지되지 않을 가능성이 있다. 하지만 개념은 이와 관계없이 적용된다.

해당 앱을 다시 시작하고 명령 줄로 돌아가서 예쌍대로 새 엔드포인트에 대한 접근을 확인하기 위해 사용자 ‘Jodie’ 먼저 로그인한다(첫 번째 엔드포인트에 대한 접근은 확인했지만 지면 관계상 생략했으며, 간결함을 위해 일부 헤더와 결과도 생략했다)

그다음 ‘Peter’로 로그인한다. ‘Peter’는 /aircraftadmin에 매핑된 getCurrentAircraftPositionsAdminPrivs() 메서드에 접근할 수 없어야 한다. 하지만 실제로는 그렇지 않다.
확인해보면, 현재 Peter(인증된 사용자)는 모든 항목에 접근할 수 있다.

콘솔창을 확인해보았듯이 해당 앱이 단순히 사용자를 인증하는 것이 아니라 특정 리소스에 접근할 수 있는 사용자 인가를 확인하도록 SecurityConfig를 리팩터링해야 한다.

스프링 시큐리티 5.4부터 SecurityFilterChain 빈을 생성해 HttpSecurity를 설정하게 됐다.

```java
@Bean
public SecurityFilterChain configure(HttpSecurity http) throws Exception{
	//로깅 문 생략
	return http
						.authorizeHttpRequests()
						.anyReqyest().authenticated()
						.and()
						.formLogin()
						.and()
						.build();
}
```

구현된 코드의 기능은 다음과 같다.

- 인증된 사용자의 모든 요청을 승인한다.
- 간단한 로그인과 로그아웃 양식(개발자가 생성한 재정의가 가능한 양식)을 제공한다.
- CLI 요청처럼, 브라우저가 아닌 곳에서 요청을 보내는 사용자에게도 HTTP 기본 인증을 활성화한다.

이 기능은 개발자가 인증 세부 사항을 제공하지 않을 때 합리적인 보안 상태를 제공한다. 다음 단계에서는 더 구체적으로 이 동작을 재정의하게 된다.

```java
// 사용자 인가
@Override
protected void configure(HttpSecurity http) throws Exception{
	return http
						.authorizeHttpRequests()
						.requestMatchers("/aircraftadmin/**").hasRole("ADMIN")
						.anyReqyest().authenticated()
						.and()
						.formLogin()
						.and()
						.httpBasic()
						.and()
						.build();
}
```

configure(HttpSecurity http) 메서드 구현은 다음 작업을 수행한다.

- String 패턴 일치자를 사용해 요청 경로가 /aircraftadmin 및 아래의 모든 경로와 일치하는지 비교한다.
- 일치에 성공하면, 사용자에게 ‘ADMIN’ 역할/인가가 있는 경우 요청할 수 있는 인가를 부여한다.
- 인증된 사용자가 실시한 모든 요청을 수행한다.
- 간단한 로그인과 로그아웃 폼(개발자가 생성한 재정의가 가능한 폼)을 제공한다.
- CLI 요청처럼, 브라우저가 아닌 곳에서 요청을 보내는 사용자에게도 HTTP 기본 인증을 활성화한다.

이 최소한의 인가 메커니즘은 보안 필터 체인에 필터 두 개를 배치한다.
하나는 경로 일치와 관리자 인가를 확인하는 것이고, 다른 하나는 그 외 모든 경로와 인증된 사용자를 확인하는 것이다. 계층화된 접근방식을 사용하면 복잡한 시나이로도 매우 간단하고 추론하기 쉬운 논리로 다루게 된다.

---

SecurityConfig 클래스의 최종 버전(폼 기반 보안)이다. 

```java
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigureAdapter{
	private final PasswordEncoder pwEncoder =
					PasswordEncoderFactories.createDelegatingPasswordEncoder();
	
	@Bean
	UserDetailsService authentication(){
		UserDetails peter = User.builder()
						.username("peter")
						.password(pwEncoder.encode("ppassword")
						.roles("USER")
						.build();

		UserDetails jodie = User.builder()
						.username("jodie")
						.password(pwEncoder.encode("jpassword")
						.roles("USER", "ADMIN")
						.build();

	sout(peter.getPassword());
	sout(jodie.getPassword());

	return new INMemoryUserDetailsManager(peter, jodie);
}

@Bean
public SecurityFilterChain configure(HttpSecurity http) throwse Exception{
	return http
						.authorizeHttpRequests()
						.requestMatchers("/aircraftadmin/**").hasRole("ADMIN") 
						.anyRequest().authenticated()
						.and()
						.formLogin()
						.and()
						.httpBasic()
						.and()
						.buidle();
```

이제 테스트를 해보면 ‘Jodie’는 ADMIN 역할을 수행하기 때문에 예상대로 /aircraftadmin 엔드포인트에 접근할 수 있다. 그러나 ‘Peter’는 USER 역할만 하기 때문에 오류가 발생한다.

내가 생각 했을 떄, 아래 코드는 SecurityConfig 클래스의 완전 최종 코드다.

이 설정은 사용자가 로그인 폼을 통해 인증을 수행할 수 있도록 하며, 역할 기반으로 접근 제어를 설정합니다. 또한, 기본적인 CSRF 보호와 세션 관리를 포함하고 있습니다.

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable() // CSRF 보호 기능을 비활성화 (테스트 목적이라면 활성화를 권장)
            .authorizeRequests()
                .antMatchers("/admin/**").hasRole("ADMIN") // 'ADMIN' 역할을 가진 사용자만 /admin/** 경로에 접근 가능
                .antMatchers("/user/**").hasAnyRole("USER", "ADMIN") // 'USER' 또는 'ADMIN' 역할을 가진 사용자만 /user/** 경로에 접근 가능
                .antMatchers("/", "/home", "/register", "/login").permitAll() // 모든 사용자에게 /, /home, /register, /login 경로 접근 허용
                .anyRequest().authenticated() // 그 외 모든 요청은 인증된 사용자에게만 허용
            .and()
            .formLogin()
                .loginPage("/login") // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/home") // 로그인 성공 시 리디렉션할 기본 경로
                .permitAll() // 모든 사용자가 로그인 페이지에 접근할 수 있도록 허용
            .and()
            .logout()
                .permitAll(); // 모든 사용자가 로그아웃할 수 있도록 허용
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication()
                .withUser("user").password(passwordEncoder().encode("password")).roles("USER")
            .and()
                .withUser("admin").password(passwordEncoder().encode("admin")).roles("ADMIN");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // 비밀번호 암호화를 위한 BCryptPasswordEncoder 사용
    }
}
```

이 코드는 스프링 시큐리티의 기본 원리와 설정 방법을 보여주며, 실제 사용 환경에서는 데이터베이스에서 사용자 정보를 가져오는 등의 추가 구성이 필요할 수 있습니다. 또한, CSRF 보호를 비활성화하는 것은 개발 중이나 테스트 환경에서만 권장되며, 실제 운영 환경에서는 보안을 위해 활성화하는 것이 좋습니다.

---

## 10.4 인증 및 인가를 위한 OIDC와 OAuth2 구현

스프링 시큐리티는 검증된 사용자 인증과 인가 확인을 OIDC(OpenIdConnect)와 OAuth2를 통해 이러한 옵션 전부와 그 이상을 지원한다.

OAuth2는 클라우드 기반 서비스, 공유 저장소, app 같은 지정된 리소스에 사용자의 제 3자의 인증 수단을 제공하기 위해 만들었다. 그리고 OAuth2를 기반으로 OIDC는 다음중 하나 이상의 요소를 사용해 일관되고 표준화된 인증을 제공한다.

- 비밀번호와 같이 알고 있는 것
- 하드웨어 키와 같이 가진 것
- 생체 인식 식별자와 같은 자신의 존재

스프링 부트와 시큐리티는 페북, 깃헙, 구글, Okta 등에서 제공하는 OIDC와 OAuth2 구현을 위한 자동 설정을 지원하고, OIDC, OAuth2, 스프링 시큐리티의 확장 가능한 아키텍처에 대해 발표된 표준으로 추가 공급자를 쉽게 설정한다. 자신이 필요로 하는 가장 적합한 보안 공급자를 자유롭게 이용하면 된다.

<aside>
👉 ***OIDC 및 OAuth2를 위한 다양한 애플리케이션/서비스 역할***
이 절에서는 인증과 인가를 위해 각각 OIDC, OAuth2를 사용한 서비스가 수행하는 역할만 설명하지만, 실제로 모든 유형의 타사 인증과 인가 메커니즘에 전체적으로 또는 부분적으로 적용할 수 있다.

- app/service는 세 가지 기본 역할을 수행한다.
1. 클라이언트
2. 인가 서버
3. 리소스 서버

일반적으로 서비스는 클라이언트이자 최종 사용자가 상호작용하는 app/service이며,
사용자에게 부여된 인가(역할/권한)을 인증하고 획득하기 위해 보안 제공자와 협력한다.

인가 서버는 사용자 인증을 처리하고 사용자가 소유한 인가를 클라이언트에 반환한다.
인가 서버는 시간이 지정된 인가 발행과 선택적으로 갱신을 처리한다.

리소스 서버는 클라이언트가 제시한 인가를 기반으로 보호되는 리소스에 접근하게 해준다.

스프링 시큐리티로 세 유형의 애플리케이션/서비스를 모두 만들 수 있지만,
해당 책에선 클라이언트와 리소스 서버를 만드는데 초점을 뒀다.

</aside>

책의 예제 app이 OIDC와 OAUth2 클라이언트 app의 역할을 하도록 리팩토링한다.
그 역할이란 Okta의 기능을 사용해 사용자를 확인하고, 리소스 서버에 접근해 리소스를 접근 가능케 하는 사용자 인가를 획득하는 일이다.

그런 다음 app의 (클라이언트 서버 역할) 요청과 함께 제공된 자격 증명을 기반으로, app이 OAuth2 리소스 서버로서 리소스를 제공하도록 리팩토링한다.

---

### 10.4.1 app 리팩토링

사용자는 일부 메커니즘을 사용해 사용자를 인증하는 클라이언트 애플리케이션에 접근한다.
일단 인증되면 리소스에 대한 사용자 요청은 해당 리소스를 보유하고 관리하는 리소스 서버로 중계된다.
이는 우리 대부분이 반복적으로 따르는 매우 익숙한 흐름이다.
리소스 서버로 순서를 동일하게 하여 클라이언트에서 리소스 서버로 보안을 활성화하면 우리가 에쌍하는 흐름과 깔끔하게 일치한다.

**의존성추가**

이니셜라이저로 의존성 OAuth2 client(OIDC 인증 부분과 그 밖의 필수 설정 요소 포함), Okta을 추가하면 된다.

**인증 및 인가(권한부여)를 위한 앱 리팩토링**

app을 OAuth2 클라이언트 app으로 설정하려면 세 가지를 수행해야 한다.

- 폼 기반 보안 설정 제거
- PlaneFinder 앱의 엔드포인트 접근에 사용된 WebClient에 OAuth2 설정 추가
- OIDC + OAuth2에 등록된 클라이언트 자격 증명을 지정하고 보안 제공자(이 경우 Okta)에 대한 URI 지정.

SecurityConfig 클래스의 바디 전체를 제거하는 일부터 시작해서 방금 전에 언급한 두 항목을 함께 처리한다.
앱에서 로컬로 제공하는 리소스에 대한 접근 제어를 여전히 원하거나 필요로 한다면, SecurityConfig를 그대로 유지하거나 약간 수정한다.
그러나 이 예제에선 PlaneFinder앱이 리소스 서버의 역할을 하므로 리소스에 대한 요청을 제어하거나 거부해야 한다. 앱은 사용자 인증을 하도록 보안 인프라와 함께 클라이언트 역할을 하며, 그다음 리소스 요청을 리소스 서버에 전달한다.

로컬 인증을 위한 자동 설정이 더 이상 필요하지 않으므로, `@EnableWebSecurity` 어노테이션을 `@Configuration`으로 대체한다. 또 클래스 헤더에서 WebSecurityCofigurerAdatper 상속을 제거한다.
앱의 이번 리팩토링에서는 엔드포인트에 대한 요청을 제한하지 않고, 대신 PlaneFinder 앱에 요청과 사용자 인가를 함께 전달해서 해당 인가를 각 리소스에 허용된 인가와 비교한 후 PlaneFinder 앱이 허용된 리소스에만 접근하도록 하기 위해서다.

다음으로 앱 전체에서 사용할 SecurityConfig 클래스 내에서 WebClient 빈을 생성한다.
PositionRetriever 내의 멤버 변수에 할당된 WebClient 생성에 OAuth2 설정을 간단히 통합할 수 있다.
또 이를 가능케 하는 유효한 인수가 있으므로 이 시점에서 이 작업은 별다른 문제 없이 수월하다.
그러나 PositionRetriever는 WebClient에 대한 접근이 필요하지만, OIDC와 OAuth2 설정을 처리하도록 WebClient를 설정하면 항공기 위치 조회라는 PositionRetriever의 주요 임무에서 벗어난다.

인증과 인가를 위한 WebClient 생성과 설정은 SecurityConfig라는 클래스의 범위에서 매우 적절하다.

```java
public class SecurityConfig{
	@Bean
	WebClient client(ClientRegistrationRepository regReop,
										OAuth2AuthorizedClientRepository cliRepo){
		ServletOAuth2AuthorizedClientExchangeFilterFuntion filter = 
					new ServletOAuth2AuthorizedClientExchangeFilterFuntion(regRepo, cliRepo);
		
		filter.setDefaultOAuthrizedClient(true);
		
		return WebClient.builder()
						.baseUrl("http://localhost:8080/")
						.apply(filter.oauth2Cofiguration())
						.build();
	}
}
```

다음의 두 빈이 client() 빈 생성 메서드로 빈 주입된다.

- 보통 application.yml 같은 속성 파일에 있는, 애플리케이션에서 사용하도록 지정된 OAuth2 클아이언트 목록 ClientRegistrationRepository
- 인증된 사용자를 나타내고 해당 사용자의 OAuth2AccessToken을 관리하는 OAuth2 클라이언트 목록 OAuth2AuthorizedClientRepository

**WebClient** 빈을 만들고 설정하는 메서드 내에서 다음 작업을 수행한다.

1. 주입된 두 리포지토리로 필터 기능을 초기화한다.
2. 기본 인증 클라이언트를 사용한다. 일반적인 경우로, 보통은 해당 리소스를 보유한 사용자가 인증을 획득한다.
하지만 액세스가 위임된 경우라면 해당 리소스 소유자가 아닌 인증된 사용자가 필요할 수 있따.
URL을 지정하고 OAuth2용으로 설정된 필터를 WebClient 빌더에 적용한 후, WebClient를 빌드해 스프링 빈으로 반환하고, 이를 ApplicationContext에 추가한다. 이제 OAuth2 지원 가능한 WebClient를 앱 전체에 사용할 수 있게 되었다.

이제 WebClient 빈이 빈 생성 메서드로 생성됐으므로, WebClient 객체를 생성하고 PositionRetriever 클래스 내의 멤버 변수에 직접 할당하는 문(statement)을 제거한 후, 간단한 멤버 변수 선언으로 대체한다.
클래스에 롬복의 `@AllArgsConstructor` 어노테이션을 사용하면, 롬복은 모든 필드값을 매개변수로 받는 생성자인 ‘모든 인수 생성자’에 WebClient 매개변수를 자동으로 추가한다. WebClient 빈은 ApplicationContext에서 사용 가능하기 때문에 스프링 부트는 PositionRetriever에 WebClient 빈을 주입하며, WebClient 멤버 변수에 자동으로 지정된다. 아래 코드는 새로 리팩토링된 PositionRetriever 클래스다.

```java
@AllArgsConstructor
@Component
public class PositionRetriever{
	private final AircraftRepository repository;
	private final WebClient client;

	Iteralbe<Aircraft> retrieveAirccraftPositions(){
		repository.deleteAll();

		client.get()
					.uri("/aircraft")
					.retreieve()
					.bodyToFlux(Aricraft.class)
					.filter(ac -> !ac.getReg().isEmpty())
					.toStream()
					.forEach(repository::save);

			return repository.findAll();
	}
}
```

이 절의 앞부분에서 app에서 사용하도록 지정된 OAuth2 클라이언트 목록 ClientRegistractionRepository의 사용을 언급한 적이 있따. 이 리포지토리를 채우는 방법은 여러 가지지만, 보통 항목은 app 속성으로 지정한다.
이 예제에서는 앱의 얌 파일에 정보를 추가하면된다.

컨트롤러에서 ‘관리자 전용’ 접근을 의미하는 매핑 추가.

```java
@AllArgsConstructor
@RestController
public class PositionController{
	private final PositionRetriever retriever;

	@GetMapping("/aircraft")
	public Iterable<Aircraft> getCurrentAircraftPositons(){
		return retriever.retrieveAircraftPositons("aircraft");
	}

	@GetMapping("/aircraftadmin")
	public Iterable<Aircraft> getCurrentAircraftPositonsAdminPrivs(){
		return retriever.retrieveAircraftPositons("aircraftadmin");
	}
}
```

PositionRetriever의 단일 메서드를 사용해 두 PlaneFinder 앱의 엔드포인트 접근을 허용하기 위해, 동적 경로 매개변수 String 엔드포인트를 수락하고 클라이언트 요청을 빌드할 때 사용하도록 해당 retrieveAircraftPositions() 메서드를 수정한다. 업데이트된 PositionRetriever 코드를 확인해보자.

```java
@AllArgsConstructor
@Component
public class PositionRetriever{
	private final AircraftRepository repository;
	private final WebClient client;

	Iteralbe<Aircraft> retrieveAirccraftPositions(){
		repository.deleteAll();

		client.get()
					.uri((null != endpoint) ? endpoint : "")
					.retreieve()
					.bodyToFlux(Aricraft.class)
					.filter(ac -> !ac.getReg().isEmpty())
					.toStream()
					.forEach(repository::save);

			return repository.findAll();
	}
}
```

이렇게 코드를 수정해줌으로써 앱은 완전하게 설정된 OIDC와 OAuth2 클라이언트 애플리케이션이다.
다음엔 승인된 사용자가 요청 시 리소스를 제공하는 OAuth2 리소스 서버 역할을 하도록 PlaneFinder 앱을 리팩토링 해보자.

---

### 10.4.2 PlaneFinder 리소스 서버

의존성 변경을 포함해 모든 리팩토링의 시작 지점은 빌드 파일이다.

**의존성추가**

새 클라이언트 app을 위한 새로운 스프링 부트 OAuth2 리소스 서버를 생성할 때는 스프링 이니셜 라이저를 통해 의존성을 추가하는 방법이 제일 간편하고 좋다.

OAuth2 Resource Server, Okta 추가. 

이후 적용을 위해 업뎃 → 인가 확인을 위해 OAuth2 리소스 서버와 Okta의 인프라를 사용할 계획 → 빌드 파일에 OAuth2 리소스 서버와 Okta를 위해 이니셜라이저에서 추가한 의존성 2개를 추가하면 된다.
(gradle 이냐 maven 이냐에 따라 상이함)
빌드를 새로고침하고 나면, 앱이 인바운드 요청과 함께 제공된 사용자 권한을 확인하고, 앱의 리소스에 접근 권한을 부여하거나 거부하도록 코드를 리팩토링 한다.

**리소스 인가를 위한 PlaneFinder 리팩토링**

분산 시스템에 Okta를 사용해 OIDC, OAuth2 인증과 인가를 활성화하는 작업의 대부분이 이 시점에서 이미 완료됐다. OAuth2 리소스 서버의 임무를 올바르게 수행하도록 PlaneFinder 앱을 리팩토링하기 위해 작은 노력.

1. JWT (JSON Web Token) 지원 포함
2. JWT (”조트”로 발음) 내에서 전달된 인가를 지정된 리소스 접근에 필요한 인가와 비교

두 작업은 스프링 시큐리티가 인바운드 요청의 JWT 내용을 조회, 확인하고 요구되는 인가와 비교할 단일 SecurityWEbFilterChain 빈을 생성해 수행한다.

빈 생성 메서드에 고유한 위치를 제공하기 위해 다시 한번 SecurityConfig 클래스를 만들고 `@Configuration` 어노테이션을 달아준다. 그러고 나서 다음과 같이 securityWebFilterChain() 메서드를 만든다.

<aside>
👉 ***여기서 나는 의문점이 생겼다.
 왜 굳이 고유한 위치를 제공해야만 하는 것일까?”***

스프링 부트 및 스프링 시큐리티를 사용하는 컨텍스트에서 `SecurityWebFilterChain` 빈을 생성할 때 고유한 위치를 제공하는 것은 중요한 목적을 갖고 있습니다. 
스프링 프레임워크와 스프링 시큐리티는 애플리케이션의 보안 구성을 관리하는 방식으로,
빈(bean)의 정의와 관리에 대해 매우 세밀한 제어를 가능하게 합니다.
여기에는 여러 가지 이유가 있지만, 가장 주요한 몇 가지를 알아두어야한다.

1. **명확한 구성의 분리**
스프링 시큐리티 설정을 담당하는 클래스에 `@Configuration` 어노테이션을 사용하면, 보안 관련 구성이 애플리케이션의 다른 부분(예: 데이터베이스 설정, MVC 설정 등)과 명확하게 분리됩니다. 이렇게 함으로써, 보안 구성을 쉽게 찾고, 관리하며, 필요에 따라 수정할 수 있습니다.
2. **스프링의 컨텍스트 관리**
스프링은 애플리케이션 컨텍스트 내에서 빈들을 관리하며, 각 빈에 대한 생명주기, 의존성 주입 등을 처리합니다. `SecurityWebFilterChain` 빈을 명시적으로 정의함으로써, 스프링 시큐리티의 필터 체인을 스프링의 관리 아래에 둘 수 있습니다. 이는 보안 구성의 일관된 관리와 함께, 스프링 생태계와의 원활한 통합을 의미합니다.
3. **커스터마이징과 확장성**
특정 애플리케이션의 보안 요구 사항은 다양할 수 있습니다. `SecurityWebFilterChain` 빈을 직접 정의함으로써 개발자는 기본 설정을 넘어서, 인증 메커니즘, 인가 정책, CORS 설정, CSRF 보호 등을 포함한 다양한 보안 관련 설정을 세밀하게 조정할 수 있습니다. 
이는 애플리케이션의 특정 요구 사항에 맞게 보안을 맞춤 설정할 수 있는 유연성을 제공합니다.
4. **명확한 의존성 주입**
`@Configuration` 클래스 내에서 빈을 정의함으로써, 스프링은 이러한 빈들 사이의 의존성을 자동으로 해결할 수 있습니다. 이는 보안 구성이 다른 애플리케이션 컴포넌트와 어떻게 상호작용해야 하는지, 그리고 필요한 의존성이 무엇인지 명확하게 만들어 줍니다.

이러한 이유들로 인해, `SecurityWebFilterChain` 빈을 생성하고 구성할 때 고유한 위치를 제공하는 것이 중요함. 이는 애플리케이션의 보안 구성을 명확하고, 관리 가능하며, 유연하게 만들어 줌.

</aside>

코드로 알아보자.

```java
// 1
@Configuration
public class SecurityConfig{
	@Bean
	public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http){
			http
						.authorizeExchage()
						.pathMatchers("/aircraft/**").hasAuthority("SCOPE_closedid")
						.pathMatchers("/aircraftadmin/**").hasAuthority("SCOPE_openid")
						.and().oauth2ResourceServeer().jwt();

			return http.build();
	}
}
```

필터 체인을 생성하기 위해 스프링 부트의 보안 자동 설정에서 제공하는 기존 ServerHttpSecurity 빈을 의존성 주입한다. 이 빈은 spring-boot-starter-webflux가 클래스 경로에 있을 때 웹플럭스 지원 app과 함께 사용됨.

<aside>
📌 클래스 경로에 웹플럭스가 없는 app은 이 장의 앞부분에 있는 폼 기반 인증 예제처럼 HttpSecurity 빈과 해당 메서드를 대신 사용한다.

</aside>

여기서 어떻게 " HttpSecurity 빈과 해당 메서드를 대신 사용한다"는 것인지 ???

스프링 시큐리티는 서블릿 기반의 애플리케이션과 리액티브 애플리케이션 모두를 위한 보안 구성을 제공합니다. 이는 주로 `HttpSecurity`와 `ServerHttpSecurity`를 통해 이루어지는데, 각각 서블릿 기반 애플리케이션과 웹플럭스(리액티브) 애플리케이션에 대응됩니다. 
이 전저드는 웹플럭스 애플리케이션에 대한 `SecurityWebFilterChain` 구성의 예입니다. 

반면, `HttpSecurity`는 서블릿 기반의 애플리케이션에서 사용됩니다.

서블릿 기반 애플리케이션에서는 `SecurityWebFilterChain` 대신 `HttpSecurity`를 사용하여 보안 구성을 정의합니다. `HttpSecurity`를 사용하면 인증, 인가, CORS, CSRF 등과 관련된 보안 설정을 구성할 수 있습니다. 이는 `SecurityConfig` 클래스 안에서 `@Bean` 어노테이션을 사용하여 `WebSecurityConfigurerAdapter`를 구현함으로써 이루어집니다.

아래는 `HttpSecurity`를 사용한 서블릿 기반 애플리케이션의 간단한 보안 구성 예제.

```java
// 2
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/aircraft/**").hasAuthority("SCOPE_closedid")
                .antMatchers("/aircraftadmin/**").hasAuthority("SCOPE_openid")
                .anyRequest().authenticated()
                .and()
            .oauth2ResourceServer()
                .jwt();
    }
}
```

이 예제에서는 `HttpSecurity` 객체를 사용하여 경로별 인가 규칙을 정의하고 있습니다. 
예를 들어, `/aircraft/**` 경로는 `"SCOPE_closedid"` 권한을 가진 사용자만 접근할 수 있고, `/aircraftadmin/**` 경로는 `"SCOPE_openid"` 권한을 가진 사용자만 접근할 수 있습니다.
그리고 OAuth2 리소스 서버로 JWT를 사용하도록 설정하고 있습니다.

요약하자면, 웹플럭스(리액티브) 애플리케이션에서는 `ServerHttpSecurity`를 사용하여 `SecurityWebFilterChain`을 구성하고, 서블릿 기반 애플리케이션에서는 `HttpSecurity`를 사용하여 보안 구성을 정의합니다. 선택은 주로 애플리케이션의 타입(리액티브 또는 서블릿 기반)에 따라 결정됩니다.

이렇게 차이점이 존재합니다. 근데 저는 이 코드와 이전 코드의 명확한 차이점을 알지 못했습니다.
어떤점에서 차이가 있는 것일까?

1. **애플리케이션 타입**
    - 1번 코드: 웹플럭스(리액티브) 애플리케이션을 위한 `SecurityWebFilterChain` 사용. 
    이는 스프링 웹플럭스 환경에서 리액티브 애플리케이션의 보안을 구성할 때 사용.
    - 2번 코드: 서블릿 기반 애플리케이션을 위한 `HttpSecurity` 사용. 
    이는 전통적인 스프링 MVC(서블릿 API를 사용하는) 환경에서 애플리케이션의 보안을 구성할 때 사용.
2. **클래스 상속 및 어노테이션**
    - 1번 코드 : `@Configuration` 어노테이션만 사용하고, `ServerHttpSecurity` 객체를 파라미터로 받는 `securityWebFilterChain` 메서드를 통해 리액티브 보안 구성을 정의하며, `WebSecurityConfigurerAdapter`를 상속받지 않습니다.
    - 2번 코드: 서블릿 기반 애플리케이션에서는 `@EnableWebSecurity`와 `@Configuration` 어노테이션을 함께 사용하고, `WebSecurityConfigurerAdapter`를 상속받아 `configure(HttpSecurity http)` 메서드를 오버라이드함으로써 보안 구성을 정의.
3. **메서드 호출 및 구성 방식**
    - 1번 코드: `authorizeExchange()`, `pathMatchers()`, `hasAuthority()`, `oauth2ResourceServer().jwt()` 등의 메서드를 연쇄 호출하여 리액티브 보안 규칙을 구성함.
    - 2번 코드: `authorizeRequests()`, `antMatchers()`, `hasAuthority()`, `oauth2ResourceServer().jwt()` 등의 메서드를 사용하여 서블릿 기반 애플리케이션의 보안 규칙을 구성함. 메서드 호출 패턴이 유사하지만, `***authorizeRequests()`와 `antMatchers()`를 사용하는 점이 차이*** 가 있습니다.
4. 적용되는 기술 스택
    - 1번 코드: 스프링 웹플럭스와 호환되는 리액티브 스택을 사용합니다.
    - 2번 코드: 스프링 MVC와 호환되는 서블릿 스택을 사용합니다.

요약하자면, 주요 차이점은 애플리케이션의 타입(리액티브 vs. 서블릿 기반), 구성 방식, 사용하는 스프링 시큐리티 클래스와 메서드에 있습니다. 1번 코드는 리액티브 애플리케이션에, 2번 코드는 서블릿 기반 애플리케이션에 적합하다.

---

다음, 요청을 어떻게 처리할지 방법을 지정해 ServerHttpSecurity 빈의 보안 기준을 설정한다.
먼저 요청과 요구되는 사용자 인가를 비교하기 위해 두 가지 리소스 경로를 제공한다.
그리고 사용자 정보를 포함하기 위해 JWT를 사용해 OAuth2 리소스 서버 지원을 활성화한다.

→ 여기서 “활성화해서 사용자 정보를 포함할때 JWT를 사용하면 무슨 장점이 있는 것일까?”

JWT(JSON Web Tokens)를 사용하여 OAuth2 리소스 서버를 활성화하는 것은 웹 서비스의 인증 및 인가 과정에서 여러 가지 장점을 제공한다.

**자가 포함(Self-contained)**

- JWT는 사용자의 인증 정보와 권한을 토큰 안에 직접 포함합니다. 이는 별도의 데이터베이스 조회 없이도 사용자의 인증 상태와 권한을 확인할 수 있게 해줍니다. 결과적으로, 인증 과정이 더 빠르고 효율적이 됩니다.

**확장성(Scalability)**

- JWT는 서버 상태를 저장하지 않는 무상태 인증 방식을 사용합니다. 이로 인해 애플리케이션의 확장성이 향상되며, 여러 서버 간의 요청 처리가 용이해집니다. 사용자 세션을 관리하는 서버의 부담도 줄어듭니다.

**보안성(Security)**

- JWT는 디지털 서명을 사용해 정보의 위변조를 방지합니다. HTTPS와 함께 사용할 경우, 데이터의 안전한 전송이 보장되며, 필요한 경우 토큰 내용을 암호화할 수도 있습니다.

**표준 기반(Standardization)**

- JWT는 널리 인정받는 표준으로, 다양한 언어와 플랫폼에서 지원됩니다. 이는 다른 시스템이나 서비스와의 통합을 용이하게 합니다.

**유연성(Flexibility)**

- JWT는 사용자 정의 클레임을 통해 다양한 인증 및 인가 시나리오를 구현할 수 있습니다. 이는 애플리케이션에 필요한 어떤 정보든 토큰에 포함시킬 수 있음을 의미합니다.

**효율성(Efficiency)**

- 한 번의 인증으로 여러 다른 서비스에 대한 접근 권한을 제공할 수 있습니다. 이는 Single Sign-On(SSO) 같은 기능을 구현하는 데 유용합니다.

이런 장점들로 인해, JWT는 다양한 웹 및 모바일 애플리케이션에서 인증 및 인가 관리를 위해 널리 사용된다.

---

여기서 또 궁금점이 생겼다.

OAuth2 리소스 서버 지원을 활성화 한다는데 이건 어떻게 활성화 하는 것이고,
JWT 말고는 사용자 정보를 포함하지 못하는 것인가?

**OAuth2 리소스 서버 활성화**

OAuth2 리소스 서버를 활성화하는 과정은 프레임워크와 언어에 따라 다를 수 있지만, 
일반적으로 다음과 같은 단계를 포함한다.

1. **의존성 추가**
OAuth2 리소스 서버 기능을 사용하기 위해 필요한 라이브러리나 모듈을 프로젝트에 추가한다.
예를 들어, Spring Security 5 이상에서는 `spring-boot-starter-oauth2-resource-server` 의존성을 추가하여 시작할 수 있다.
2. **구성 설정**
`application.properties` 또는 `application.yml` 파일 같은 구성 설정 파일에서 OAuth2 리소스 서버와 관련된 속성을 설정한다.
***이 설정에는 토큰 발급자(issuer), 토큰 검증을 위한 JWK(공개 키 세트)의 URL 등이 포함될 수 있다.***
3. **Security Configuration**
보안 구성 클래스에서 OAuth2 리소스 서버를 활성화하고 JWT 또는 다른 토큰 형식을 사용하도록 설정한다. Spring Security에서는 `SecurityWebFilterChain` 또는 `WebSecurityConfigurerAdapter`를 사용하여 이를 구현할 수 있습니다.

**사용자 정보 포함 방법**

JWT 외에도 사용자 정보를 포함할 수 있는 여러 방법이 있다. 
다만, JWT가 가장 널리 사용되며 많은 장점을 가지고 있기 때문에 인증 및 인가 과정에서 권장 및 선호한다.

다른 방법으로는

- **Opaque Tokens**: 이 토큰 유형은 클라이언트에게 내용이 불투명합니다. 즉, 사용자 정보나 다른 데이터를 직접 포함하지 않습니다. 대신, 리소스 서버는 토큰을 발급한 인증 서버에 직접 요청하여 토큰의 유효성을 검증하고 사용자 정보를 조회합니다.
- **SAML Assertions**: SAML(Security Assertion Markup Language)은 주로 엔터프라이즈 환경에서 싱글 사인온(SSO)을 구현할 때 사용됩니다. SAML 어설션은 사용자에 대한 인증 및 권한 정보를 포함할 수 있으며, XML 형식으로 되어 있습니다.
- **Custom Tokens**: 어떤 경우에는 시스템 특정 요구 사항에 맞추어 사용자 정의 토큰을 생성하고 사용할 수 있습니다. 이 토큰들은 시스템 내부에서 약속된 구조와 데이터를 가지며, 사용자 정보를 포함할 수 있습니다. 하지만 이 방법은 표준화되지 않았으며, 보안과 호환성에 특별한 주의가 필요합니다.

요약하자면, OAuth2 리소스 서버를 활성화하는 과정은 특정 의존성 추가, 구성 설정, 보안 구성을 통해 이루어집니다. ***JWT는 사용자 정보를 포함하는 효율적인 방법***이지만, 다른 방법들도 상황에 따라 적절히 선택하여 사용할 수 있습니다. (그래도 아직까진 “JWT 쓰는게 제일 좋으먀, 다른 방법도 있다”는 느낌으로 기억하면 된다.)

---

<aside>
📌 JWT는 리소스 액세스 권한을 사용자에게 전달하기 떄문에 ‘전달자 토큰’ 이라고도 한다.

</aside>

---

마지막으로, `ServerHttpSecurity` 빈에서 `SecurityWebFilterChain`을 빌드하고 반환해서 `PlaneFinder` 앱 전체에서 빈으로 사용할 수 있게 한다.

요청이 도착하면 필터 체인은 일치하는 항목을 찾을 때까지 요청된 리소스 경로를  체인에 지정된 경로와 비교한다.
일치하면, 애플리케이션은 OAuth2 제공자(이 경우엔 Okta)를 통해 토큰 유효성을 확인한 다음, 매핑된 리소스 접근에 필요한 인가와 요청에 포함된 인가를 비교한다. 
유효한 일치 항목이 있으면, 접근 인가를 부여한다. 그렇지 않은 경우, 애플리케이션은 ‘403’ 상태코드를 반환함.

두 번쨰 pathMatcher가 PlaneFinder 앱에 아직 존재하지 않는 리소스 경로를 지정한다는 사실을 알아차렸을 것이다.

- 어떻게 알아차린거지?
    1. **애플리케이션 라우팅 및 구성 분석**
    애플리케이션의 라우팅 구성을 분석하여 현재 구성된 경로와 비교합니다. 애플리케이션 코드 내에서 정의된 경로와 `SecurityWebFilterChain` 내에서 지정된 경로를 비교함으로써, 누락된 또는 아직 생성되지 않은 경로를 식별할 수 있습니다.
    2. **개발 문서 및 API 스펙 참조**
    프로젝트의 개발 문서나 API 스펙을 참조하여 현재 구현된 기능과 향후 계획된 기능 간의 차이를 확인합니다. 이러한 문서는 종종 예정된 또는 개발 중인 기능에 대한 경로를 포함하고 있으며, 이는 보안 구성에서 누락될 수 있습니다.
    3. **팀 내 커뮤니케이션 및 협업**
    개발 팀 내에서의 지속적인 커뮤니케이션과 협업을 통해, 개발 중이거나 계획된 기능에 대한 정보를 공유할 수 있습니다. 이는 보안 설정이 현재와 미래의 애플리케이션 요구사항을 모두 충족할 수 있도록 하는 데 중요합니다.
    4. 보안 리뷰 및 감사
    정기적인 보안 리뷰와 감사를 통해, 보안 설정과 애플리케이션의 현재 상태 간의 일치 여부를 확인할 수 있습니다. 이 과정에서 아직 존재하지 않는 경로를 포함한 보안 설정의 누락 또는 오류를 발견할 수 있습니다.

인가 검사의 성공과 실패를 보여주는 두 예제를 모두 제공하기 위해 이 경로를 PlaneController 클래스에 추가한다.

OAuth2 제공자는 openid, email, profile 등이 담긴 여러 기본 인가를 포함한다.
예제 필터 체인에서 (공급자와 OAuth2 인가 설정에 대해) closeid의 존재하지 않는 인가를 확인한다.
결과적으로 경로가 `/aircraft`로 시작하는 리소스 요청은 모두 실패한다.
현재 작성된 대로 유효한 토큰을 가지며 `/aircraftadmin` 경로로 시작하는 리소스의 인바운드 요청은 모두 성공한다.

<aside>
⚠️ ***스프링 시큐리티는 OAuth2 제공자 인가 앞에  ‘`SCOPE_`’를 추가해 스프링 시큐리티의 내부 개념 범위와 OAuth2 인가를 일대일로 매핑한다***. 
스프링 시큐리티를 OAuth2와 함께 사용하는 개발자라면, 실질적인 차이가 없더라도 이 점을 알고는 있어야한다.

</aside>

---

코드 리팩토링을 완료하기 위해, 이제 이전 경로 일치자(pathMatcher)에서 참조된 `/aircraftadmin` 엔드포인트 매핑을 PlaneFinder 앱의 PlaneController 클래스에 추가하고, 기존 `/aircraft` 엔드포인트의 기능을 `/aircraftadmin` 엔드포인트에 단순히 복사해서 접근 기준이 다른 두 엔드포인트를 보여준다.

```java
package com.thehecklers.planefinder;

import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import reactor.core.publisher.Flux;

import java.io.IOException;
import java.time.Duration;

@Controller
public class PlaneController {
    private final PlaneFinderService pfService;

    public PlaneController(PlaneFinderService pfService) {
        this.pfService = pfService;
    }

    @ResponseBody
    @GetMapping("/aircraft")
    public Flux<Aircraft> getCurrentAircraft() throws IOException {
        return pfService.getAircraft();
    }

    @ResponseBody
    @GetMapping("/aircraftadmin")
    public Flux<Aircraft> getCurrentAircraftByAdmin() throws IOException {
        return pfService.getAircraft();
    }

    @MessageMapping("acstream")
    public Flux<Aircraft> getCurrentACStream() throws IOException {
        return pfService.getAircraft().concatWith(
                Flux.interval(Duration.ofSeconds(1))
                        .flatMap(l -> pfService.getAircraft()));
    }
}
```

마지막으로, app이 들어오는 JWT의 유효성 검사를 목적으로 OAuth2 제공자에 접근하려면 어디로 가야할 지 알려야 한다. OAuth2 제공자 엔드포인트 사양에 약간의 선택 범위가 있기 떄문에 수행 방법상 여러 변형이 있기 때문이다. Okta는 그 밖의 필요한 URI를 획득하는 설정에서 중앙 URI 역할을 하는 발급자 URI를 유용하게 구현한다. 이로써 애플리케이션 개발자가 단일 속성을 추가해야 하는 부담이 줄어든다.

yml 파일

```yaml
spring:
	security:
		oauth2:
			resourceserver:
				jwt:
					issuer-uri: https:// <okta에서 발급받은 subdoamin 삽입>.oktapreview.com/oauth2/default
	
	rsocket:
		server:
			port: 8080
	
	server:
		port: 7634
```
