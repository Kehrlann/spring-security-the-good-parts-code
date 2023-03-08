package wf.garnier.spring.security.thegoodparts;

import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
class SecurityConfig {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http
				.authorizeHttpRequests(
						authorizeConfig -> {
							authorizeConfig.requestMatchers("/").permitAll();
							authorizeConfig.requestMatchers("/error").permitAll();
							authorizeConfig.requestMatchers("/favicon.svg").permitAll();
							authorizeConfig.requestMatchers("/css/**").permitAll();
							authorizeConfig.anyRequest().authenticated();
						}
				)
				.formLogin(withDefaults())
				.oauth2Login(withDefaults())
				.httpBasic(withDefaults())
				.addFilterBefore(new VerbotenHeaderFilter(), AuthorizationFilter.class)
				.addFilterBefore(new RobotAccountFilter(), AuthorizationFilter.class)
				.authenticationProvider(new DanielAuthenticationProvider())
				.build();
	}

	@Bean
	UserDetailsService userDetailsService() {
		return new InMemoryUserDetailsManager(
				User.withUsername("user")
						.password("{noop}password")
						.authorities(AuthorityUtils.NO_AUTHORITIES)
						.build()
		);
	}

	@Bean
	public ApplicationListener<AuthenticationSuccessEvent> successListener() {
		return event -> {
			System.out.println("🎉 SUCCESS [%s] %s".formatted(
					event.getAuthentication().getClass().getSimpleName(),
					event.getAuthentication().getName()
			));
		};
	}
}
