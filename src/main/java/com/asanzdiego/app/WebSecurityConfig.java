package com.asanzdiego.app;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.configurers.ldap.LdapAuthenticationProviderConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;

import com.asanzdiego.security.LdapUserDetailsContextMapper;

import org.springframework.session.web.http.HeaderHttpSessionStrategy;
import org.springframework.web.cors.CorsUtils;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
	
		http
			.csrf().disable() // Disable CSRF protection, not necessary with 
			.httpBasic().and().authorizeRequests()
				.requestMatchers(CorsUtils::isCorsRequest)
				.permitAll().anyRequest().authenticated();

	}


	@Bean
	HeaderHttpSessionStrategy sessionStrategy() {
		return new HeaderHttpSessionStrategy();
	}
	
	@Configuration
	protected static class AuthenticationConfiguration extends GlobalAuthenticationConfigurerAdapter {
		
		private String ldapURI = "ldap://192.168.1.2:389/dc=company,dc=com";

		private String ldapUser = "uid=admin,ou=adminstrators,dc=company,dc=com";

		private String ldapPassword = "password";

		@Override
		public void init(AuthenticationManagerBuilder auth) throws Exception {

			DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(ldapURI);
			contextSource.setUserDn(ldapUser);
			contextSource.setPassword(ldapPassword);
			contextSource.afterPropertiesSet();

			LdapAuthenticationProviderConfigurer<AuthenticationManagerBuilder> ldapAuthenticationProviderConfigurer = auth
					.ldapAuthentication().userDetailsContextMapper(new LdapUserDetailsContextMapper());

			ldapAuthenticationProviderConfigurer.userSearchFilter("(&(uid={0}))")
					.userSearchBase("").contextSource(contextSource);

		}
	}
}
