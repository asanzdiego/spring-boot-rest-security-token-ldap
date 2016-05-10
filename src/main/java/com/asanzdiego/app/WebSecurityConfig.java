package com.asanzdiego.app;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.configurers.ldap.LdapAuthenticationProviderConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;

import com.asanzdiego.security.LdapUserDetailsContextMapper;

import org.springframework.session.web.http.HeaderHttpSessionStrategy;
import org.springframework.web.cors.CorsUtils;

@Configuration
//@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
	
		/*http
			  	.csrf().disable() // Disable CSRF protection, not necessary with x-auth-token
			  	.httpBasic()
			.and()
				.authorizeRequests()
				.requestMatchers(CorsUtils::isCorsRequest).permitAll()
				.anyRequest().authenticated();*/
		http
	        .authorizeRequests()
	        .requestMatchers(CorsUtils::isCorsRequest).permitAll()
	        .anyRequest().authenticated()
	        .and().httpBasic()
	        .and().addFilterBefore(new WebSecurityCorsFilter(), ChannelProcessingFilter.class);

	}


	@Bean
	HeaderHttpSessionStrategy sessionStrategy() {
		return new HeaderHttpSessionStrategy();
	}
	
	@Configuration
	protected static class AuthenticationConfiguration extends GlobalAuthenticationConfigurerAdapter {
		
		@Value("${ldap.uri}")
		private String ldapURI;

		@Value("${ldap.user}")
		private String ldapUser;

		@Value("${ldap.password}")
		private String ldapPassword;

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
	
	protected class WebSecurityCorsFilter implements Filter {
	    @Override
	    public void init(FilterConfig filterConfig) throws ServletException {
	    }
	    @Override
	    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
	        HttpServletResponse res = (HttpServletResponse) response;
	        res.setHeader("Access-Control-Allow-Origin", "*");
	        res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE, PUT");
	        res.setHeader("Access-Control-Max-Age", "3600");
	        res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, x-requested-with, Cache-Control");
	        chain.doFilter(request, res);
	    }
	    @Override
	    public void destroy() {
	    }
	}
}
