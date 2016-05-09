package com.asanzdiego.security;

import java.util.Collection;

import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;

import com.asanzdiego.pojos.User;

public class LdapUserDetailsContextMapper implements UserDetailsContextMapper {

	// http://docs.spring.io/spring-security/site/docs/3.1.x/reference/springsecurity-single.html#ldap-custom-user-details

	public UserDetails mapUserFromContext(DirContextOperations ctx, String username,
			Collection<? extends GrantedAuthority> authorities) {
		
		System.out.println("-->");
		User user = new User();
		user.setUsername(ctx.getStringAttribute("uid"));
		user.setName(ctx.getStringAttribute("cn"));
		user.setSurname(ctx.getStringAttribute("sn"));
		user.setRoleUser();
		
		return user;
	}

	@Override
	public void mapUserToContext(UserDetails arg0, DirContextAdapter arg1) {
		// TODO Auto-generated method stub
	}

}
