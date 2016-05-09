package com.asanzdiego.pojos;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class User implements UserDetails {

	private static final long serialVersionUID = 1L;

	private static final String ROLE_USER = "user";

	// Field uid in ldap
	private String username;
	
	// Field userPassword
	private String password;
	
	// Field cn in ldap
	private String name;
	
	// Field sn in ldap
	private String surname;
	
	private Collection<GrantedAuthority> grantedAuth;

	public Collection<? extends GrantedAuthority> getAuthorities() {
		return grantedAuth;
	}

	public boolean isAccountNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	public boolean isAccountNonLocked() {
		// TODO Auto-generated method stub
		return true;
	}

	public boolean isCredentialsNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	public boolean isEnabled() {
		// TODO Auto-generated method stub
		return true;
	}

	public void setRoleUser() {
		if (this.grantedAuth == null) {
			this.grantedAuth = new ArrayList<GrantedAuthority>();
		}
		GrantedAuthority teacherAuth = new GrantedAuthority() {
			private static final long serialVersionUID = 4356967414267942910L;

			public String getAuthority() {
				return "user";
			}

		};
		this.grantedAuth.add(teacherAuth);
	}

	public boolean isRoleUser() {
		if (this.grantedAuth != null) {
			for (GrantedAuthority grantedAuthority : grantedAuth) {
				if (grantedAuthority.getAuthority().equals(this.ROLE_USER))
					return true;
			}
		}
		return false;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getSurname() {
		return surname;
	}

	public void setSurname(String surname) {
		this.surname = surname;
	}

	@Override
	public String toString() {
		return "User [name=" + name + ", surname=" + surname + ", grantedAuth=" + grantedAuth + "]";
	}

	@Override
	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	@Override
	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}


}
