package com.asanzdiego.rest;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin(origins = "*", maxAge = 3600, allowedHeaders = { "x-auth-token", "x-requested-with" })
public class UserREST {

	@RequestMapping(value = "/user", method = RequestMethod.GET)
	public ResponseEntity<Authentication> user( Authentication auth ) {
		return new ResponseEntity<Authentication>(auth, HttpStatus.OK);
	}
}
