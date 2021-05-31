package com.auth.authServer;

import com.auth.interop.User;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthServerApplication {

	public static void main(String[] args) {
		User user = new User();
		SpringApplication.run(AuthServerApplication.class, args);
	}

}
