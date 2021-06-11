package com.auth.authServer;

import com.auth.authServer.model.implementations.AuthDatabaseImplementationRAM;
import com.auth.interop.utils.CipherUtils;
import com.auth.interop.contents.AddUserField;
import com.auth.interop.contents.GenerateAdminKeys;
import com.auth.interop.contents.SetPanicPublicKey;
import com.google.gson.Gson;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.Cipher;
import java.security.KeyPair;

@SpringBootApplication
public class AuthServerApplication {
	private static final boolean TEST_DATABASE = true;

	// Order
	public static void main(String[] args) {
		if (TEST_DATABASE) {
			try {
				testDatabase();
			} catch (Exception e) {
				e.printStackTrace();
			}
		} else {
			SpringApplication.run(AuthServerApplication.class, args);
		}
	}

	private static void testDatabase() throws Exception {

		{
			KeyPair pair = CipherUtils.generateKeyPair(CipherUtils.Algorithm.RSA);
			Gson gson = new Gson();

			//Cipher encrypter = CipherUtils.getEncrypter(CipherUtils.Algorithm.RSA, pair.getPublic());
			//Cipher decrypter = CipherUtils.getDecrypter(CipherUtils.Algorithm.RSA, pair.getPrivate());
			Cipher encrypter = CipherUtils.getEncrypter(CipherUtils.Algorithm.RSA, pair.getPrivate());
			Cipher decrypter = CipherUtils.getDecrypter(CipherUtils.Algorithm.RSA, pair.getPublic());

			AddUserField f = new AddUserField();
			f.setContent(new AddUserField.Content("Hola"), encrypter, gson);
			AddUserField.Content c = f.getContent(decrypter, gson);
			c = null;
		}


		AuthDatabaseImplementationRAM db = new AuthDatabaseImplementationRAM();
		String panicPrivateKey;
		byte[] adminPrivateKey;
		// 1 - set_panic_pk
		{
			SetPanicPublicKey value = new SetPanicPublicKey();
			KeyPair pair = CipherUtils.generateKeyPair(CipherUtils.Algorithm.RSA);
			value.content = CipherUtils.getPublicKeyInBase64(pair);
			panicPrivateKey = CipherUtils.getPrivateKeyInBase64(pair);
			db.setPanicPublicKeys(value);
		}
		// 2 - gen_admin_pk
		{
			GenerateAdminKeys value = new GenerateAdminKeys();
			value.content = null;
			adminPrivateKey = db.generateAdminKeys(value);
		}
		// 3 - add_user_key
		{
			//AddUserField value = new AddUserField();
			//value.
			//db.addUserField(value);
		}
		// ** Register application
		// 4 - prepare_captcha
		// 5 - register
		// 6 - verify
		// 7 - update_user
		// ** Register user
		// 8 - prepare_captcha
		// 9 - register
		// 10 - verify
		// 11 - update_user
		// 12 - generate_token

	}

}
