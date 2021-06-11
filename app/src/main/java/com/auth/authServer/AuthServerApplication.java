package com.auth.authServer;

import com.auth.authServer.model.Application;
import com.auth.authServer.model.implementations.AuthDatabaseImplementationRAM;
import com.auth.interop.*;
import com.auth.interop.contents.*;
import com.auth.interop.utils.CipherUtils;
import com.google.gson.Gson;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.UUID;

@SpringBootApplication
public class AuthServerApplication {
	private static final boolean TEST_DATABASE = false;

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

		if (false) {
			KeyPair pair = CipherUtils.generateKeyPair(CipherUtils.Algorithm.RSA);
			Gson gson = new Gson();

			//Cipher encrypter = CipherUtils.getEncrypter(CipherUtils.Algorithm.RSA, pair.getPublic());
			//Cipher decrypter = CipherUtils.getDecrypter(CipherUtils.Algorithm.RSA, pair.getPrivate());
			Cipher encrypter = CipherUtils.getEncrypter(CipherUtils.Algorithm.RSA, pair.getPrivate());
			Cipher decrypter = CipherUtils.getDecrypter(CipherUtils.Algorithm.RSA, pair.getPublic());

			EncryptedContent<AddUserField> f = new EncryptedContent<AddUserField>();
			f.setContent(new AddUserField("Hola"), encrypter, gson);
			AddUserField c = f.getContent(decrypter, gson);
			c = null;
		}


		AuthDatabaseImplementationRAM db = new AuthDatabaseImplementationRAM();

		{
			String panicPrivateKey;
			String adminPrivateKey;
			Cipher adminCipher;
			// 1 - set_panic_pk
			{
				KeyPair pair = CipherUtils.generateKeyPair(CipherUtils.Algorithm.RSA);
				panicPrivateKey = CipherUtils.getPrivateKeyInBase64(pair);

				EncryptedContent<SetPanicPublicKey> content = new EncryptedContent<>();
				content.setContent(new SetPanicPublicKey("Hola"), Application.getGson());
				db.setPanicPublicKeys(content);
			}
			// 2 - gen_admin_pk
			{
				KeyPair pair;
				{
					EncryptedContent<GenerateKeyPair> content = new EncryptedContent<>();
					content.setContent(new GenerateKeyPair(new Date(System.currentTimeMillis())), Application.getGson());
					pair = db.generateKeyPair(content);
				}
				{
					EncryptedContent<SetAdminPrivateKey> content = new EncryptedContent<>();
					content.setContent(new SetAdminPrivateKey(CipherUtils.getPublicKeyInBase64(pair)), Application.getGson());
					db.setAdminPublicKey(content);
					adminPrivateKey = CipherUtils.getPrivateKeyInBase64(pair);
					adminCipher = CipherUtils.getEncrypter(CipherUtils.Algorithm.RSA, pair.getPrivate());
				}
			}
			// 3 - add_user_key
			{
				EncryptedContent<AddUserField> content = new EncryptedContent<>();
				content.setContent(new AddUserField("name"), adminCipher, Application.getGson());
				db.addUserField(content);
			}
		}

		String applicationCode;
		String appPrivateKey;
		{
			SimpleDateFormat formatter= new SimpleDateFormat("yyyy-MM-dd 'at' HH:mm:ss z");
			UUID appId;

			// ** Register application
			// 4 - prepare_captcha
			{
				Captcha captcha = Captcha.newInstance(Application.DEBUG_MODE, "1", "11");
				db.registerHumanVerificationInquiry(captcha);
			}
			// 5 - register
			{
				Validator validator = new Validator();
				validator.phone = "phone";
				validator.password = "phone_pass";
				validator.inquiry = new Inquiry("1", "11");
				validator.debugForceInternalInquiry = new Inquiry("2", "22");
				db.sendValidationInquiry(validator);
			}
			// 6 - verify
			{
				Validator validator = new Validator();
				validator.inquiry = new Inquiry("2", "22");
				appId = db.verifyUser(validator);
			}
			// 7 - update_user
			{
				KeyPair pair;
				{
					EncryptedContent<GenerateKeyPair> content = new EncryptedContent<>();
					content.setContent(new GenerateKeyPair(new Date(System.currentTimeMillis())), Application.getGson());
					pair = db.generateKeyPair(content);
				}
				{
					Validator validator = new Validator();
					validator.phone = "phone";
					validator.password = "phone_pass";
					User user = db.getUser(validator);

					user.setName("MainApplication");
					user.type = User.Type.APPLICATION;
					user.appFields = new HashSet<>();
					user.appFields.add(User.NAME_FIELD);
					user.publicKey = CipherUtils.getPublicKeyInBase64(pair);
					appPrivateKey = CipherUtils.getPrivateKeyInBase64(pair);
					db.updateUser(user, validator);
					user = db.getUser(validator);
					applicationCode = user.appCode;
				}
			}
		}

		Token user_token;
		{
			// ** Register user
			UUID userId;
			// 8 - prepare_captcha
			{
				Captcha captcha = Captcha.newInstance(Application.DEBUG_MODE, "3", "33");
				db.registerHumanVerificationInquiry(captcha);
			}
			// 9 - register
			{
				Validator validator = new Validator();
				validator.phone = "user";
				validator.password = "user_pass";
				validator.inquiry = new Inquiry("3", "33");
				validator.debugForceInternalInquiry = new Inquiry("4", "44");
				db.sendValidationInquiry(validator);
			}
			// 10 - verify
			{
				Validator validator = new Validator();
				validator.inquiry = new Inquiry("4", "44");
				userId = db.verifyUser(validator);
			}
			// 11 - update_user
			{
				Validator validator = new Validator();
				validator.phone = "phone";
				validator.password = "phone_pass";
				User user = db.getUser(validator);

				user.setName("User Name");
				db.updateUser(user, validator);
			}
			// 12 - generate_token
			{
				Validator validator = new Validator();
				validator.phone = "phone";
				validator.password = "phone_pass";
				validator.applicationCode = applicationCode;
				user_token = db.generateTokenForUser(validator);
			}
		}

		{
			String pk_name = user_token.serverPublicKeyName;
			NamedPublicKey pk = db.getServerPublicKey(pk_name);

			Cipher decrypter1 = CipherUtils.generateDecrypterFromBase64PublicKey(pk.name, CipherUtils.Algorithm.RSA);
			Cipher decrypter2 = CipherUtils.generateDecrypterFromBase64PrivateKey(appPrivateKey, CipherUtils.Algorithm.RSA);
			Token.UserData user = user_token.userData.getContent(decrypter2, decrypter1, Application.getGson());
			user = null;
		}

	}

}
