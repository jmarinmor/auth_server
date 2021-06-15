package com.auth.authServer;

import com.auth.authServer.model.Application;
import com.auth.authServer.model.AuthDatabase;
import com.auth.authServer.model.KeyDatabase;
import com.auth.authServer.model.implementations.AuthDatabaseImplementationRAM;
import com.auth.authServer.model.implementations.KeyDatabaseImplementationRAM;
import com.auth.interop.*;
import com.auth.interop.contents.*;
import com.google.gson.Gson;
import com.jcore.utils.CipherUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.UUID;

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

		if (true) {
			final String ALGORITHM_RSA = "RSA";
			final String ALGORITHM_RSA_CIPHER = "RSA";
			final int ALGORITHM_RSA_KEYSIZE = 2048;
			//final String SECURITY_PROVIDER = "BC";

//			for (Provider provider: Security.getProviders()) {
//				System.out.println(provider.getName());
//				for (String key: provider.stringPropertyNames())
//					System.out.println("\t" + key + "\t" + provider.getProperty(key));
//			}

			KeyPairGenerator keyPairGeneratorClient;
			keyPairGeneratorClient = KeyPairGenerator.getInstance(ALGORITHM_RSA);
			keyPairGeneratorClient.initialize(ALGORITHM_RSA_KEYSIZE);

			KeyPair pair = keyPairGeneratorClient.generateKeyPair();

			byte[] plain = "hello00000000000hello00000000000hello00000000000hello00000000000hello00000000000hello00000000000hello00000000000hello00000000000hello00000000000hello00000000000hello00000000000hello00000000000hello00000000000hello00000000000hello00000000000hello00000000000".getBytes(StandardCharsets.UTF_8);

			Cipher encrypter = Cipher.getInstance(ALGORITHM_RSA_CIPHER);
			encrypter.init(Cipher.ENCRYPT_MODE, pair.getPrivate());
			int n = encrypter.getBlockSize();
			n= encrypter.getOutputSize(25);
			byte[] encrypted = encrypter.doFinal(plain);

			Cipher decrypter = Cipher.getInstance(ALGORITHM_RSA_CIPHER);
			decrypter.init(Cipher.DECRYPT_MODE, pair.getPublic());
			byte[] decrypted = decrypter.doFinal(encrypted);

			String s = new String(decrypted, StandardCharsets.US_ASCII);

			s = null;
		}

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


		AuthDatabase adb = new AuthDatabaseImplementationRAM();
		KeyDatabase kdb = new KeyDatabaseImplementationRAM();
		Token admin_token;
		String adminPrivateKey;
		Cipher adminCipher;

		// 1 - register admin user
		{
			{
				Validator validator = new Validator();
				validator.password = "12345";
				admin_token = adb.generateTokenForUser(kdb, validator);
			}
			{
				Validator validator = new Validator();
				validator.password = "12345";
				adb.updateUserValidator("54321", validator, Validator.fromPassword("54321"));
				admin_token = adb.generateTokenForUser(kdb, validator);
				validator.password = "54321";
				admin_token = adb.generateTokenForUser(kdb, validator);
			}
			{
				KeyPair pair = CipherUtils.generateKeyPair(CipherUtils.Algorithm.RSA);
				adminPrivateKey = CipherUtils.getPrivateKeyInBase64(pair);
				adminCipher = CipherUtils.getEncrypter(CipherUtils.Algorithm.RSA, pair.getPrivate());

				Validator validator = new Validator();
				validator.password = "54321";
				String public_key = CipherUtils.getPublicKeyInBase64(pair);
				adb.setUserPublicKey(public_key, kdb, validator);
				adb.setUserPublicKey(public_key, kdb, validator);
			}
		}
		{
			String panicPrivateKey;
			// 1 - set_panic_pk
			{
				KeyPair pair = CipherUtils.generateKeyPair(CipherUtils.Algorithm.RSA);
				panicPrivateKey = CipherUtils.getPrivateKeyInBase64(pair);

				EncryptedContent<PanicPublicKey> content = new EncryptedContent<>();
				content.setContent(new PanicPublicKey(CipherUtils.getPublicKeyInBase64(pair)), adminCipher, Application.getGson());
				kdb.setPanicPublicKey(content);
			}
			// 2 - gen_admin_pk
			{
				KeyPair pair;
				{
					EncryptedContent<GenerateKeyPair> content = new EncryptedContent<>();
					content.setContent(new GenerateKeyPair(new Date(System.currentTimeMillis())), Application.getGson());
					pair = kdb.generateKeyPair(content);
				}
				{
					EncryptedContent<AdminPublicKey> content = new EncryptedContent<>();
					content.setContent(new AdminPublicKey(CipherUtils.getPublicKeyInBase64(pair)), Application.getGson());
					kdb.setAdminPublicKey(content);
					//adminPrivateKey = CipherUtils.getPrivateKeyInBase64(pair);
				}
			}
			// 3 - add_user_key
			{
				EncryptedContent<AddUserField> content = new EncryptedContent<>();
				content.setContent(new AddUserField("name"), adminCipher, Application.getGson());
				adb.addUserPropertyField(content);
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
				adb.registerInquiry(captcha);
			}
			// 5 - register
			{
				Validator validator = new Validator();
				validator.phone = "phone";
				validator.password = "phone_pass";
				validator.inquiry = new Inquiry("1", "11");
				validator.debugForceInternalInquiry = new Inquiry("2", "22");
				adb.sendInquiry(Inquiry.Reason.REGISTER_VALIDATION, validator);
			}
			// 6 - verify
			{
				Validator validator = new Validator();
				validator.inquiry = new Inquiry("2", "22");
				appId = adb.verifyUser(validator);
			}
			// 7 - update_user
			{
				KeyPair pair;
				{
					EncryptedContent<GenerateKeyPair> content = new EncryptedContent<>();
					content.setContent(new GenerateKeyPair(new Date(System.currentTimeMillis())), Application.getGson());
					pair = kdb.generateKeyPair(content);
				}
				{
					Validator validator = new Validator();
					validator.phone = "phone";
					validator.password = "phone_pass";
					User user = adb.getUser(kdb, validator);

					user.setName("MainApplication");
					user.type = User.Type.APPLICATION;
					user.appFields = new HashSet<>();
					user.appFields.add(User.NAME_FIELD);
					user.publicKey = CipherUtils.getPublicKeyInBase64(pair);
					appPrivateKey = CipherUtils.getPrivateKeyInBase64(pair);
					adb.updateUser(user, kdb, validator);
					user = adb.getUser(kdb, validator);
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
				adb.registerInquiry(captcha);
			}
			// 9 - register
			{
				Validator validator = new Validator();
				validator.phone = "user";
				validator.password = "user_pass";
				validator.inquiry = new Inquiry("3", "33");
				validator.debugForceInternalInquiry = new Inquiry("4", "44");
				adb.sendInquiry(Inquiry.Reason.REGISTER_VALIDATION, validator);
			}
			// 10 - verify
			{
				Validator validator = new Validator();
				validator.inquiry = new Inquiry("4", "44");
				userId = adb.verifyUser(validator);
			}
			// 11 - update_user
			{
				Validator validator = new Validator();
				validator.phone = "phone";
				validator.password = "phone_pass";
				User user = adb.getUser(kdb, validator);

				user.setName("User Name");
				adb.updateUser(user, kdb, validator);
			}
			// 12 - generate_token
			{
				Validator validator = new Validator();
				validator.phone = "phone";
				validator.password = "phone_pass";
				validator.applicationCode = applicationCode;
				user_token = adb.generateTokenForUser(kdb, validator);
			}
		}

		{
			String pk_name = user_token.serverPublicKeyName;
			NamedPublicKey pk = kdb.getServerPublicKey(pk_name);

			Cipher decrypter1 = CipherUtils.generateDecrypterFromBase64PublicKey(pk.name, CipherUtils.Algorithm.RSA);
			Cipher decrypter2 = CipherUtils.generateDecrypterFromBase64PrivateKey(appPrivateKey, CipherUtils.Algorithm.RSA);
			Token.UserData user = ContentEncrypter.decryptContent(Token.UserData.class, user_token.userData, decrypter2, decrypter1, Application.getGson());
			user = null;
		}

	}

}
