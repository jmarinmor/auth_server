package com.auth.authServer;

import com.auth.authServer.model.Application;
import com.auth.authServer.model.AuthDatabase;
import com.auth.authServer.model.KeyDatabase;
import com.auth.authServer.model.implementations.AuthDatabaseImplementationRAM;
import com.auth.authServer.model.implementations.KeyDatabaseImplementationRAM;
import com.auth.interop.*;
import com.auth.interop.contents.*;
import com.google.gson.Gson;
import com.jcore.crypto.Crypter;
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

		if (false) {
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

			String source = "012345678901234567890123456789012345678901234567890123456789" +
					"012345678901234567890123456789012345678901234567890123456789" +
					"012345678901234567890123456789012345678901234567890123456789" +
					"012345678901234567890123456789012345678901234567890123456789" +
					"012345678901234567890123456789012345678901234567890123456789" +
					"012345678901234567890123456789012345678901234567890123456789" +
					"012345678901234567890123456789012345678901234567890123456789" +
					"012345678901234567890123456789012345678901234567890123456789" +
					"012345678901234567890123456789012345678901234567890123456789" +
					"012345678901234567890123456789012345678901234567890123456789" +
					"012345678901234567890123456789012345678901234567890123456789";
			byte[] plain = source.getBytes(StandardCharsets.UTF_8);

			Cipher encrypter = Cipher.getInstance(ALGORITHM_RSA_CIPHER);
			encrypter.init(Cipher.ENCRYPT_MODE, pair.getPrivate());
			Cipher decrypter = Cipher.getInstance(ALGORITHM_RSA_CIPHER);
			decrypter.init(Cipher.DECRYPT_MODE, pair.getPublic());

			byte[] encrypted = CipherUtils.encrypt(encrypter, plain, 245);
			byte[] decrypted = CipherUtils.encrypt(decrypter, encrypted, 256);

			String s = new String(decrypted, StandardCharsets.US_ASCII);

			s = null;
		}

		if (false) {
			KeyPair pair = CipherUtils.generateKeyPair(CipherUtils.Algorithm.RSA);
			Gson gson = new Gson();

			Crypter.Encrypter encrypter = Crypter.Encrypter.newFromRSAKey(pair.getPrivate());
			Crypter.Decrypter decrypter = Crypter.Decrypter.newFromRSAKey(pair.getPublic());

			EncryptedContent<AddUserField> f = new EncryptedContent<AddUserField>();
			f.setContent(new AddUserField("Hola"), encrypter, gson);
			AddUserField c = f.getContent(decrypter, gson);
			c = null;
		}


		AuthDatabase adb = new AuthDatabaseImplementationRAM();
		KeyDatabase kdb = new KeyDatabaseImplementationRAM();
		Token admin_token;
		String adminPrivateKey;
		Crypter.Encrypter adminCipher;

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
				adb.updateUserValidator(validator, Validator.fromPassword("54321"));
				admin_token = adb.generateTokenForUser(kdb, validator);
				validator.password = "54321";
				admin_token = adb.generateTokenForUser(kdb, validator);
			}
			{
				KeyPair pair = CipherUtils.generateKeyPair(CipherUtils.Algorithm.RSA);
				adminPrivateKey = CipherUtils.getPrivateKeyInBase64(pair);
				adminCipher = Crypter.Encrypter.newFromRSAKey(pair.getPrivate());

				Validator validator = new Validator();
				validator.password = "54321";
				String public_key = CipherUtils.getPublicKeyInBase64(pair);
				AdminCommand command = AdminCommand.newSetPublicKey(public_key);
				adb.setUserPublicKey(public_key, kdb, validator);
				{
					String json = ContentEncrypter.encryptContent(command, Application.getGson());
					adb.executeAdminCommand(json, kdb);
				}
				{
					String json = ContentEncrypter.encryptContent(command, Application.getGson());
					adb.executeAdminCommand(json, kdb);
				}
				{
					String cmd = ContentEncrypter.encryptContent(command, adminCipher, Application.getGson());
					adb.executeAdminCommand(cmd, kdb);
				}
			}
			{
				KeyPair pair = CipherUtils.generateKeyPair(CipherUtils.Algorithm.RSA);

				Validator validator = new Validator();
				validator.password = "54321";
				String public_key = CipherUtils.getPublicKeyInBase64(pair);
				adb.setUserPublicKey(public_key, kdb, validator);
			}
		}
		{
			// 3 - add_user_key
			{
				AdminCommand command = AdminCommand.newAddUserField("name");
				String cmd = ContentEncrypter.encryptContent(command, Application.getGson());
				adb.executeAdminCommand(cmd, kdb);
			}
			{
				AdminCommand command = AdminCommand.newAddUserField("name");
				String cmd = ContentEncrypter.encryptContent(command, adminCipher, Application.getGson());
				adb.executeAdminCommand(cmd, kdb);
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
				adb.registerInquiry(captcha, Inquiry.Action.REGISTER_USER, null, kdb);
			}
			// 5 - register
			Inquiry.Response register_response;
			{
				Inquiry inquiry = new Inquiry("1", "11");
				Inquiry.ActionParams action = new Inquiry.ActionParams();

				action.user = new User.PublicData();
				action.user.setName("app");
				action.user.type = User.Type.APPLICATION;
				action.validator = new Validator();
				action.validator.phone = "phone";
				action.validator.password = "phone_pass";
				register_response = adb.verifyInquiry(inquiry, action, kdb);
			}
			// 6 - verify
			{
				Inquiry inquiry = new Inquiry(register_response.debugDesiredResponse.inquiry,
						register_response.debugDesiredResponse.desiredResult);

				adb.verifyInquiry(inquiry, null, kdb);
			}
			// 7 - update_user
			{
				KeyPair pair = kdb.generateKeyPair();
				{
					Validator validator = new Validator();
					validator.phone = "phone";
					validator.password = "phone_pass";
					User.PublicData user = adb.getUser(kdb, validator);

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
				adb.registerInquiry(captcha, Inquiry.Action.REGISTER_USER, null);
			}
			// 9 - register
			Inquiry.Response register_response;
			{
				Inquiry inquiry = new Inquiry("1", "11");
				Inquiry.ActionParams action = new Inquiry.ActionParams();

				action.user = new User.PublicData();
				action.user.setName("user");
				action.user.type = User.Type.USER;
				action.validator = new Validator();
				action.validator.phone = "phone1";
				action.validator.password = "phone_pass1";
				register_response = adb.verifyInquiry(inquiry, action, kdb);
			}
			// 10 - verify
			{
				Inquiry inquiry = new Inquiry(register_response.debugDesiredResponse.inquiry,
						register_response.debugDesiredResponse.desiredResult);

				adb.verifyInquiry(inquiry, null, kdb);
			}
			// 11 - update_user
			User.PublicData user;
			{
				Validator validator = new Validator();
				validator.phone = "phone";
				validator.password = "phone_pass";
				user = adb.getUser(kdb, validator);
				user.setName("User Name");
				adb.updateUser(user, kdb, validator);
			}
			{
				Inquiry inquiry = new Inquiry("1", "11");
				Inquiry.ActionParams params = new Inquiry.ActionParams();
				params.userId = user.id;
				params.applicationCode = applicationCode;
				adb.registerInquiry(inquiry, Inquiry.Action.REGISTER_USER_TO_APPLICATION, params, kdb);
			}
			{
				Inquiry inquiry = new Inquiry("1", "11");
				adb.verifyInquiry(inquiry, null, kdb);
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

			Crypter.Decrypter decrypter1 = Crypter.Decrypter.newFromRSABase64PublicKey(pk.key);
			Crypter.Decrypter decrypter2 = Crypter.Decrypter.newFromRSABase64PrivateKey(appPrivateKey);
			Token.UserData user = ContentEncrypter.decryptContent(Token.UserData.class, user_token.userData, decrypter2, decrypter1, Application.getGson());
			user = null;
		}

	}

}
