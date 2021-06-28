package com.auth.authServer;

import com.auth.authServer.model.Application;
import com.auth.authServer.model.AuthDatabase;
import com.auth.authServer.model.implementations.AuthDatabaseImplementationRAM;
import com.servers.interop.*;
import com.servers.interop.contents.AdminCommand;
import com.servers.interop.contents.AlterUserField;
import com.servers.interop.contents.ContentEncrypter;
import com.servers.interop.contents.EncryptedContent;
import com.servers.key.model.KeyDatabase;
import com.servers.key.model.implementations.KeyDatabaseImplementationRAM;
import com.servers.interop.requests.CommandRequest;
import com.google.common.collect.Sets;
import com.google.gson.Gson;
import com.jcore.crypto.CipherUtils;
import com.jcore.crypto.Crypter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.text.SimpleDateFormat;
import java.util.Properties;
import java.util.UUID;

@SpringBootApplication
public class AuthServerApplication {
	private static final boolean TEST_DATABASE = true;

	@Bean
	public JavaMailSender getJavaMailSender() {
		JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
		mailSender.setHost("smtp.gmail.com");
		mailSender.setPort(587);

		mailSender.setUsername("jmarindevel.tests@gmail.com");
		mailSender.setPassword("q2w3E$R%");

		Properties props = mailSender.getJavaMailProperties();
		props.put("mail.transport.protocol", "smtp");
		props.put("mail.smtp.auth", "true");
		props.put("mail.smtp.starttls.enable", "true");
		props.put("mail.debug", "true");

		return mailSender;
	}

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

			EncryptedContent<AlterUserField> f = new EncryptedContent<AlterUserField>();
			f.setContent(new AlterUserField(Sets.newHashSet("hola")), encrypter, gson);
			AlterUserField c = f.getContent(decrypter, gson);
			c = null;
		}


		KeyDatabase kdb = new KeyDatabaseImplementationRAM();
		AuthDatabase adb = new AuthDatabaseImplementationRAM(kdb);
		Token admin_token;
		String adminPrivateKey;
		Crypter.Encrypter adminCipher;

		// 1 - register admin user
		{
			{
				Validator validator = new Validator();
				validator.password = "12345";
				admin_token = adb.generateTokenForUser(validator);
			}
			{
				Validator validator = new Validator();
				validator.password = "12345";
				adb.updateUserValidator(validator, Validator.fromPassword("54321"));
				admin_token = adb.generateTokenForUser(validator);
				validator.password = "54321";
				admin_token = adb.generateTokenForUser(validator);
			}
			{
				KeyPair pair = CipherUtils.generateKeyPair(CipherUtils.Algorithm.RSA);
				adminPrivateKey = CipherUtils.getPrivateKeyInBase64(pair);
				adminCipher = Crypter.Encrypter.newFromRSAKey(pair.getPrivate());

				Validator validator = new Validator();
				validator.password = "54321";
				String public_key = CipherUtils.getPublicKeyInBase64(pair);
				AdminCommand cmd = AdminCommand.newSetPublicKey(public_key);
				adb.setUserPublicKey(public_key, validator);
				{
					CommandRequest<AdminCommand> command = new CommandRequest<>();
					command.commandEncoded = ContentEncrypter.encryptContent(cmd, Application.getGson());
					//adb.executeAdminCommand(json);
				}
				{
					//String json = ContentEncrypter.encryptContent(command, Application.getGson());
					//adb.executeAdminCommand(json);
				}
				{
					//String cmd = ContentEncrypter.encryptContent(command, adminCipher, Application.getGson());
					//adb.executeAdminCommand(cmd);
				}
			}
			{
				KeyPair pair = CipherUtils.generateKeyPair(CipherUtils.Algorithm.RSA);

				Validator validator = new Validator();
				validator.password = "54321";
				String public_key = CipherUtils.getPublicKeyInBase64(pair);
				adb.setUserPublicKey(public_key, validator);
			}
		}
		{
			// 3 - add_user_key
			{
				AdminCommand command = AdminCommand.newAddUserField(Sets.newHashSet("name"));
				String cmd = ContentEncrypter.encryptContent(command, Application.getGson());
				//adb.executeAdminCommand(cmd);
			}
			{
				AdminCommand command = AdminCommand.newAddUserField(Sets.newHashSet("name"));
				String cmd = ContentEncrypter.encryptContent(command, adminCipher, Application.getGson());
				//adb.executeAdminCommand(cmd);
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
				adb.registerInquiry(captcha, Inquiry.Action.REGISTER_USER, null);
			}
			// 5 - register
			Inquiry.Response register_response;
			{
				Inquiry inquiry = new Inquiry("1", "11");
				Inquiry.ActionParams action = new Inquiry.ActionParams();

				action.user = new User();
				action.setProperty(User.NAME_FIELD, "app");
				action.user.type = User.Type.APPLICATION;
				action.validator = new Validator();
				action.validator.phone = "phone";
				action.validator.password = "phone_pass";
				register_response = adb.verifyInquiry(inquiry, action);
			}
			// 6 - verify
			{
				Inquiry inquiry = new Inquiry(register_response.debugDesiredResponse.inquiry,
						register_response.debugDesiredResponse.desiredResult);

				adb.verifyInquiry(inquiry, null);
			}
			// 7 - update_user
			{
				KeyPair pair = kdb.generateKeyPair();
				{
					Validator validator = new Validator();
					validator.phone = "phone";
					validator.password = "phone_pass";
					User user = adb.getUser(validator);

					//user.setName("MainApplication");
					user.type = User.Type.APPLICATION;
					//user.appFields = new HashSet<>();
					//user.appFields.add(User.NAME_FIELD);
					//user.publicKey = CipherUtils.getPublicKeyInBase64(pair);
					appPrivateKey = CipherUtils.getPrivateKeyInBase64(pair);
					adb.updateUser(user, validator);
					user = adb.getUser(validator);
					com.servers.interop.Application app = adb.getApplication(validator);
					applicationCode = app.appCode;
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

				action.user = new User();
				action.setName("user");
				action.user.type = User.Type.USER;
				action.validator = new Validator();
				action.validator.phone = "phone1";
				action.validator.password = "phone_pass1";
				register_response = adb.verifyInquiry(inquiry, action);
			}
			// 10 - verify
			{
				Inquiry inquiry = new Inquiry(register_response.debugDesiredResponse.inquiry,
						register_response.debugDesiredResponse.desiredResult);

				adb.verifyInquiry(inquiry, null);
			}
			// 11 - update_user
			User user;
			{
				Validator validator = new Validator();
				validator.phone = "phone";
				validator.password = "phone_pass";
				user = adb.getUser(validator);
				//user.setName("User Name");
				adb.updateUser(user, validator);
			}
			{
				Inquiry inquiry = new Inquiry("1", "11");
				Inquiry.ActionParams params = new Inquiry.ActionParams();
				params.userId = user.id;
				params.applicationCode = applicationCode;
				adb.registerInquiry(inquiry, Inquiry.Action.REGISTER_USER_TO_APPLICATION, params);
			}
			{
				Inquiry inquiry = new Inquiry("1", "11");
				adb.verifyInquiry(inquiry, null);
			}
			// 12 - generate_token
			{
				Validator validator = new Validator();
				validator.phone = "phone";
				validator.password = "phone_pass";
				validator.applicationCode = applicationCode;
				user_token = adb.generateTokenForUser(validator);
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
