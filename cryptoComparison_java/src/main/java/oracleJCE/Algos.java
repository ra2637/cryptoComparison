package oracleJCE;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Date;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import yuntai.cryptoComparison.App;
import yuntai.cryptoComparison.App.ALGORITHM;
import yuntai.cryptoComparison.App.MODE;

public class Algos {

	public static void symmetric(String filePath, ALGORITHM algo, MODE mode) {
		try {
//			System.out.println("====" + algo.name() + "_" + mode.name() + "====");
			KeyGenerator keygenerator = KeyGenerator.getInstance(algo.name(), App.getProvider());
			String algoName = algo.name() + "/" + mode.name() + "/" + "PKCS5Padding";
			int ivSize = 8;
			if (algo.name() == "AES") {
				ivSize = 16;
			}

			Date genKeyS = new Date();
			SecretKey myKey = keygenerator.generateKey();
			Date genKeyE = new Date();
			System.out.println("Genkey:"+ (genKeyE.getTime() - genKeyS.getTime()));

			runSymmetric(filePath, algoName, ivSize, myKey);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private static void runSymmetric(String filePath, String algoName, int ivSize, SecretKey myKey){
		Cipher cipher;
		// Create the cipher
		try {
			cipher = Cipher.getInstance(algoName, App.getProvider());
			Date genIVS = new Date();
			IvParameterSpec iv = new IvParameterSpec(new byte[ivSize]);
			Date genIVE = new Date();

			// Initialize the cipher for encryption
			cipher.init(Cipher.ENCRYPT_MODE, myKey, iv);

			// sensitive information
			byte[] file = Files.readAllBytes(Paths.get(filePath));

			// Encrypt the text
			Date encryptS = new Date();
			byte[] textEncrypted = cipher.doFinal(file);
			Date encryptE = new Date();

			// Initialize the same cipher for decryption
			cipher.init(Cipher.DECRYPT_MODE, myKey, iv);

			// Decrypt the text
			Date decryptS = new Date();
			cipher.doFinal(textEncrypted);
			Date decryptE = new Date();
			
			System.out.println("GenIV:"+ (genIVE.getTime() - genIVS.getTime()));
			System.out.println("Encrypt:"+ (encryptE.getTime() - encryptS.getTime()));
			System.out.println("Decrypt:"+ (decryptE.getTime() - decryptS.getTime()));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static void hash(String filePath, ALGORITHM algo) {
		String algoStr = algo.name();
		if (algoStr == ALGORITHM.SHA512.name()) {
			algoStr = "SHA-512";
		}
		try {
			String provider = App.getProvider();
			if (provider == "SunJCE") {
				provider = "SUN";
			}
			MessageDigest md = MessageDigest.getInstance(algoStr, provider);
			byte[] file = Files.readAllBytes(Paths.get(filePath));
			
			Date hashS = new Date();
			md.digest(file);
			Date hashE = new Date();
			System.out.println("Hash:"+ (hashE.getTime() - hashS.getTime()));
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	public static void DH(String filePath) {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", App.getProvider());
			keyGen.initialize(512);
			KeyAgreement keyAgreeA = KeyAgreement.getInstance("DH", App.getProvider());
			KeyAgreement keyAgreeB = KeyAgreement.getInstance("DH", App.getProvider());
			
			Date genKeyS = new Date();
			KeyPair keyPairA = keyGen.generateKeyPair();
			KeyPair keyPairB = keyGen.generateKeyPair();
			keyAgreeA.init(keyPairA.getPrivate());
			keyAgreeB.init(keyPairB.getPrivate());

			/* Check out A and B has the same secret 
	        keyAgreeA.doPhase(keyPairB.getPublic(), true);
	        keyAgreeB.doPhase(keyPairA.getPublic(), true);
	        byte[] sharedSecretA = keyAgreeA.generateSecret();
	        byte[] sharedSecretB = keyAgreeB.generateSecret();
	        if (!java.util.Arrays.equals(sharedSecretA, sharedSecretB))
	            throw new Exception("Shared secrets differ");
			 */
	        keyAgreeB.doPhase(keyPairA.getPublic(), true);
	        SecretKey key = keyAgreeB.generateSecret("DES");
	        Date genKeyE = new Date();
	        System.out.println("Genkey:"+ (genKeyE.getTime() - genKeyS.getTime()));
			runSymmetric(filePath, "DES/CBC/PKCS5Padding", 8, key);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static void RSA(String filePath){
		try {
			String keyProvider = App.getProvider();
			if (keyProvider == "SunJCE") {
				keyProvider = "SunRsaSign";
			}
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", keyProvider);
			keyGen.initialize(1024, new SecureRandom());
			Date genKeyS = new Date();
			KeyPair keyPair = keyGen.generateKeyPair();
			Date genKeyE = new Date();
			
			Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", App.getProvider());
			rsaCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

			// sensitive information
			byte[] file = Files.readAllBytes(Paths.get(filePath));
			ByteArrayOutputStream resultBuffer = new ByteArrayOutputStream();
			
			// Encrypt the text
			Date encryptS = new Date();
			for (int i = 0; i < file.length; i+=117) {
				byte[] f = Arrays.copyOfRange(file, i, i+117);
				byte[] textEncrypted = rsaCipher.doFinal(f);
				resultBuffer.write(textEncrypted);
			}
			Date encryptE = new Date();

			// Initialize the same cipher for decryption
			
			rsaCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
			byte[] result = resultBuffer.toByteArray();
			resultBuffer.flush();
			
			// Decrypt the text
			Date decryptS = new Date();
			for (int i = 0; i < result.length; i+=128) {
				byte[] f = Arrays.copyOfRange(result, i, i+128);
				byte[] textDecrypted = rsaCipher.doFinal(f);
				resultBuffer.write(textDecrypted);
			}
			Date decryptE = new Date();
			resultBuffer.flush();
			resultBuffer.close();
			
 			System.out.println("Genkey:"+ (genKeyE.getTime() - genKeyS.getTime()));
			System.out.println("Encrypt:"+ (encryptE.getTime() - encryptS.getTime()));
			System.out.println("Decrypt:"+ (decryptE.getTime() - decryptS.getTime()));
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}

}
