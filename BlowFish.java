import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKey;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.spec.KeySpec;
import javax.crypto.IllegalBlockSizeException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class BlowFish {

	private static int KEYLENGTH = 128;  // limited by JCE 
	public static void main(String[] args) throws Exception{
		if (args.length<2){
			System.out.println("usage: BlowFish filename pass [salt]");
			return;
		}
		String fn = args[0];
		String pw = args[1];
		String salt = "default";
		if (args.length>2)	{
			salt = args[2];
		}

		byte[] payload = null;
		try{
			payload = Files.readAllBytes(Paths.get(fn));
		} catch (Exception e) {
			System.err.println("fileio error " + e.getMessage());
		}	
	
		String ciphertxt = encrypt( new String(payload), pw, salt);
		String cleartxt = decrypt(ciphertxt, pw, salt);
		System.out.println("ciphertxt= " + ciphertxt);
		System.out.println("cleartxt= " + cleartxt);
	} 

	public static String encrypt(String txt, String pw, String salt){
		byte[] keyData = deriveKey(pw, salt.getBytes(), KEYLENGTH) ;
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyData, "Blowfish");
		byte[] ciphertext = null;
		try{
			Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
			ciphertext = cipher.doFinal(txt.getBytes());
		} catch ( NoSuchAlgorithmException noSuch ) {
			System.err.println("NoSuchAlgorithmException " + noSuch.getMessage());
		} catch ( InvalidKeyException invKey ) {
			System.err.println("InvalidKey " + invKey.getMessage());
		} catch ( IllegalBlockSizeException blockSz){
			System.err.println("IllegalBlockSize " + blockSz.getMessage());
		} catch (Exception e) {
			System.err.println(e.getMessage());
		}

		return (new BASE64Encoder().encode(ciphertext));
	}

	public static String decrypt(String ciphertxt, String pw, String salt) {
		byte[] keyData = deriveKey(pw, salt.getBytes(), KEYLENGTH) ;
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyData,"Blowfish");
		byte[] decoded = null;
		try{
			Cipher cipher = Cipher.getInstance("Blowfish");
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
			decoded = cipher.doFinal(new BASE64Decoder().decodeBuffer(ciphertxt));
		} catch ( NoSuchAlgorithmException noSuch ) {
			System.err.println("NoSuchAlgorithmException " + noSuch.getMessage());
		} catch ( InvalidKeyException invKey ) {
			System.err.println("InvalidKey " + invKey.getMessage());
		} catch ( IllegalBlockSizeException blockSz){
			System.err.println("IllegalBlockSize " + blockSz.getMessage());
		} catch (Exception e) {
			System.err.println(e.getMessage());
		}
		return new String(decoded);
	}


	public static byte[] deriveKey (String password, byte[] salt, int keyLen) {
		SecretKey key = null;
		try{
			SecretKeyFactory kf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
			KeySpec specs = new PBEKeySpec(password.toCharArray(), salt, 1024, keyLen);
			key = kf.generateSecret(specs);
		} catch (Exception e) {
			System.err.println(" Error: " + e.getMessage());
		}
		return key.getEncoded();
	}



}

