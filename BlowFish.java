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
import java.io.File;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.Paths;
import java.io.IOException;

public class BlowFish {

	private static int KEYLENGTH = 128;  // limited by JCE 
	
	public static void main(String[] args) throws Exception{
		String fn = null;
		String pw = null;
		String salt = null;
		if (args.length<2){
			System.out.println("usage: BlowFish filename pass [salt]");
			System.out.println("       BlowFish DECRYPTFILE fn pass salt");
			return;
		}
		if (args[0].equals("DECRYPTFILE")){
			fn = args[1];
			pw = args[2];
			salt = "default";
			if (args.length==4)
				salt = args[3];

			decryptFile(fn,  pw,  salt);
		} else {
			fn = args[0];
			pw = args[1];
			salt = "default";
			if (args.length>2)
				salt = args[2];

			byte[] payload = null;
			try{
				payload = Files.readAllBytes(Paths.get(fn));
			} catch (Exception e) {
				System.err.println("fileio error " + e.getMessage());
			}	
	
			String ciphertxt = encrypt( new String(payload), pw, salt);
			String cleartxt = decrypt(ciphertxt, pw, salt);
			System.out.println("ciphertxt= " + ciphertxt);
			if (writeFile(fn + ".enc", ciphertxt, true)){
				System.out.println("wrote to file " + fn + ".enc");
			}
			System.out.println("cleartxt= " + cleartxt);
		}
	} 

	/* since we are encrypting a random char docusign password, we dont
		have to worry about repeating patterns within the payload so
		we can use ECB and avoid having to specify initialization vectors.
		suspect this and padding are why openssl blowfish encryption does
		not appear to interwork with java based 
	*/
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

	public static void decryptFile(String fn, String pw, String salt){
		if (salt.length()==0){
			salt = "default";
		}
		byte[] ciphertext = null;
		try{
			ciphertext = Files.readAllBytes(Paths.get(fn));
		} catch (Exception e) {
			System.err.println("fileio error " + e.getMessage());
		}	
		System.out.println( decrypt(new String(ciphertext), pw, salt));

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

	public static boolean writeFile(String fn, String contents, boolean overwrite){
		File targ = new File(fn);
		if (!targ.exists()||overwrite){
			Path file = targ.toPath();
			System.out.println( " targ.exists() = " + targ.exists() +
								" fn = " + fn  
							);
			try {
				Files.write(file, contents.getBytes(), 
					StandardOpenOption.CREATE);	
			} catch(IOException ioe) {
				System.err.println("ioe " + ioe.getMessage());
				System.err.println(ioe.getCause());
			} catch(UnsupportedOperationException uoe){
				System.err.println("uoe " + uoe.getMessage());

			} catch(SecurityException sec){
				System.err.println("sec " + sec.getMessage());
			} catch (Exception e) {
				System.err.println("could not write to " + fn);
				System.err.println("file io error: " + e.getMessage());
				return false;
			}
			return true;
		}
		return false;
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

