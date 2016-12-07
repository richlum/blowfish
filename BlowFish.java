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
import java.util.List;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;

public class BlowFish {

	private static int KEYLENGTH = 128;  // limited by JCE 
	
	public static void main(String[] args) throws Exception{
		String fn = null;
		String pw = null;
		String salt = null;
		byte[] iv = null;
		StringBuilder ivstr = new StringBuilder();
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

			//decryptFile(fn,  pw,  salt);
			System.out.println(decryptFile(fn,pw));
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
	
			String ciphertxt = encrypt( new String(payload), pw, salt, ivstr);
			System.out.println("iv:" + ivstr );
			System.out.println("salt:" + salt );
			
			String cleartxt = decrypt(ciphertxt, pw, salt, ivstr.toString());
			System.out.println("ciphertxt= " + ciphertxt);
			if (writeFile(fn + ".enc", ciphertxt, true)){
				System.out.println("wrote to file " + fn + ".enc");
			}
						
			ArrayList<String> coded = new ArrayList<String>();
			coded.add(salt);
			coded.add(ivstr.toString());
			coded.add(ciphertxt);
			try{
				toFile(fn + "2.enc", coded);
			} catch (IOException ioe){
				System.err.println("Input Output Exception: " +
					ioe.getMessage());
			} catch (Exception e) {
				System.err.println("Error Writing cipher file " +
					e.getMessage());
			}
			System.out.println("cleartxt= " + cleartxt);
		}
	} 
	public static StringBuilder toHexStr(byte[] bytes){
		StringBuilder sb = new StringBuilder();
		for (int i=0;i<bytes.length;i++){
			System.out.println(i + " " + String.format("%02X",bytes[i]) + " " + bytes[i]);
			sb.append(String.format("%02X",bytes[i]));
		}
		return sb;

	}

	/* since we are encrypting a random char docusign password, we dont
		have to worry about repeating patterns within the payload so
		we can use ECB and avoid having to specify initialization vectors.
		suspect this and padding are why openssl blowfish encryption does
		not appear to interwork with java based 
	*/
	public static String encrypt(String txt, String pw, String salt, StringBuilder ivstr){
		byte[] keyData = deriveKey(pw, salt.getBytes(), KEYLENGTH) ;
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyData, "Blowfish");
		byte[] ciphertext = null;
		try{
			Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
			SecureRandom srnd = new SecureRandom();
		//	byte[] iv = new byte[cipher.getBlockSize()];
		//	rnd.nextBytes(iv);

			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec,srnd);
			ciphertext = cipher.doFinal(txt.getBytes());
			ivstr.append(new BASE64Encoder().encode(cipher.getIV()));

			//System.out.println("iv:" + toHexStr(iv) );
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
		byte[] ciphertext = null;
		String ciphertextstr = null;
		List<String> lines = null;
		String ivstr = null;
		try{
			lines = Files.readAllLines(Paths.get(fn),Charset.defaultCharset());
			if (lines.size()==3){
				salt = lines.get(0);
				ivstr = lines.get(1);
				ciphertextstr = lines.get(2);
			} else {
				System.err.println("File must have 3 lines: salt, iv, ciphertext");
				return;
			}
			
		} catch (Exception e) {
			System.err.println("fileio error " + e.getMessage());
		}
		System.out.println( "salt " + salt);
		System.out.println( "ivstr " + ivstr);
		System.out.println( "ciphertextstr " + ciphertextstr);
	
		System.out.println( decrypt(ciphertextstr, pw, salt, ivstr));

	}

	public static String decrypt(String ciphertxt, String pw, String salt, String ivstr) {
		byte[] keyData = deriveKey(pw, salt.getBytes(), KEYLENGTH) ;
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyData,"Blowfish");
		byte[] decoded = null;
		try{
			byte[] iv = new BASE64Decoder().decodeBuffer(ivstr);
			Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec,new IvParameterSpec(iv));
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
		if (decoded!= null)
			return new String(decoded);
		return "";
	}

	/* string of hex values to convert to byte array */
	public static byte[] toByteArray(String s) {
		
		byte[] result = s.getBytes();
		/*
		new byte[s.length()*2];
		for (int i=0;i<s.length();i++) {
			result[i] = (byte) s.charAt(i)>>>4;
			result[i] = (byte) s.charAt(i);
		} */

		for (int i=0;i<result.length;i++){
			System.out.println(i + " " + result[i]);
		}
		return result;
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

	public static List<String> readFile(String fn) throws IOException{
		return Files.readAllLines(Paths.get(fn),Charset.forName("UTF-8"));
	}
	
	public static void toFile(String fn, List<String> lines) throws IOException {
		Files.write(Paths.get(fn),
			lines,Charset.forName("UTF-8"), StandardOpenOption.CREATE);
	}

	/*
		File format
		line 1 salt - prevents reuse of dictionary attacks for pw reuse
		line 2 initization vector - 1st block encoding in cbc - hide repeated plaintext
		line 3 ciphertext - encrypted payload.
	*/
	public static String decryptFile(String fn, String pw){
		List<String> lines = null;
		try{
			lines =  readFile(fn);
		} catch (IOException ioe) {
			System.err.println("Decrypting File Error: " +
				ioe.getMessage());
			return null;
		} catch (Exception e) {
			System.err.println("Decrypting File Error: " +
				e.getMessage());
			return null;
		}	
		if (lines.size() < 2){
			System.err.println("Incorrect Encrypted File format");
			return null;
		}
		//byte[] keyData = deriveKey(pw, lines.get(0).getBytes(),  KEYLENGTH) ;
		
		System.out.println("salt: " + lines.get(0));
		System.out.println("iv: " + lines.get(1));
		System.out.println("ct: " + lines.get(2));
		
		String plaintext = decrypt( lines.get(2), // ciphertxt, 
			pw, 
			lines.get(0),
			lines.get(1)); 
		return plaintext;
	}
}

