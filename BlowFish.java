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
import javax.crypto.BadPaddingException;

public class BlowFish {

	private static int KEYLENGTH = 128;  // limited by JCE 
	private static BASE64Decoder b64Decoder = null;
	private static BASE64Encoder b64Encoder = null;
	
	public static void main(String[] args) throws Exception{
		String fn = null;
		String pw = null;
		StringBuilder salt = new StringBuilder();
		byte[] iv = null;
		StringBuilder ivstr = new StringBuilder();
		if (args.length<2){
			System.out.println("usage: BlowFish filename pass [salt] ");
			System.out.println("       BlowFish DECRYPTFILE fn pass ");
			return;
		}
		if (args[0].equals("DECRYPTFILE")){
			fn = args[1];
			pw = args[2];

			//decryptFile(fn,  pw,  salt);
			System.out.println(decryptFile(fn,pw));
		} else {
			fn = args[0];
			pw = args[1];
			if (args.length >2)
				salt.append(args[2]);
		
			byte[] payload = null;
			try{
				payload = Files.readAllBytes(Paths.get(fn));
			} catch (Exception e) {
				System.err.println("Exception-fileio: " + e.getMessage());
			}	
	
			String ciphertxt = encrypt( new String(payload), pw, salt, ivstr);
			System.out.println("## iv:" + ivstr );
			System.out.println("## salt:" + salt );
			
			String cleartxt = decrypt(ciphertxt, pw, salt, ivstr.toString());
			System.out.println("## ciphertxt= " + ciphertxt);
			/*
			if (writeFile(fn + ".enc", ciphertxt, true)){
				System.out.println("wrote to file " + fn + ".enc");
			}
			*/			
			ArrayList<String> coded = new ArrayList<String>();
			coded.add(salt.toString());
			coded.add(ivstr.toString());
			coded.add(ciphertxt);
			try{
				toFile(fn + ".enc", coded);
			} catch (IOException ioe){
				System.err.println("Exception-IO during encr output: " +
					ioe.getMessage());
			} catch (Exception e) {
				System.err.println("Exception-Writing cipher file " +
					e.getMessage());
			}
			System.out.println("## cleartxt= " + cleartxt);
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
	public static String encrypt(String txt, String pw, StringBuilder salt, StringBuilder ivstr){
		SecureRandom srnd = new SecureRandom();
		if (salt.length() == 0){
			salt.append(base64Encode(srnd.generateSeed(16)));
			System.out.println("## setting salt to " + salt);
		} else {
			System.out.println("## Salt given: " + salt);
		}
		byte[] keyData = deriveKey(pw, salt.toString().getBytes(), KEYLENGTH) ;
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyData, "Blowfish");
		byte[] ciphertext = null;
		try{
			Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
		//	byte[] iv = new byte[cipher.getBlockSize()];
		//	rnd.nextBytes(iv);

			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec,srnd);
			ciphertext = cipher.doFinal(txt.getBytes());
			//ivstr.append(new BASE64Encoder().encode(cipher.getIV()));
			ivstr.append( base64Encode(cipher.getIV()));

			//System.out.println("iv:" + toHexStr(iv) );
		} catch ( NoSuchAlgorithmException noSuch ) {
			System.err.println("Exception-NoSuchAlg during encr " + noSuch.getMessage());
		} catch ( InvalidKeyException invKey ) {
			System.err.println("Exception-InvalidKey during encr" + invKey.getMessage());
		} catch ( IllegalBlockSizeException blockSz){
			System.err.println("Exception-IllegalBlockSize during encr" + blockSz.getMessage());
		} catch (Exception e) {
			System.err.println("Exception during encr" + e.getMessage());
		}
		//return (new BASE64Encoder().encode(ciphertext));
		return (base64Encode(ciphertext));
	}
/*
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
*/
	public static String decrypt(String ciphertxt, String pw, StringBuilder salt, String ivstr) {
		
		byte[] keyData = deriveKey(pw, salt.toString().getBytes(), KEYLENGTH) ;
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyData,"Blowfish");
		byte[] decoded = null;
		try{
			//byte[] iv = new BASE64Decoder().decodeBuffer(ivstr);
			byte[] iv = base64Decode(ivstr);
			Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec,new IvParameterSpec(iv));
			//decoded = cipher.doFinal(new BASE64Decoder().decodeBuffer(ciphertxt));
			decoded = cipher.doFinal(base64Decode(ciphertxt));
		} catch ( NoSuchAlgorithmException noSuch ) {
			System.err.println("Exception-NoSuchAlgorithmException during decr " + noSuch.getMessage());
		} catch ( InvalidKeyException invKey ) {
			System.err.println("Exception-InvalidKey during decr" + invKey.getMessage());
		} catch ( IllegalBlockSizeException blockSz){
			System.err.println("Exception-IllegalBlockSize during decr " + blockSz.getMessage());
		} catch ( BadPaddingException pe ){
			System.err.println("Exception-Bad Padding: Probably wrong password : " + pe.getMessage());
		} catch (Exception e) {
			System.err.println("Exception during decr " + e.getMessage() + " " +
				e.getClass().getSimpleName());
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
			try {
				Files.write(file, contents.getBytes(), 
					StandardOpenOption.CREATE);	
			} catch(IOException ioe) {
				System.err.println("Exception-io during write" + ioe.getMessage());
				System.err.println(ioe.getCause());
			} catch(UnsupportedOperationException uoe){
				System.err.println("Exception-unsupported operation during write" + uoe.getMessage());

			} catch(SecurityException sec){
				System.err.println("Exception-security during write " + sec.getMessage());
			} catch (Exception e) {
				System.err.println("Exception-could not write to " + fn + " during write");
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
			System.err.println("Exception deriving key : " + e.getMessage());
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
			System.err.println("Exception-Decrypting File IO Error: " +
				ioe.getMessage());
			return null;
		} catch (Exception e) {
			System.err.println("Exception-Decrypting File Error: " +
				e.getMessage());
			return null;
		}	
		if (lines.size() < 2){
			System.err.println("Exception-Incorrect Encrypted File format");
			return null;
		}
		//byte[] keyData = deriveKey(pw, lines.get(0).getBytes(),  KEYLENGTH) ;
		
		System.out.println("## salt: " + lines.get(0));
		System.out.println("## iv: " + lines.get(1));
		System.out.println("## ct: " + lines.get(2));
		
		String plaintext = decrypt( lines.get(2), // ciphertxt, 
			pw, 
			new StringBuilder(lines.get(0)),
			lines.get(1)); 
		return plaintext;
	}
	
	public static byte[] base64Decode(String payload){
		byte[] result = null;
		if (b64Decoder == null)
			b64Decoder = new BASE64Decoder();
		try{
			result = b64Decoder.decodeBuffer(payload);
		} catch(IOException ioe) {
			System.err.println("Exception-IO decoding " + ioe.getMessage());
		} catch (Exception e) {
			System.err.println("Exception decoding " + e.getMessage());
		}
		return result;
	}

	public static String base64Encode(byte[] payload){
		if (b64Encoder == null)
			b64Encoder = new BASE64Encoder();
		return b64Encoder.encode(payload);
	}
}

