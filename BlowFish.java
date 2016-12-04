import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import javax.crypto.IllegalBlockSizeException;

public class BlowFish {

	public static void main(String[] args) throws Exception{
		String payload = args[0];
		String pw = args[1];
	
		String ciphertxt = encrypt( payload, pw);
		String cleartxt = decrypt(ciphertxt, pw);
		System.out.println("ciphertxt= " + ciphertxt);
		System.out.println("cleartxt= " + cleartxt);
	} 

	public static String encrypt(String txt, String pw){
		byte[] keyData = pw.getBytes();
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyData, "Blowfish");
		byte[] ciphertext = null;
		try{
			Cipher cipher = Cipher.getInstance("Blowfish");
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

	public static String decrypt(String ciphertxt, String pw) {
		byte[] keyData = pw.getBytes();
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

}

