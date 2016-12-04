import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import java.security.Security;
import java.security.Provider;

class KeyFctry{
	public static byte[] deriveKey (String password, byte[] salt, int keyLen) {
		SecretKey key = null;

		try{
			SecretKeyFactory kf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
			KeySpec specs = new PBEKeySpec(password.toCharArray(), salt, 1024, keyLen);
			key = kf.generateSecret(specs);
		} catch (Exception e) {
			System.err.println("InvalidKeySpec " + e.getMessage());
		}
		return key.getEncoded();
	}

	public static void showProviderInfo(){
		Provider[] providers = Security.getProviders();	
		for (int i=0;i<providers.length;i++){
			System.out.println(providers[i].getName());
			System.out.println("\t - services: " + providers[i].getServices());
			System.out.println("\t - info: " + providers[i].getInfo());
		}
	}


	public static void main(String[] args){
		//showProviderInfo();
		byte[] data = deriveKey("password", "salt".getBytes(), 192);
		int i = 0;
		for (byte b: data){
			System.out.println(i++ + "\t" + b);
		}
	}
}
