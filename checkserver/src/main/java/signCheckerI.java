
import java.util.*;
import Demo.*;

public class signCheckerI implements signChecker {

    @Override
    public void generateKey(String keypassword, com.zeroc.Ice.Current current) {
        System.out.println("Generating keys with password: " + keypassword);
    }
    
    @Override
    public boolean verifySign(String path, String signature, String publicKey, com.zeroc.Ice.Current current){
        System.out.println("Verifying signature for file: " + path);
        return true;
    }

    @Override
    public void signFile(String path, String signaturePath, String privateKey, String keyPassword, com.zeroc.Ice.Current current){
        System.out.println("Signing file: " + path);
    }
    
}
