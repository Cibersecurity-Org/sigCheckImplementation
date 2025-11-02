 module Demo
 {
    interface signChecker
    {
        void generateKey(string keypassword);
        bool verifySign(string path, string signature, string publicKey);
        void signFile(string path, string signaturePath, string privateKey, string keyPassword);
    }
 }