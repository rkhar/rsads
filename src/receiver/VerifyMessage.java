package receiver;

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

public class VerifyMessage {
    private List<byte[]> list;

    @SuppressWarnings("unchecked")
    public VerifyMessage(String filename, String keyFile) throws Exception {
        ObjectInputStream in = new ObjectInputStream(new FileInputStream(filename));
        this.list = (List<byte[]>) in.readObject();
        in.close();

        System.out.println(verifySignature(list.get(0), list.get(1), keyFile) ? "VERIFIED MESSAGE" +
                "\n----------------\n" + new String(list.get(0)) : "Could not verify the signature.");
    }

    private boolean verifySignature(byte[] data, byte[] signature, String keyFile) throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(getPublic(keyFile));
        sig.update(data);

        return sig.verify(signature);
    }

    public PublicKey getPublic(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static void main(String[] args) throws Exception{
        try {
            new VerifyMessage("MyData/SignedData.txt", "KeyPair/publicKey");
        } catch (Exception e){
            System.out.println(e.getMessage());
        }
    }
}