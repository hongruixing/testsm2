package test;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class TransformPublicKey {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        String rawPublicKey = new String("04169c7a84629c33ae3a35b63a3431c6eeb828637e1623d4ccd15f2c40c939a1a7584fc728eb09dd5f7ecfb972e7e3e69919e68b8ada41d9c1e8ae39d0bb1ce2b4");
        byte[] val = new byte[rawPublicKey.length() / 2];
        for (int i = 0; i < val.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(rawPublicKey.substring(index, index + 2), 16);
            val[i] = (byte) j;
        }
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("sm2p256v1");

        ECPublicKeySpec keySpec = new ECPublicKeySpec(params.getCurve().decodePoint(val), params);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        ECPublicKey javaPublicKey =(ECPublicKey) keyFactory.generatePublic(keySpec);
        System.out.println(javaPublicKey);
    }
}
