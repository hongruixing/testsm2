package test;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class GenPrivateKey {
    private static byte[] bytesFromKeyStrings(String string) {
        string = string.replaceAll("-----BEGIN PRIVATE KEY-----", "");
        string = string.replaceAll("-----BEGIN EC PRIVATE KEY-----", "");
        string = string.replaceAll("-----END EC PRIVATE KEY-----", "");
        string = string.replaceAll("-----END PRIVATE KEY-----", "");
        string = string.replaceAll("\r", "");
        string = string.replaceAll("\n", "");
        byte[] bytes = Base64.getDecoder().decode(string);
        return bytes;
    }
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        // 获取SM2加密器
        // 获取SM2相关参数
        X9ECParameters parameters = GMNamedCurves.getByName("sm2p256v1");
        // 获取椭圆曲线KEY生成器
        BouncyCastleProvider provider = new BouncyCastleProvider();
        KeyFactory keyFactory = KeyFactory.getInstance("EC", provider);
        // 椭圆曲线参数规格
        ECParameterSpec ecParameterSpec = new ECParameterSpec(parameters.getCurve(), parameters.getG(), parameters.getN(), parameters.getH());

        String privateKeyHex = "fafe8820638bf5d343c55cbafab450b4fd4b12f73c4a9c0401cd75e0dc067ff3";
        BigInteger bigInteger = new BigInteger(privateKeyHex,16);
        BCECPrivateKey privateKey = (BCECPrivateKey) keyFactory.generatePrivate(new ECPrivateKeySpec(bigInteger,
                ecParameterSpec));
        System.out.println(privateKey.getD());
        String plainText = "I like huangjuan";
        // 创建签名对象
        Signature signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), provider);
        // 初始化为签名状态
        signature.initSign(privateKey);
        // 传入签名字节
        signature.update(plainText.getBytes());
        // 签名
        String sig = Base64.getEncoder().encodeToString(signature.sign());
        System.out.println(sig);
    }
}
