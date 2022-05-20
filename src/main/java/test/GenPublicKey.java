package test;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class GenPublicKey {
    public static void main(String[] args) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException {
        // 获取SM2相关参数
        X9ECParameters parameters = GMNamedCurves.getByName("sm2p256v1");
        // 椭圆曲线参数规格
        ECParameterSpec ecParameterSpec = new ECParameterSpec(parameters.getCurve(), parameters.getG(), parameters.getN(), parameters.getH());
        // 将公钥HEX字符串转换为椭圆曲线对应的点
        String rawPublicKey = new String("04169c7a84629c33ae3a35b63a3431c6eeb828637e1623d4ccd15f2c40c939a1a7584fc728eb09dd5f7ecfb972e7e3e69919e68b8ada41d9c1e8ae39d0bb1ce2b4");

        ECPoint ecPoint = parameters.getCurve().decodePoint(Hex.decode(rawPublicKey));
        // 获取椭圆曲线KEY生成器
        BouncyCastleProvider provider = new BouncyCastleProvider();
        KeyFactory keyFactory = KeyFactory.getInstance("EC", provider);
        BCECPublicKey key = (BCECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(ecPoint, ecParameterSpec));
        System.out.println(key);
        // 创建签名对象
        String plainText = "I like huangjuan";
        Signature signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), provider);
        // 将公钥HEX字符串转换为椭圆曲线对应的点
        String signatureValue = "MEYCIQD3R/qBtFcUxf1z3uiuXmmqPgKJLF9bnxi5tevkSTSjbAIhAI1EdlDqkhsY63xXXELzpRHgOmXLBGlNt9AccAiBA57V";
        // 初始化为验签状态
        signature.initVerify(key);
        signature.update(plainText.getBytes());
        boolean ver = signature.verify(Base64.getDecoder().decode(signatureValue));
        System.out.println(ver);
    }
}
