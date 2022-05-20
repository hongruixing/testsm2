package test;

import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.ECKeyUtil;
import cn.hutool.crypto.asymmetric.SM2;

import java.util.Base64;

public class HuiTollVerSign {
    public static void main(String[] args) {
        //指定的公钥
        String publicKeyHex ="04169c7a84629c33ae3a35b63a3431c6eeb828637e1623d4ccd15f2c40c939a1a7584fc728eb09dd5f7ecfb972e7e3e69919e68b8ada41d9c1e8ae39d0bb1ce2b4";
//需要加密的明文,得到明文对应的字节数组
        byte[] dataBytes = "我是一段测试aaaa".getBytes();
//签名值
        String signHex ="GOfw4rfnsBqFwAohJrC40UNd512fAAnonlyiUsi0uTWNmzGKfCowgQovRD+ZTCf8bYJTTFvRfdZu7yNu3lly1g==";

        final SM2 sm2 = new SM2(null, ECKeyUtil.toSm2PublicParams(publicKeyHex));
        sm2.usePlainEncoding();

// true
        boolean verify = sm2.verify(dataBytes, Base64.getDecoder().decode(signHex));
        System.out.println(verify);
    }
}
