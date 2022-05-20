package test;

import cn.hutool.crypto.asymmetric.SM2;

import java.util.Base64;

public class HuiTollSign {
    public static void main(String[] args) {
        //需要签名的明文,得到明文对应的字节数组
        byte[] dataBytes = "我是一段测试aaaa".getBytes();
//指定的私钥
        String privateKeyHex = "fafe8820638bf5d343c55cbafab450b4fd4b12f73c4a9c0401cd75e0dc067ff3";

// 此构造从5.5.9开始可使用
        final SM2 sm2 = new SM2(privateKeyHex, null, null);
        sm2.usePlainEncoding();
        byte[] sign = sm2.sign(dataBytes, null);
        String sig = Base64.getEncoder().encodeToString(sign);
        System.out.println(sig);
    }
}
