import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.config.TinkConfig;
import com.sun.org.apache.xerces.internal.dom.ElementNSImpl;
import com.sun.xml.internal.bind.v2.model.core.ID;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.math.BigInteger;
import java.net.UnknownServiceException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadFactory;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.config.TinkConfig;

import java.io.IOException;
import java.security.GeneralSecurityException;
public class hss {
    public static void main(String[] args) throws GeneralSecurityException, IOException {
        // 基于默认配置进行注册
        TinkConfig.register();
        // 测试用的明文字符串
        BigInteger Id=new BigInteger(32,new Random());

        // 生成密钥
        KeysetHandle keysetHandle = KeysetHandle.generateNew(AesGcmKeyManager.aes128GcmTemplate());
        Aead aead = keysetHandle.getPrimitive(Aead.class);
        TypeACurveGenerator pg = new TypeACurveGenerator(160, 512);
        PairingParameters typeAParams = pg.generate();
        Pairing pairing = PairingFactory.getPairing(typeAParams);

        Element sk=pairing.getG1().newRandomElement().getImmutable();
        /*
         * 加密
         * 第一个参数是plaintext（明文）
         * 第二个参数是associatedData（相关数据）
         *     可以为null，相当于一个空（零长度）字节数组。
         *     同样，解密时必须提供同样的相关数据。
         */
        String sk_id=sk.toString().concat(Id.toString());
        byte[] head=new String("adad").getBytes();
        byte[] cipher = aead.encrypt(sk_id.getBytes(), head);
        long start=System.currentTimeMillis();
        long t1=0,t2=0;
        for(int i=0;i<1000;++i)
        {
            byte[] ciphertext = aead.encrypt(sk_id.getBytes(), head);
        }
        System.out.println(System.currentTimeMillis()-start);
        byte[] ciphertext = aead.encrypt(sk_id.getBytes(), head);
        start=System.currentTimeMillis();
        for(int i=0;i<1000;++i)
        {
            byte[] decrypted = aead.decrypt(ciphertext, head);
        }
        System.out.println(System.currentTimeMillis()-start);
        // 解密

    }

}