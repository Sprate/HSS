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
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.config.TinkConfig;

import java.io.IOException;
import java.security.GeneralSecurityException;
public class tt{
    public static int rBits = 160;
    public static int qBits = 512;

    public static byte hexToByte(String inHex){
        return (byte)Integer.parseInt(inHex,16);
    }
    public static byte[] hexToByteArray(String inHex){
        int hexlen = inHex.length();
        byte[] result;
        if (hexlen % 2 == 1){
            //奇数
            hexlen++;
            result = new byte[(hexlen/2)];
            inHex="0"+inHex;
        }else {
            //偶数
            result = new byte[(hexlen/2)];
        }
        int j=0;
        for (int i = 0; i < hexlen; i+=2){
            result[j]=hexToByte(inHex.substring(i,i+2));
            j++;
        }
        return result;
    }
    public static String getSha1(String str) {
        if (null == str || 0 == str.length()) {
            return null;
        }
        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                'a', 'b', 'c', 'd', 'e', 'f'};
        String buf = getString(str, hexDigits);
        if (buf != null) return buf;
        return null;
    }

    static String getString(String str, char[] hexDigits) {
        try {
            MessageDigest mdTemp = MessageDigest.getInstance("SHA1");
            mdTemp.update(str.getBytes("UTF-8"));

            byte[] md = mdTemp.digest();
            int j = md.length;
            char[] buf = new char[j * 2];
            int k = 0;
            for (int i = 0; i < j; i++) {
                byte byte0 = md[i];
                buf[k++] = hexDigits[byte0 >>> 4 & 0xf];
                buf[k++] = hexDigits[byte0 & 0xf];
            }
            return new String(buf);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }
    //Pairing pairing = PairingFactory.getPairing("params.properties");
    public static void main(String[]args) throws GeneralSecurityException {
        long t1=0,t2=0,t3=0,t4=0,t5=0,t6=0,t7=0,t8=0;
        long start=0;
        TinkConfig.register();
        KeysetHandle keysetHandle = KeysetHandle.generateNew(
               AeadKeyTemplates.AES128_GCM);

        Aead aead = keysetHandle.getPrimitive(Aead.class);
        String headhead=new String("asd");
        String plaintext=new String("12340");
        aead.encrypt(plaintext.getBytes(),headhead.getBytes());
        KeysetHandle keysetHandle2 = KeysetHandle.generateNew(
                AeadKeyTemplates.AES128_GCM);
        Aead aead2 = keysetHandle.getPrimitive(Aead.class);

        KeysetHandle keysetHandle3 = KeysetHandle.generateNew(
                AeadKeyTemplates.AES128_GCM);
        Aead aead3 = keysetHandle.getPrimitive(Aead.class);


        TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits);
        PairingParameters typeAParams = pg.generate();
        Pairing pairing = PairingFactory.getPairing(typeAParams);
//注册
        start=System.currentTimeMillis();
        for(int i=0;i<100;++i)
        {
            BigInteger IDu=new BigInteger(32,new Random());
            BigInteger IDcs=new BigInteger(32,new Random());
            System.out.println("IDu"+IDu);
            System.out.println("IDcs"+IDcs);
            Element s=pairing.getZr().newRandomElement().getImmutable();
            String pwd=new String("qwerasdfzxcv1996");
            Element sku=pairing.getG1().newElement().setFromHash(IDu.toByteArray(),0,IDu.toByteArray().length).powZn(s);
            Element ku=pairing.getZr().newRandomElement().getImmutable();
            System.out.println("用户注册sku计算完成时间"+(System.currentTimeMillis()-start));
            Element hash_pwd_ku=pairing.getG1().newElement().setFromHash(pwd.getBytes(),0,pwd.getBytes().length).powZn(ku);
            String rwd=getSha1(pwd.concat(hash_pwd_ku.toString()));
            byte[] head=new String("abc").getBytes();
            System.out.println("rwd 时间 "+(System.currentTimeMillis()-start));
            byte[] Cu=aead.encrypt(sku.toString().concat(IDu.toString()).getBytes(),head);
            //System.out.println(sku.toString().concat(IDu.toString()));
            System.out.println("用户注册时间为"+(System.currentTimeMillis()-start));
            Element skcs=pairing.getG1().newElement().setFromHash(IDcs.toByteArray(),0,IDcs.toByteArray().length).powZn(s);
            System.out.println("云服务器注册时间"+(System.currentTimeMillis()-start));
//认证
            Element a=pairing.getZr().newRandomElement().getImmutable();
            Element arf=pairing.getG1().newRandomElement().setFromHash(pwd.getBytes(),0,pwd.getBytes().length).powZn(a);
            Element beta=arf.powZn(ku);
            System.out.println("beta 时间"+(System.currentTimeMillis()-start));

            Element beta1=beta.powZn(pairing.getZr().newOneElement().div(a));
            //System.out.println("beta1 "+beta1);
            //System.out.println("hash pwd ku "+hash_pwd_ku);
            String rwd1=getSha1(pwd.concat(beta1.toString()));
            System.out.println("rwd'时间"+(System.currentTimeMillis()-start));
            String sku_IDu=new String(aead.decrypt(Cu,head));
            //System.out.println(sku_IDu);

            Element b=pairing.getZr().newRandomElement().getImmutable();
            Element x=pairing.getZr().newRandomElement().getImmutable();
            System.out.println("PSu计算前时间 "+(System.currentTimeMillis()-start));
            Element PSu=pairing.pairing(sku,pairing.getG1().newElement().setFromHash(IDcs.toByteArray(),0,IDcs.toByteArray().length)).powZn(x);
            //System.out.println("PSu "+PSu.toString());
            System.out.println( "pairing 时间 "+(System.currentTimeMillis()-start));
            Element g=pairing.getG1().newRandomElement().getImmutable();
            Element B=g.powZn(b);
            Element X=pairing.getG1().newElement().setFromHash(IDu.toByteArray(),0,IDu.toByteArray().length).powZn(x);
            String K1=getSha1(PSu.toString().concat(X.toString().concat(IDcs.toString())));
            byte[] Eu=aead2.encrypt(IDu.toString().concat(IDcs.toString().concat(B.toString().concat(x.toString()))).getBytes(),head);
            System.out.println("Eu 时间"+(System.currentTimeMillis()-start));

            Element PSu1=pairing.pairing(X,skcs);
            //System.out.println("PSu1" +PSu1.toString());

            String IDu_IDcs_B_x=new String(aead2.decrypt(Eu,head));
            //System.out.println(IDu_IDcs_B_x);
            System.out.println(X.isEqual(pairing.getG1().newElement().setFromHash(IDu.toByteArray(),0,IDu.toByteArray().length).powZn(x)));
            //String rwd1=getSha1(pwd.toString())
            System.out.println("检查X结束时间 "+(System.currentTimeMillis()-start));
            Element c=pairing.getZr().newRandomElement().getImmutable();
            Element y=pairing.getZr().newRandomElement().getImmutable();
            Element C=g.powZn(c);
            Element SKcs=B.powZn(c);
            Element PScs=pairing.pairing(skcs,pairing.getG1().newElement().setFromHash(IDu.toByteArray(),0,IDu.toByteArray().length)).powZn(y);
            //System.out.println("PScs "+PScs.toString());
            Element Y=pairing.getG1().newElement().setFromHash(IDcs.toByteArray(),0,IDcs.toByteArray().length).powZn(y);
            String K2=getSha1(PScs.toString().concat(Y.toString().concat(IDu.toString())));
            String Mcs=getSha1(SKcs.toString().concat(IDcs.toString().concat(IDu.toString())));
            //System.out.println("K2 "+K2);
            //System.out.println("MCS "+Mcs);
            byte[] Ecs=aead3.encrypt(IDcs.toString().concat(IDu.toString().concat(Mcs.concat(y.toString()))).getBytes(),head);
            //System.out.println("AE k2 "+IDcs.toString().concat(IDu.toString().concat(Mcs.concat(y.toString()))));
            System.out.println("ECS 时间为"+(System.currentTimeMillis()-start));

            Element SKu=C.powZn(b);
            String Mcs1=getSha1(SKu.toString().concat(IDcs.toString().concat(IDu.toString())));
            //System.out.println("Mcs1 "+Mcs1);
            Element PScs1=pairing.pairing(Y,sku);
            //System.out.println("PScs1 "+PScs1.toString());
            String K21=getSha1(PScs1.toString().concat(Y.toString().concat(IDu.toString())));
            //System.out.println("K2 1 "+K21);
            String IDcs_IDu_Mcs_y_1=new String(aead3.decrypt(Ecs,head));
            //System.out.println("AD k2 "+IDcs_IDu_Mcs_y_1);
            System.out.println(Y.isEqual(pairing.getG1().newElement().setFromHash(IDcs.toByteArray(),0,IDcs.toByteArray().length).powZn(y)));
            System.out.println("检查 Y 的时间为 "+(System.currentTimeMillis()-start));
        }
        System.out.println((System.currentTimeMillis()-start)/100);
    }




}
