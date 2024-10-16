package org.example;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.Security;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Base64;
import java.util.Timer;

//TIP 要<b>运行</b>代码，请按 <shortcut actionId="Run"/> 或
// 点击装订区域中的 <icon src="AllIcons.Actions.Execute"/> 图标。
public class Main {
    public static void Test1() throws Exception {
        BouncyCastleProvider bcp = new BouncyCastleProvider();
        Security.addProvider(bcp);
        UE x=new UE();
//        //这个没有写完，完整写完AKA很困难，
//        x.generate_SUCI("我是S1","我是S2");
        //SM2生成公私钥Demo,这个明天早上我也把它整到前端里面去
        SM2 sm2 = new SM2();
        sm2.generateKey();
        //密钥交换DEMO，明天早上我把它做到前端里面去
        SM2 demo=new SM2();
        demo.SM2ExchangeDemo();

        SM2sign test=new SM2sign();
        byte[] sign = test.sign();
        test.Verify(sign);
    }
    public static void Test2() throws Exception{
        SM2 sm2 = new SM2();
        AsymmetricCipherKeyPair testKey=sm2.generateKey();
        CipherParameters priv=testKey.getPrivate();
        CipherParameters pub=testKey.getPublic();
        byte[] signature = SM2sign.sign(priv, "LouisXVI".getBytes(), "l’etat, c’est moi".getBytes());
        System.out.println(SM2sign.verify(pub,"LouisXVI".getBytes(),"l’etat, c’est moi".getBytes(),signature));
        System.out.println(SM2sign.verify(pub,"Lia".getBytes(),"A E I O U".getBytes(),signature));

    }
    public static void Test3() throws Exception{
        long l = System.currentTimeMillis();
        System.out.println(l);
        byte[] bytes = SM2.longToBytes(l);
        System.out.println(SM2.bytesToLong(bytes));
return;
    }
    public static void InitDatabase() throws Exception{
        Class.forName("com.mysql.jdbc.Driver");

        Connection con= DriverManager.getConnection("jdbc:mysql://localhost:3306/test","root","123456");
        byte[] bytes = SM2.generateByteStream(15);
        String encode = Base64.getEncoder().encodeToString(bytes);
        //生成全部的公私钥对
        SM2 sm2 = new SM2();
        AsymmetricCipherKeyPair HNKey = sm2.generateKey();
        AsymmetricCipherKeyPair SNKey = sm2.generateKey();
        AsymmetricCipherKeyPair TPKey=sm2.generateKey();
        AsymmetricCipherKeyPair UEKey=sm2.generateKey();
        ECPublicKeyParameters HNPub = (ECPublicKeyParameters)HNKey.getPublic();
        ECPrivateKeyParameters HNPriv=(ECPrivateKeyParameters) HNKey.getPrivate();
        ECPublicKeyParameters SNPub = (ECPublicKeyParameters)SNKey.getPublic();
        ECPrivateKeyParameters SNPriv=(ECPrivateKeyParameters) SNKey.getPrivate();
        ECPublicKeyParameters UEPub = (ECPublicKeyParameters)UEKey.getPublic();
        ECPrivateKeyParameters UEPriv=(ECPrivateKeyParameters) UEKey.getPrivate();
        ECPublicKeyParameters TPPub = (ECPublicKeyParameters)TPKey.getPublic();
        ECPrivateKeyParameters TPPriv=(ECPrivateKeyParameters) TPKey.getPrivate();
        byte[] hnPub = HNPub.getQ().getEncoded(false);
        String hnPubStore=Base64.getEncoder().encodeToString(hnPub);
        String hnPrivStore=HNPriv.getD().toString();
        String snPubStore=Base64.getEncoder().encodeToString(SNPub.getQ().getEncoded(false));
        String snPrivStore=SNPriv.getD().toString();
        String uePubStore=Base64.getEncoder().encodeToString(UEPub.getQ().getEncoded(false));
        String uePrivStore=UEPriv.getD().toString();
        String tpPubStore=Base64.getEncoder().encodeToString(TPPub.getQ().getEncoded(false));
        String tpPrivStore=TPPriv.getD().toString();
            //清空过去用过的表格，每个机器里面应该都只有一个数据
        PreparedStatement ps = con.prepareStatement("DELETE FROM UE WHERE 1=1;");
        ps.execute();
        ps=con.prepareStatement("DELETE FROM SN WHERE 1=1;");
        ps.execute();
        ps=con.prepareStatement("DELETE FROM TP WHERE 1=1;");
        ps.execute();
        ps=con.prepareStatement("DELETE FROM HN WHERE 1=1;");
        ps.execute();
        ps=con.prepareStatement("insert into UE(id,TPPub,HNPub, UEPRIV, UEPUB, SNPUB) VALUES (1,'"+tpPubStore
                +"','"+hnPubStore+"','"+uePrivStore+"','"+uePubStore+"','"+snPubStore+"')");
        ps.execute();
        ps=con.prepareStatement("insert into HN(id,TPPub,HNPub, HNPRIV, UEPUB, SNPUB) VALUES (1,'"+tpPubStore
                    +"','"+hnPubStore+"','"+hnPrivStore+"','"+uePubStore+"','"+snPubStore+"')");
        ps.execute();
        ps=con.prepareStatement("insert into SN(id,TPPub,HNPub, SNPRIV, UEPUB, SNPUB) VALUES (1,'"+tpPubStore
                    +"','"+hnPubStore+"','"+snPrivStore+"','"+uePubStore+"','"+snPubStore+"')");
        ps.execute();
        ps=con.prepareStatement("insert into TP(id,TPPub,HNPub, TPPRIV, UEPUB, SNPUB) VALUES (1,'"+tpPubStore
                    +"','"+hnPubStore+"','"+tpPrivStore+"','"+uePubStore+"','"+snPubStore+"')");
        ps.execute();
        ps=con.prepareStatement("update SN set SNName=\"5GAKACHINAUECNU\" WHERE ID=1");
        ps.execute();
        con.close();
            return;

    }
    public static void main(String[] args) throws Exception{
//        PS：每次用之前先启动一下服务器，然后初始化一下再运行，密码是123456
        InitDatabase();
        UE x=new UE();
        x.gen_key_2();
        x.ask();
        TP t=new TP();
        HN s=new HN();
        System.out.println(t.VerifySign_1());
        System.out.println(s.VerifySign_2());
        System.out.println("c");
        x.calculateForUEFirstStep();
        SN sn=new SN();
        sn.VerifyCert1_Cert2();
        BigInteger KSN=sn.CalculateKSN();
        BigInteger KUE=x.UEsecondStep();
        System.out.println("KUE:"+KUE.toString());
        System.out.println("KSN:"+KSN.toString());
        SN.AskforRid();
        HN.FindRid();
        TP.RestoreRID();
        //身份追溯
//        Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "123456");
//        PreparedStatement ps=con.prepareStatement("select * from SN where CName=\"Hab\"");
//        ResultSet resultSet = ps.executeQuery();
//        System.out.println(resultSet.getRow());
//        while(resultSet.next()){
//            System.out.println(resultSet.getRow());
//        }
//        ps=con.prepareStatement("select COMMON from SN where CName=\"cert2SIGN\"");
//        ResultSet resultSet1 = ps.executeQuery();
//        while(resultSet1.next()){
//            System.out.println(resultSet1.getRow());
//        }
//        sn.CalculateKSN();
//        byte[] bytes = SM2.generateByteStream(256);
//        String AID_1 = Base64.getEncoder().encodeToString(bytes);
//        byte[] decode = Base64.getDecoder().decode(AID_1);
//        System.out.println(decode.length);
//        System.out.println(bytes.length);
//        System.out.println("Tempo");
//        SM2 sm2 = new SM2();
//        ECPrivateKeyParameters aPrivate = (ECPrivateKeyParameters) sm2.generateKey().getPrivate();
//        System.out.println(aPrivate.getD().toString());
//        byte[] byteArray = aPrivate.getD().toByteArray();
//        BigInteger bigInteger = new BigInteger(byteArray);
//        ECPrivateKeyParameters privateKeyParameters = sm2.RestorePriv(bigInteger);
//        System.out.println(SM2.compareECPrivateKeyParameters(privateKeyParameters,aPrivate));
//        ECPublicKeyParameters aPub=(ECPublicKeyParameters) sm2.generateKey().getPublic();
//        byte[] encoded = aPub.getQ().getEncoded(false);
//        ECPublicKeyParameters aPubRestore = sm2.RestorePub(encoded);
//        System.out.println(SM2.compareECPublicKeyParameters(aPub,aPubRestore));
//

//        Test2();
//        UE ue = new UE();
//        ue.gen_key();
//        ue.ask();
        //测试转换
//        SM2.SM2ExchangeDemo2();
       // SM2_convert.test();
//        SM2.SM2SelfExchangeDemo();
//            Main.Test2();
//        byte[] bytes = SM3.sm3Hash("sdfsd".getBytes());
//        System.out.println(bytes.length);
    }
}