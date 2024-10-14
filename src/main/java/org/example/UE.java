package org.example;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.SM2KeyExchange;
import org.bouncycastle.crypto.generators.KDF1BytesGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jcajce.provider.digest.SHA512;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.sql.*;
import java.util.*;

public class UE {
    AsymmetricCipherKeyPair A;
    AsymmetricCipherKeyPair B;

    public void setAPub(ECPublicKeyParameters APub) {
        this.APub = APub;
    }

    ECPublicKeyParameters APub;
    ECPublicKeyParameters BPub;
    AsymmetricCipherKeyPair UE;
    ECPublicKeyParameters PHN;
    ECPublicKeyParameters PSN;
    ECPublicKeyParameters PTP;
    SM2 sm2;
    byte[] RID;
    long timeStamp;
    byte[] AID_1;
    byte[] AID_2;
    UE() throws SQLException,ClassNotFoundException{
        this.sm2=new SM2();
        byte[] UEPUBbyte;
        byte[] UEPrivByte;
        byte[] SNPUBbyte;
        byte[] TPPUBbyte;
        byte[] HNPUBByte;
        Map<String, Object> sqlmap = autoSqlValue();
        UEPUBbyte= Base64.getDecoder().decode((String)sqlmap.get("UEPub"));
        UEPrivByte=Base64.getDecoder().decode((String)sqlmap.get("UEPRIV"));
        this.setUE(new AsymmetricCipherKeyPair(sm2.RestorePub(UEPUBbyte),sm2.RestorePriv(new BigInteger(UEPrivByte))));
        SNPUBbyte= Base64.getDecoder().decode((String)sqlmap.get("SNPub"));
        this.setPSN(sm2.RestorePub(SNPUBbyte));
        TPPUBbyte=Base64.getDecoder().decode((String)sqlmap.get("TPPub"));
        this.setPTP(sm2.RestorePub(TPPUBbyte));
        HNPUBByte=Base64.getDecoder().decode((String)sqlmap.get("HNPub"));
        this.setPHN(sm2.RestorePub(HNPUBByte));
    }
    public Map<String,Object> autoSqlValue() throws ClassNotFoundException, SQLException {
        Class.forName("com.mysql.jdbc.Driver");
        Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "123456");
        PreparedStatement ps = con.prepareStatement("select * from UE where id=1 ");
        ResultSet rs = ps.executeQuery();
        ResultSetMetaData metaData = rs.getMetaData();
        int columnCount = metaData.getColumnCount();
        Map<String, Object> columnValues = new HashMap<>();
        while (rs.next()) {
            for (int i = 1; i <= columnCount; i++) {
                String columnName = metaData.getColumnName(i);
                Object columnValue = rs.getObject(i);
                columnValues.put(columnName, columnValue);
            }
        }
        rs.close();
        con.close();

        return columnValues;
    }
    public byte[] getAID_1() {
        return AID_1;
    }

    public void setAID_1(byte[] AID_1) {
        this.AID_1 = AID_1;
    }

    public byte[] getAID_2() {
        return AID_2;
    }

    public void setAID_2(byte[] AID_2) {
        this.AID_2 = AID_2;
    }

    public long getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStamp(long timeStamp) {
        this.timeStamp = timeStamp;
    }

    public AsymmetricCipherKeyPair getA() {
        return A;
    }

    public void setA(AsymmetricCipherKeyPair a) {
        A = a;
    }

    public AsymmetricCipherKeyPair getB() {
        return B;
    }

    public void setB(AsymmetricCipherKeyPair b) {
        B = b;
    }

    public AsymmetricCipherKeyPair getUE() {
        return UE;
    }

    public void setUE(AsymmetricCipherKeyPair UE) {
        this.UE = UE;
    }

    public ECPublicKeyParameters getPHN() {
        return PHN;
    }

    public void setPHN(ECPublicKeyParameters PHN) {
        this.PHN = PHN;
    }

    public ECPublicKeyParameters getPSN() {
        return PSN;
    }

    public void setPSN(ECPublicKeyParameters PSN) {
        this.PSN = PSN;
    }

    public ECPublicKeyParameters getPTP() {
        return PTP;
    }

    public void setPTP(ECPublicKeyParameters PTP) {
        this.PTP = PTP;
    }

    public byte[] getRID() {
        return RID;
    }

    public void setRID(byte[] RID) {
        this.RID = RID;
    }
    public void gen_key_2() throws ClassNotFoundException, SQLException {
        this.sm2 = new SM2();
        Class.forName("com.mysql.jdbc.Driver");
//        byte[] UEPUBbyte;
//        byte[] UEPrivByte;
//        byte[] SNPUBbyte;
//        byte[] TPPUBbyte;
//        byte[] HNPUBByte;
//        Connection con= DriverManager.getConnection("jdbc:mysql://localhost:3306/test","root","123456");
//        PreparedStatement ps=con.prepareStatement("select UEPUB from UE where id=1 ");
//        ResultSet resultSet = ps.executeQuery();
//        ECPublicKeyParameters UEPub=null;
//        ECPrivateKeyParameters UEPriv=null;
//        while(resultSet.next()){
//            String uepub = resultSet.getString("UEPUB");
//            UEPub = sm2.RestorePub(Base64.getDecoder().decode(uepub));
//        }
//        ps=con.prepareStatement("select UEPRIV from UE where id=1 ");
//        resultSet = ps.executeQuery();
//        while(resultSet.next()){
//            String uepriv = resultSet.getString("UEPRIV");
//
//            UEPriv = sm2.RestorePriv(new BigInteger(Base64.getDecoder().decode(uepriv)));
//        }
//        this.setUE(new AsymmetricCipherKeyPair(UEPub,UEPriv));
//        ps=con.prepareStatement("select SNPUB from UE where id=1 ");
//        resultSet = ps.executeQuery();
//        while(resultSet.next()){
//            String uepriv = resultSet.getString("SNPUB");
//            ECPublicKeyParameters SNPUB = sm2.RestorePub(Base64.getDecoder().decode(uepriv));
//            this.setPSN(SNPUB);
//        }
//        ps=con.prepareStatement("select HNPUB from UE where id=1 ");
//        resultSet = ps.executeQuery();
//        while(resultSet.next()){
//            String uepriv = resultSet.getString("HNPUB");
//            ECPublicKeyParameters HNPUB = sm2.RestorePub(Base64.getDecoder().decode(uepriv));
//            this.setPHN(HNPUB);
//        }
//        ps=con.prepareStatement("select TPPUB from UE where id=1 ");
//        resultSet = ps.executeQuery();
//        while(resultSet.next()){
//            String uepriv = resultSet.getString("TPPUB");
//            ECPublicKeyParameters TPPUB = sm2.RestorePub(Base64.getDecoder().decode(uepriv));
//            this.setPTP(TPPUB);
//        }
        //生成一个65字节长度的RID
        this.RID=sm2.generateByteStream(65);
        Connection con= DriverManager.getConnection("jdbc:mysql://localhost:3306/test","root","123456");

        PreparedStatement ps = con.prepareStatement("UPDATE UE set RID=\"" + this.RID + "\" where id=1;");
        con.close();
    }
    public void gen_key(){
        this.sm2 = new SM2();
        //生成一个65字节长度的RID
        this.RID=sm2.generateByteStream(65);
        this.UE=sm2.generateKey();
        AsymmetricCipherKeyPair HN = sm2.generateKey();
        AsymmetricCipherKeyPair SN = sm2.generateKey();
        AsymmetricCipherKeyPair TP = sm2.generateKey();
        this.PHN=(ECPublicKeyParameters)HN.getPublic();
        this.PTP=(ECPublicKeyParameters) TP.getPublic();
        this.PSN=(ECPublicKeyParameters) SN.getPublic();
    }
    //UE请求凭证
    public void ask() throws Exception{
        //1步骤,算出C
        Connection con= DriverManager.getConnection("jdbc:mysql://localhost:3306/test","root","123456");
        this.RID=sm2.generateByteStream(65);

        AsymmetricCipherKeyPair temp = this.sm2.generateKey();
        //C的点的公共值
        ECPublicKeyParameters CPublic = (ECPublicKeyParameters)temp.getPublic();

        byte[] Cor = CPublic.getQ().getEncoded(false);
        //2步骤，计算中间值M
        byte[] M=SM2.xorByteArrays(Cor,RID);
        //3.选取两个随机数a,b计算A,B
        A=this.sm2.generateKey();
        B=this.sm2.generateKey();

        //4.计算两个假名
        ECCurve.Fp curve = this.sm2.getcurve();
        ECPrivateKeyParameters aPrivate = (ECPrivateKeyParameters) A.getPrivate();
        ECPrivateKeyParameters bPrivate = (ECPrivateKeyParameters) B.getPrivate();
        ECPublicKeyParameters aPublic = (ECPublicKeyParameters)A.getPublic();
        ECPublicKeyParameters bPublic = (ECPublicKeyParameters)B.getPublic();
        BigInteger aPrivBG = aPrivate.getD();
        BigInteger bPrivBG= bPrivate.getD();
//a*Ktp和b*Phn
        ECPoint amultiplyTPtemp = this.PTP.getQ().multiply(aPrivBG);
        ECPoint bmultiplyHNtemp = this.PHN.getQ().multiply(bPrivBG);
        byte[] Hktp = SM3.extendHash(amultiplyTPtemp.getEncoded(false), 65);
        byte[] Hkhn = SM3.extendHash(bmultiplyHNtemp.getEncoded(false),65);
        byte[] AID_1=SM2.xorByteArrays(M,Hktp);
        this.setAID_1(AID_1);

        byte[] AID_2=SM2.xorByteArrays(Cor,Hkhn);
        this.setAID_2(AID_2);
        //第五步：UE向TP和HN分别请求身份凭证
        //生成时间戳签名

        PreparedStatement ps=con.prepareStatement("UPDATE UE set AID_1=\""+Base64.getEncoder().encodeToString(this.AID_1)+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE UE set AID_2=\""+Base64.getEncoder().encodeToString(this.AID_2)+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE UE set RID=\""+Base64.getEncoder().encodeToString(this.RID)+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE UE set APRIV=\""+((ECPrivateKeyParameters) A.getPrivate()).getD().toString()+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE UE set BPRIV=\""+((ECPrivateKeyParameters) B.getPrivate()).getD().toString()+"\" where id=1;");
        ps.execute();
        // 获取当前时间的时间戳（毫秒）
        long timestamp = System.currentTimeMillis();
        this.setTimeStamp(timestamp);
        ps=con.prepareStatement("UPDATE UE set TimeSTAMP="+this.timeStamp+" where id=1;");
        ps.execute();
        byte[] timestampByte=SM2.longToBytes(timestamp);
        byte[] SignData1=SM2.byteMerger(AID_1,timestampByte,aPublic.getQ().getEncoded(false));
        byte[] SignData2=SM2.byteMerger(AID_2,timestampByte,bPublic.getQ().getEncoded(false));
        SM2sign sm2sign = new SM2sign();
        byte[] sign1 = sm2sign.sign(this.UE.getPrivate(), null, SignData1);
        byte[] sign2 = sm2sign.sign(this.UE.getPrivate(), null, SignData2);

        //向UE发送的内容
        Map<String, Object> ToTP = new HashMap<String, Object>(4);
        ps=con.prepareStatement("UPDATE TP set TimeSTAMPUE="+this.timeStamp+" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE TP set AID_1=\""+Base64.getEncoder().encodeToString(this.AID_1)+"\" where id=1;");
        ps.execute();
        String AString = Base64.getEncoder().encodeToString(aPublic.getQ().getEncoded(false));
        ps=con.prepareStatement("UPDATE TP set A=\""+AString+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE TP set SIGNDATA=\""+Base64.getEncoder().encodeToString(sign1)+"\" where id=1;");
        ps.execute();

        ToTP.put("AID1",AID_1);
        ToTP.put("timestamp",timestamp);
        ToTP.put("A",aPublic);
        ToTP.put("SignData",SignData1);
        //向HN发送的内容
        Map<String, Object> ToHN = new HashMap<String, Object>(4);
        ps=con.prepareStatement("UPDATE HN set TimeSTAMPUE="+this.timeStamp+" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE HN set AID_2=\""+Base64.getEncoder().encodeToString(this.AID_2)+"\" where id=1;");
        ps.execute();
        String BString = Base64.getEncoder().encodeToString(bPublic.getQ().getEncoded(false));
        ps=con.prepareStatement("UPDATE HN set B=\""+BString+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE HN set SIGNDATA=\""+Base64.getEncoder().encodeToString(sign2)+"\" where id=1;");
        ps.execute();
        ToHN.put("AID2",AID_2);
        ToHN.put("timestamp",timestampByte);
        ToHN.put("B",bPublic);
        ToHN.put("SignData",SignData2);
        ps.close();
        con.close();
    }


    public ECPublicKeyParameters getBPub() {
        return BPub;
    }

    public void setBPub(ECPublicKeyParameters BPub) {
        this.BPub = BPub;
    }

    public ECPublicKeyParameters getAPub() {
        return APub;
    }

    public void UE_ExchangeFirst() throws Exception {
        SM2 sm2 = new SM2();
        Map<String, Object> UEINFO = autoSqlValue();
        String a = (String) UEINFO.get("A");
        String b = (String) UEINFO.get("B");
        byte[] aB = Base64.getDecoder().decode(a);
        byte[] bB = Base64.getDecoder().decode(b);
        this.setBPub(sm2.RestorePub(bB));
        this.setAPub(sm2.RestorePub(aB));

        SM2KeyExchangeSelf exch = new SM2KeyExchangeSelf();
        exch.init(this.getUE().getPrivate());
        exch.calculateUEFirstStep(new ParametersWithID(this.getUE().getPublic(),null),new ParametersWithID(this.getPSN(),null),this.getA(),this.getB());
    }
}
