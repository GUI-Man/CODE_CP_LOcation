package org.example;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.agreement.SM2KeyExchange;
import org.bouncycastle.crypto.generators.KDF1BytesGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jcajce.provider.digest.SHA512;
import org.bouncycastle.math.ec.ECAlgorithms;
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

import static org.example.SM2KeyExchangeSelf.intToTwoBytes;

public class UE {
    AsymmetricCipherKeyPair A;
    AsymmetricCipherKeyPair B;
AsymmetricCipherKeyPair RA;
ECPublicKeyParameters RB;

    public AsymmetricCipherKeyPair getRA() {
        return RA;
    }

    public void setRA(AsymmetricCipherKeyPair RA) {
        this.RA = RA;
    }

    public ECPublicKeyParameters getRB() {
        return RB;
    }

    public void setRB(ECPublicKeyParameters RB) {
        this.RB = RB;
    }

    public void setAPub(ECPublicKeyParameters APub) {
        this.APub = APub;
    }

    ECPublicKeyParameters APub;
    ECPublicKeyParameters BPub;
    AsymmetricCipherKeyPair UE;
    ECPublicKeyParameters PHN;
    ECPublicKeyParameters PSN;
    ECPublicKeyParameters PTP;
    SM2 sm2 = new SM2();
    byte[] RID;
    long timeStamp;
    byte[] AID_1;
    byte[] AID_2;
    byte[] Cert1;
    byte[] Cert2;

    public byte[] getCert1() {
        return Cert1;
    }

    public void setCert1(byte[] cert1) {
        Cert1 = cert1;
    }

    public byte[] getCert2() {
        return Cert2;
    }

    public void setCert2(byte[] cert2) {
        Cert2 = cert2;
    }

    UE() throws SQLException,ClassNotFoundException{
        byte[] UEPUBbyte;
        String UEPrivByte;
        byte[] SNPUBbyte;
        byte[] TPPUBbyte;
        byte[] HNPUBByte;
        Map<String, Object> sqlmap = autoSqlValue();
        UEPUBbyte= Base64.getDecoder().decode((String)sqlmap.get("UEPub"));
        UEPrivByte=(String)sqlmap.get("UEPRIV");
        this.setUE(new AsymmetricCipherKeyPair(sm2.RestorePub(UEPUBbyte),sm2.RestorePriv(new BigInteger(UEPrivByte))));
        SNPUBbyte= Base64.getDecoder().decode((String)sqlmap.get("SNPub"));
        this.setPSN(sm2.RestorePub(SNPUBbyte));
        TPPUBbyte=Base64.getDecoder().decode((String)sqlmap.get("TPPub"));
        this.setPTP(sm2.RestorePub(TPPUBbyte));
        HNPUBByte=Base64.getDecoder().decode((String)sqlmap.get("HNPub"));
        this.setPHN(sm2.RestorePub(HNPUBByte));
    }
    public static Map<String,Object> autoSqlValue() throws ClassNotFoundException, SQLException {
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
    public static void gen_key_2() throws ClassNotFoundException, SQLException {
        SM2 sm2 = new SM2();
        Class.forName("com.mysql.jdbc.Driver");
        //生成一个65字节长度的RID
        byte[] RID=sm2.generateByteStream(65);
        Connection con= DriverManager.getConnection("jdbc:mysql://localhost:3306/test","root","123456");

        PreparedStatement ps = con.prepareStatement("UPDATE UE set RID=\"" +Base64.getEncoder().encodeToString( RID) + "\" where id=1;");
        ps.execute();
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
    public static void ask() throws Exception{

        //1步骤,算出C
        SM2 sm2 = new SM2();
        Connection con= DriverManager.getConnection("jdbc:mysql://localhost:3306/test","root","123456");
        Map<String, Object> sqlValue = autoSqlValue();
        //事先从数据库获取所有的PTP PHN PSN PUE
        ECPublicKeyParameters PTP=sm2.RestorePub(Base64.getDecoder().decode( (String)sqlValue.get("TPPub")));
        ECPublicKeyParameters PHN=sm2.RestorePub(Base64.getDecoder().decode( (String)sqlValue.get("HNPub")));
        ECPrivateKeyParameters UEPriv=sm2.RestorePriv(new BigInteger((String) sqlValue.get("UEPRIV")));
        byte[] RID=Base64.getDecoder().decode((String)sqlValue.get("RID"));
        System.out.println("原来的真实身份是:"+Base64.getEncoder().encodeToString(RID));
        AsymmetricCipherKeyPair temp = sm2.generateKey();
        //C的点的公共值
        ECPublicKeyParameters CPublic = (ECPublicKeyParameters)temp.getPublic();

        byte[] Cor = CPublic.getQ().getEncoded(false);
        System.out.println("C在生成阶段是"+Base64.getEncoder().encodeToString(Cor));
        //2步骤，计算中间值M
        byte[] M=SM2.xorByteArrays(Cor,RID);
        //3.选取两个随机数a,b计算A,B

        AsymmetricCipherKeyPair A=sm2.generateKey();
        AsymmetricCipherKeyPair B=sm2.generateKey();

        //4.计算两个假名
        ECCurve.Fp curve = sm2.getcurve();
        ECPrivateKeyParameters aPrivate = (ECPrivateKeyParameters) A.getPrivate();
        ECPrivateKeyParameters bPrivate = (ECPrivateKeyParameters) B.getPrivate();
        ECPublicKeyParameters aPublic = (ECPublicKeyParameters)A.getPublic();
        ECPublicKeyParameters bPublic = (ECPublicKeyParameters)B.getPublic();
        BigInteger aPrivBG = aPrivate.getD();
        BigInteger bPrivBG= bPrivate.getD();
//a*Ktp和b*Phn
        ECPoint amultiplyTPtemp = PTP.getQ().multiply(aPrivBG).normalize();
        ECPoint bmultiplyHNtemp = PHN.getQ().multiply(bPrivBG).normalize();
        byte[] Hktp = SM3.extendHash(amultiplyTPtemp.getEncoded(false), 65);
        System.out.println("HKTP在生成阶段是："+Base64.getEncoder().encodeToString(Hktp));
        byte[] Hkhn = SM3.extendHash(bmultiplyHNtemp.getEncoded(false),65);
        System.out.println("HKHN在生成阶段是："+Base64.getEncoder().encodeToString(Hkhn));
        byte[] AID_1=SM2.xorByteArrays(M,Hktp);
//        this.setAID_1(AID_1);

        byte[] AID_2=SM2.xorByteArrays(Cor,Hkhn);
//        this.setAID_2(AID_2);
        //第五步：UE向TP和HN分别请求身份凭证
        //生成时间戳签名

        PreparedStatement ps=con.prepareStatement("UPDATE UE set AID_1=\""+Base64.getEncoder().encodeToString(AID_1)+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE SN set AID_1=\""+Base64.getEncoder().encodeToString(AID_1)+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE UE set AID_2=\""+Base64.getEncoder().encodeToString(AID_2)+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE SN set AID_2=\""+Base64.getEncoder().encodeToString(AID_2)+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE UE set RID=\""+Base64.getEncoder().encodeToString(RID)+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE UE set APRIV=\""+((ECPrivateKeyParameters) A.getPrivate()).getD().toString()+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE UE set BPRIV=\""+((ECPrivateKeyParameters) B.getPrivate()).getD().toString()+"\" where id=1;");
        ps.execute();
        // 获取当前时间的时间戳（毫秒）
        long timestamp = System.currentTimeMillis();
//        this.setTimeStamp(timestamp);
        ps=con.prepareStatement("UPDATE UE set TimeSTAMP="+timestamp+" where id=1;");
        ps.execute();
        byte[] timestampByte=SM2.longToBytes(timestamp);
        byte[] SignData1=SM2.byteMerger(AID_1,timestampByte,aPublic.getQ().getEncoded(false));
        byte[] SignData2=SM2.byteMerger(AID_2,timestampByte,bPublic.getQ().getEncoded(false));
        SM2sign sm2sign = new SM2sign();
        byte[] sign1 = sm2sign.sign(UEPriv, null, SignData1);
        byte[] sign2 = sm2sign.sign(UEPriv, null, SignData2);

        //向UE发送的内容
        Map<String, Object> ToTP = new HashMap<String, Object>(4);
        ps=con.prepareStatement("UPDATE TP set TimeSTAMPUE="+timestamp+" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE TP set AID_1=\""+Base64.getEncoder().encodeToString(AID_1)+"\" where id=1;");
        ps.execute();
        String AString = Base64.getEncoder().encodeToString(aPublic.getQ().getEncoded(false));
        ps=con.prepareStatement("UPDATE TP set A=\""+AString+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE UE set A=\""+AString+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE SN set A=\""+AString+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE TP set SIGNDATA=\""+Base64.getEncoder().encodeToString(sign1)+"\" where id=1;");
        ps.execute();

        ToTP.put("AID1",AID_1);
        ToTP.put("timestamp",timestamp);
        ToTP.put("A",aPublic);
        ToTP.put("SignData",SignData1);
        //向HN发送的内容
        Map<String, Object> ToHN = new HashMap<String, Object>(4);
        ps=con.prepareStatement("UPDATE HN set TimeSTAMPUE="+timestamp+" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE HN set AID_2=\""+Base64.getEncoder().encodeToString(AID_2)+"\" where id=1;");
        ps.execute();
        String BString = Base64.getEncoder().encodeToString(bPublic.getQ().getEncoded(false));
        ps=con.prepareStatement("UPDATE HN set B=\""+BString+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE SN set B=\""+BString+"\" where id=1;");
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
    //计算出w
    private int w;
    private BigInteger H;
    private BigInteger t;
    public void CalculatewAndH(){
        SM2 sm2=new SM2();
        sm2.getcurve();
        ECDomainParameters ecParams= sm2.domainParams;
        this.w = ecParams.getCurve().getFieldSize() / 2 - 1;
        this.H=ecParams.getH();
    }
    //计算ta,d是长期私钥，x是x头上一划，r是临时私钥
    public void CalcuateT(ECPrivateKeyParameters d,BigInteger x,ECPrivateKeyParameters r){
        this.t=d.getD().add(x.multiply(r.getD()));
    }
    //计算出x2头上一划
    public static BigInteger reduce(BigInteger var1,int w) {
        return var1.and(BigInteger.valueOf(1L).shiftLeft(w).subtract(BigInteger.valueOf(1L))).setBit(w);
    }
    //BPubTemp可以理解为RB,同理RATEMP也可以理解为RA,特注这里的A是SN的临时公私钥,这里的B是UE发过去的,是UE的临时公私钥对
    public static ArrayList<byte[]> calculateForUEFirstStep() throws Exception {
        //var3用于记载公钥中的信息,var3和var3_1事实上是一样的，var3是UE的公钥信息，var3_1是SN的公钥信息，此处为了方便显示
        //获取CERT1,CERT2
        SM2 sm2 = new SM2();
        Connection con= DriverManager.getConnection("jdbc:mysql://localhost:3306/test","root","123456");
        Map<String, Object> sqlValue = autoSqlValue();
        //拿到自己的UE,PSN,PHN
        ECPublicKeyParameters PTP=sm2.RestorePub(Base64.getDecoder().decode( (String)sqlValue.get("TPPub")));
        ECPublicKeyParameters PHN=sm2.RestorePub(Base64.getDecoder().decode( (String)sqlValue.get("HNPub")));
        ECPublicKeyParameters PSN=sm2.RestorePub(Base64.getDecoder().decode( (String)sqlValue.get("SNPub")));
        ECPublicKeyParameters PUE=sm2.RestorePub(Base64.getDecoder().decode( (String)sqlValue.get("UEPub")));

        ECPrivateKeyParameters UEPriv=sm2.RestorePriv(new BigInteger((String) sqlValue.get("UEPRIV")));

        byte[] cert1 =Base64.getDecoder().decode((String)sqlValue.get("CERT1SIGN"));
        byte[] cert2 = Base64.getDecoder().decode((String)sqlValue.get("CERT2SIGN"));
        PreparedStatement ps = con.prepareStatement("select SNName From SN where id=1");
        ResultSet rs = ps.executeQuery();
        String SSNname=null;
        while(rs.next()){
            SSNname=rs.getString("SNName");
        }

        byte[] SNname = SSNname.getBytes();
        //this.setCert1(cert1);
        //this.setCert2(cert2);
        byte[] AID,AID_1 = new byte[0],AID_2 = new byte[0];
        ps=con.prepareStatement("select AID_1 from tp where id=1");
        rs=ps.executeQuery();
        while(rs.next()){
            AID_1=Base64.getDecoder().decode(rs.getString("AID_1"));
        }
        ps=con.prepareStatement("select AID_2 from hn where id=1");
        rs=ps.executeQuery();
        while(rs.next()){
            AID_2=Base64.getDecoder().decode(rs.getString("AID_2"));
        }
        AID= SM2.byteMerger(AID_1,AID_2);

        //byte[] Zue=this.getZ(this.digest, AID, var3.getStaticPublicKey().getQ());
        //byte[] Zsn=this.getZ(this.digest,AID,var3_1.getStaticPublicKey().getQ());
        //生成ENTLue,ENTLsn，即AID
        byte[] ENTLue=intToTwoBytes(AID.length);
        byte[] ENTLsn=intToTwoBytes(SNname.length);
        //a

        byte[] a=sm2.getcurve().getA().getEncoded();
        byte[] b=sm2.getcurve().getB().getEncoded();
        byte[] gx=sm2.domainParams.getG().getAffineXCoord().getEncoded();
        byte[] gy=sm2.domainParams.getG().getAffineYCoord().getEncoded();
        //ECPublicKeyParameters ueKey = PUE;
        //ECPublicKeyParameters ueSn=PSN;
        byte[] xue=PUE.getQ().getAffineXCoord().getEncoded();
        byte[] yue=PUE.getQ().getAffineYCoord().getEncoded();
        byte[] xsn=PSN.getQ().getAffineXCoord().getEncoded();
        byte[] ysn=PSN.getQ().getAffineYCoord().getEncoded();
        byte[] Zue=SM3.sm3Hash(SM2.byteMerger(ENTLue,AID,a,b,gx,gy,xue,yue));
        byte[] Zsn=SM3.sm3Hash(SM2.byteMerger(ENTLsn,SNname,a,b,gx,gy,xsn,ysn));

        ps = con.prepareStatement("UPDATE SN SET ZUE=\"" + Base64.getEncoder().encodeToString(Zue) + "\" where id=1");
        ps.execute();
        ps = con.prepareStatement("UPDATE UE SET ZUE=\"" + Base64.getEncoder().encodeToString(Zue) + "\" where id=1");
        ps.execute();
        ps = con.prepareStatement("UPDATE SN SET ZSN=\"" + Base64.getEncoder().encodeToString(Zsn) + "\" where id=1");
        ps.execute();
        ps = con.prepareStatement("UPDATE UE SET ZSN=\"" + Base64.getEncoder().encodeToString(Zsn) + "\" where id=1");
        ps.execute();
        //生成Ra
        AsymmetricCipherKeyPair RaKeyPair = sm2.generateKey();
        //将Ra的公钥转换为字符串
        ECPublicKeyParameters temppublic = (ECPublicKeyParameters) RaKeyPair.getPublic();
        ECPrivateKeyParameters RaPrivate = (ECPrivateKeyParameters) RaKeyPair.getPrivate();
        byte[] bRa=temppublic.getQ().getEncoded(false);
        ps = con.prepareStatement("UPDATE SN SET RA=\"" + Base64.getEncoder().encodeToString(bRa) + "\" where id=1");
        ps.execute();
        ps = con.prepareStatement("UPDATE UE SET RA=\"" + Base64.getEncoder().encodeToString(bRa) + "\" where id=1");
        ps.execute();
        ps = con.prepareStatement("UPDATE UE SET RAPRIV=\"" + RaPrivate.getD().toString() + "\" where id=1");
        ps.execute();
        //拿到A和B公钥和私钥
        String APubString = (String) sqlValue.get("A");
        String BPubString = (String) sqlValue.get("B");
        String APrivString = (String) sqlValue.get("aPriv");
        String BPrivString = (String) sqlValue.get("bPriv");
        ECPublicKeyParameters APublic = sm2.RestorePub(Base64.getDecoder().decode(APubString));
        ECPublicKeyParameters BPublic=sm2.RestorePub(Base64.getDecoder().decode(BPubString));
        ECPrivateKeyParameters APrivate=sm2.RestorePriv(new BigInteger(APrivString));
        ECPrivateKeyParameters BPrivate=sm2.RestorePriv(new BigInteger(BPrivString));
        AsymmetricCipherKeyPair A = new AsymmetricCipherKeyPair(APublic, APrivate);
        AsymmetricCipherKeyPair B = new AsymmetricCipherKeyPair(BPublic, BPrivate);
        //把哈希值A,B补上，明天
        byte[] U1SignData = SM3.sm3Hash(SM2.byteMerger(Zue, Zsn, bRa, APublic.getQ().getEncoded(false)));
        byte[] U2SignData=SM3.sm3Hash(SM2.byteMerger(Zue,Zsn,bRa,BPublic.getQ().getEncoded(false)));
        byte[] U1sign = SM2sign.sign((CipherParameters) A.getPrivate(), null, U1SignData);
        byte[] U2sign=SM2sign.sign((CipherParameters)B.getPrivate(),null,U2SignData);
        ArrayList<byte[]> result = new ArrayList<byte[]>();
        result.add(U1sign);
        result.add(U2sign);
        ps=con.prepareStatement("UPDATE SN set SIGNU1=\""+Base64.getEncoder().encodeToString(U1sign)+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("UPDATE SN set SIGNU2=\""+Base64.getEncoder().encodeToString(U2sign)+"\" where id=1;");
        ps.execute();
        ps=con.prepareStatement("insert into SN(CName,COMMON) values(\"U1SignData\",\""
                +Base64.getEncoder().encodeToString(U1SignData)
                +"\");");
        ps.execute();
        ps=con.prepareStatement("insert into SN(CName,COMMON) values(\"U2SignData\",\""
                +Base64.getEncoder().encodeToString(U2SignData)
                +"\");");
        ps.execute();
        //发送CERT1和CERT2给SN
        String cert1SIGN = (String) sqlValue.get("CERT1SIGN");
        String cert2SIGN = (String) sqlValue.get("CERT2SIGN");
        ps=con.prepareStatement("insert into SN(CName,COMMON) values(\"cert1SIGN\",\""
                +cert1SIGN
                +"\");");
        ps.execute();
        ps=con.prepareStatement("insert into SN(CName,COMMON) values(\"cert2SIGN\",\""
                +cert2SIGN
                +"\");");
        ps.execute();
        //将CERT,U1SIGN,U2SIGN和RA都发给
        return result;
    }
    public static BigInteger UEsecondStep() throws Exception {
        SM2 sm2 = new SM2();
        Map<String, Object> stringObjectMap = org.example.UE.autoSqlValue();
        //获取PSN，PUN,PHN,PUE
        ECPublicKeyParameters PUE=sm2.RestorePub(Base64.getDecoder().decode( (String)stringObjectMap.get("UEPub")));
        ECPublicKeyParameters PSN=sm2.RestorePub(Base64.getDecoder().decode( (String)stringObjectMap.get("SNPub")));
        ECPublicKeyParameters PHN=sm2.RestorePub(Base64.getDecoder().decode( (String)stringObjectMap.get("HNPub")));

        ECPrivateKeyParameters UEPRIV=sm2.RestorePriv(new BigInteger((String)stringObjectMap.get("UEPRIV")));

        byte[] ra = Base64.getDecoder().decode((String) stringObjectMap.get("RA"));
        byte[] rb = Base64.getDecoder().decode((String) stringObjectMap.get("RB"));
        byte[] Ab = Base64.getDecoder().decode((String) stringObjectMap.get("A"));
        byte[] Bb = Base64.getDecoder().decode((String) stringObjectMap.get("B"));
        byte[] ZUE = Base64.getDecoder().decode((String) stringObjectMap.get("ZUE"));
        byte[] ZSN = Base64.getDecoder().decode((String) stringObjectMap.get("ZSN"));
        String RaPriv=(String) stringObjectMap.get("RAPriv");
        String aPriv=(String) stringObjectMap.get("aPriv");
        ECPrivateKeyParameters RaPrivateKey=sm2.RestorePriv(new BigInteger(RaPriv));
        ECPrivateKeyParameters aPrivateKey=sm2.RestorePriv(new BigInteger(aPriv));

        ECPublicKeyParameters RA = sm2.RestorePub(ra);
        ECPublicKeyParameters RB = sm2.RestorePub(rb);
        byte[] verifyByte = SM3.sm3Hash(SM2.byteMerger(ZUE, ZSN, ra, rb, Ab, Bb));
        //获取SN给的签名
        Connection con= DriverManager.getConnection("jdbc:mysql://localhost:3306/test","root","123456");
        PreparedStatement ps = con.prepareStatement("select COMMON from UE where CNAME=\"SIGNSN\"");
        ResultSet rs = ps.executeQuery();
        byte[] SIGNSN=null;
        while(rs.next()){
            String common = rs.getString("COMMON");
            SIGNSN = Base64.getDecoder().decode(common);
        }
        if(SM2sign.verify(PSN,null,verifyByte,SIGNSN)==false){
            System.out.println("SN验证失败");
            return BigInteger.valueOf(0);
        }else{
            System.out.println("SN验证成功");
            sm2.getcurve();
            ECDomainParameters ecParams= sm2.domainParams;
            int w = ecParams.getCurve().getFieldSize() / 2 - 1;
            BigInteger H=ecParams.getH();
            //计算x1_,x2_
            BigInteger x1_= org.example.UE.reduce(RA.getQ().getAffineXCoord().toBigInteger(),w);
            BigInteger x2_= org.example.UE.reduce(RB.getQ().getAffineXCoord().toBigInteger(),w);
            //ECPrivateKeyParameters RAPriv= (ECPrivateKeyParameters) this.RA.getPrivate();
            //ECPrivateKeyParameters aPrivate = (ECPrivateKeyParameters)this.UE.getPrivate();
            BigInteger tA=aPrivateKey.getD().add(x1_.multiply(RaPrivateKey.getD()));
            ECPoint RBPoint = ECAlgorithms.cleanPoint(sm2.getcurve(), RB.getQ());
            //ta*H
            BigInteger var8=sm2.domainParams.getH().multiply(tA).mod(sm2.domainParams.getN());
            //
            BigInteger var9=var8.multiply(x2_).mod(sm2.domainParams.getN());
            ECPoint U=ECAlgorithms.sumOfTwoMultiplies(PSN.getQ(),var8,RBPoint,var9).normalize();
            return SN.KDF(U,ZUE,ZSN);
        }
    }
//    public void UE_ExchangeFirst() throws Exception {
//        //获取CERT1,CERT2
//        Map<String, Object> sqlValue = this.autoSqlValue();
//        byte[] cert1 =Base64.getDecoder().decode((String)sqlValue.get("CERT1SIGN"));
//        byte[] cert2 = Base64.getDecoder().decode((String)sqlValue.get("CERT2SIGN"));
//        this.setCert1(cert1);
//        this.setCert2(cert2);
//        SM2 sm2 = new SM2();
//        Map<String, Object> UEINFO = autoSqlValue();
//        String a = (String) UEINFO.get("A");
//        String b = (String) UEINFO.get("B");
//        byte[] aB = Base64.getDecoder().decode(a);
//        byte[] bB = Base64.getDecoder().decode(b);
//        this.setBPub(sm2.RestorePub(bB));
//        this.setAPub(sm2.RestorePub(aB));
//
//        SM2KeyExchangeSelf exch = new SM2KeyExchangeSelf();
//        //
//    }
}
