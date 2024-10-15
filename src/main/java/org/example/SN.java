package org.example;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.symmetric.ARC4;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.spec.ECParameterSpec;
import java.sql.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static com.mysql.cj.conf.PropertyKey.logger;
import static org.example.SM2KeyExchangeSelf.intToTwoBytes;

public class SN {

    AsymmetricCipherKeyPair SN;
    ECPublicKeyParameters PUE;
    ECPublicKeyParameters PTP;
    ECPublicKeyParameters PHN;
    ECPublicKeyParameters A;

    public AsymmetricCipherKeyPair getRB() {
        return RB;
    }

    public void setRB(AsymmetricCipherKeyPair RB) {
        this.RB = RB;
    }

    public ECPublicKeyParameters getRA() {
        return RA;
    }

    public void setRA(ECPublicKeyParameters RA) {
        this.RA = RA;
    }

    AsymmetricCipherKeyPair RB;
    ECPublicKeyParameters RA;
    public ECPublicKeyParameters getB() {
        return B;
    }

    public void setB(ECPublicKeyParameters b) {
        B = b;
    }

    public ECPublicKeyParameters getA() {
        return A;
    }

    public void setA(ECPublicKeyParameters a) {
        A = a;
    }

    ECPublicKeyParameters B;

    public ECPublicKeyParameters getPHN() {
        return PHN;
    }

    public void setPHN(ECPublicKeyParameters PHN) {
        this.PHN = PHN;
    }

    byte[] ZUE,ZSN;
    SN() throws SQLException,ClassNotFoundException{
        this.sm2=new SM2();
        byte[] UEPUBbyte;
        byte[] SNPrivByte;
        byte[] SNPUBbyte;
        byte[] TPPUBbyte;
        byte[] HNPUBByte;
        Map<String, Object> sqlmap = autoSqlValue();
        SNPUBbyte= Base64.getDecoder().decode((String)sqlmap.get("SNPub"));
        SNPrivByte=Base64.getDecoder().decode((String)sqlmap.get("SNPriv"));
        this.setSN(new AsymmetricCipherKeyPair(sm2.RestorePub(SNPUBbyte),sm2.RestorePriv(new BigInteger(SNPrivByte))));
        TPPUBbyte= Base64.getDecoder().decode((String)sqlmap.get("TPPub"));
        this.setPTP(sm2.RestorePub(TPPUBbyte));
        UEPUBbyte=Base64.getDecoder().decode((String)sqlmap.get("UEPub"));
        this.setPUE(sm2.RestorePub(UEPUBbyte));
        HNPUBByte=Base64.getDecoder().decode((String)sqlmap.get("HNPub"));
        this.setPHN(sm2.RestorePub(HNPUBByte));
    }
    public Map<String,Object> autoSqlValue() throws ClassNotFoundException, SQLException {
        Class.forName("com.mysql.jdbc.Driver");
        Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "123456");
        PreparedStatement ps = con.prepareStatement("select * from SN where id=1 ");
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
    public byte[] getZUE() {
        return ZUE;
    }

    public void setZUE(byte[] ZUE) {
        this.ZUE = ZUE;
    }

    public byte[] getZSN() {
        return ZSN;
    }

    public void setZSN(byte[] ZSN) {
        this.ZSN = ZSN;
    }

    SM2 sm2;
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
    public void CalcuateT(ECPrivateKeyParameters d, BigInteger x, ECPrivateKeyParameters r){
        this.t=d.getD().add(x.multiply(r.getD()));
    }
    //计算出x2头上一划
    private BigInteger reduce(BigInteger var1) {
        return var1.and(BigInteger.valueOf(1L).shiftLeft(this.w).subtract(BigInteger.valueOf(1L))).setBit(this.w);
    }
    //BPubTemp可以理解为RB,同理RATEMP也可以理解为RA,特注这里的A是SN的临时公私钥,这里的B是UE发过去的,是UE的临时公私钥对
    //this.calculateUForSN(RA, this.PHN, this.SN, this.RB);
    private ECPoint calculateUForSN(ECPublicKeyParameters UEPubTemp, ECPublicKeyParameters UEPub, AsymmetricCipherKeyPair SN, AsymmetricCipherKeyPair SNTemp) throws Exception {
        SM2 sm2 = new SM2();
        sm2.getcurve();
        CalculatewAndH();
        //aPrivate的x点就是x1
        ECPrivateKeyParameters SNPrivate = (ECPrivateKeyParameters) (SN.getPrivate());
        ECPrivateKeyParameters tempSNPrivate = (ECPrivateKeyParameters) (SNTemp.getPrivate());
        ECPublicKeyParameters SNPublic=(ECPublicKeyParameters)(SN.getPublic());
        ECPublicKeyParameters SNTempPublic=(ECPublicKeyParameters)(SNTemp.getPublic());
        ECDomainParameters var2 = sm2.domainParams;
        //检查这两个是不是在一个电商，顺便说明一下，这一步还有个隐藏效果是把压缩的点变成了没压缩的
        ECPoint UEPubQ = ECAlgorithms.cleanPoint(var2.getCurve(), UEPub.getQ());
        ECPoint UEPubTempQ = ECAlgorithms.cleanPoint(var2.getCurve(), UEPubTemp.getQ());
        BigInteger x2_ = this.reduce(SNTempPublic.getQ().getAffineXCoord().toBigInteger());
        BigInteger x1_ = this.reduce(UEPubTemp.getQ().getAffineXCoord().toBigInteger());
        //算出了tB
        BigInteger tB = SNPrivate.getD().add(x2_.multiply(tempSNPrivate.getD()));
        //算出tb*h
        BigInteger var8 = var2.getH().multiply(tB).mod(var2.getN());
        //算出tb*h和x1_的乘积
        BigInteger var9 = var8.multiply(x1_).mod(var2.getN());

        return ECAlgorithms.sumOfTwoMultiplies(UEPub.getQ(), var8,UEPubTemp.getQ(), var9).normalize();
    }
    /**
     * 生成 EC 私钥 D 的导出算法
     *
     * @param ecPointV 椭圆曲线的 ECPointV
     * @param byteArray1 第一个 byte[] 数组
     * @param byteArray2 第二个 byte[] 数组
     * @return 生成的私钥 D
     * @throws Exception 如果有任何错误
     */
    public static BigInteger KDF(ECPoint ecPointV, byte[] byteArray1, byte[] byteArray2) throws Exception {
        // 记录输入参数日志
        System.out.println("开始生成 EC 私钥 D");
        System.out.println("ECPointV: " + ecPointV);
        System.out.println("byteArray1: " + Hex.toHexString(byteArray1));
        System.out.println("byteArray2: " + Hex.toHexString(byteArray2));
        SM2 sm2 = new SM2();
//        sm2.getcurve()
//        // 获取椭圆曲线参数（比如 secp256k1，可以根据需要替换）
//        ECParameterSpec ecSpec = ;
//        if (ecSpec == null) {
//            throw new IllegalArgumentException("无法获取椭圆曲线参数");
//        }

        System.out.println("使用的椭圆曲线:SM2标准 " );

        // 假设这里的私钥导出算法是基于两个 byte[] 的 Hash 结合
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        // 计算第一个 byte[] 的哈希
        sha256.update(byteArray1);
        byte[] hash1 = sha256.digest();
        System.out.println("第一个 byte[] 的哈希值: " + Hex.toHexString(hash1));

        // 计算第二个 byte[] 的哈希
        sha256.update(byteArray2);
        byte[] hash2 = sha256.digest();
        System.out.println("第二个 byte[] 的哈希值: " + Hex.toHexString(hash2));

        // 将两个哈希值结合生成最终的私钥 D
        BigInteger combinedHash = new BigInteger(1, hash1).add(new BigInteger(1, hash2)).mod(sm2.domainParams.getN());
        System.out.println(("生成的私钥 D (BigInteger): " + combinedHash.toString(16)));

        // 将 ECPoint V 与私钥 D 进行进一步运算（如果需要）
        ECPoint derivedPoint = ecPointV.multiply(combinedHash);
        System.out.println(("基于私钥 D 生成的 ECPoint: " + derivedPoint));

        return combinedHash; // 返回生成的私钥 D
    }
    public Boolean VerifyCert1_Cert2() throws SQLException, ClassNotFoundException {
        //检验U1，U2签名
        SM2 sm2=new SM2();
        Map<String, Object> sqlValue = autoSqlValue();
        byte[] signu1 =Base64.getDecoder().decode ((String)sqlValue.get("SIGNU1"));
        byte[] signu2 = Base64.getDecoder().decode ((String)sqlValue.get("SIGNU2"));
        byte[] signu1Data =null;
        byte[] signu2Data =null;
        //获取签名的公钥A和B
        ECPublicKeyParameters APub = sm2.RestorePub(Base64.getDecoder().decode((String) sqlValue.get("A")));
        ECPublicKeyParameters BPub = sm2.RestorePub(Base64.getDecoder().decode((String) sqlValue.get("B")));

        Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "123456");
        PreparedStatement ps = con.prepareStatement("select COMMON from SN where CNAME=\"U1SIGNDATA\" ");
        ResultSet rs = ps.executeQuery();
        while(rs.next()){
            String u1SignDataS = rs.getString("Common");
            signu1Data=Base64.getDecoder().decode(u1SignDataS);
        }
        ps = con.prepareStatement("select COMMON from SN where CNAME=\"U2SIGNDATA\" ");
        rs = ps.executeQuery();
        while(rs.next()){
            String u2SignDataS = rs.getString("Common");
            signu2Data=Base64.getDecoder().decode(u2SignDataS);
        }
        Boolean VerifyU1=SM2sign.verify(APub,null,signu1Data,signu1);
        Boolean VerifyU2=SM2sign.verify(BPub,null,signu2Data,signu2);
        System.out.println("验证A的结果："+VerifyU1.toString());
        System.out.println("验证B的结果："+VerifyU2.toString());
        //验证CERT1和CERT2
        byte[] CERT1=null,CERT2=null;
        //获取AID1,A和T1
        String AID1String = (String) sqlValue.get("AID_1");
        byte[] AID_1 = Base64.getDecoder().decode(AID1String);
        String AString = (String) sqlValue.get("A");
        ECPublicKeyParameters Apub = sm2.RestorePub(Base64.getDecoder().decode(AString));
        ps = con.prepareStatement("select COMMON from SN where CName=\"cert1SIGN\";");
        ResultSet RS = ps.executeQuery();
        while(RS.next()){
            String common = RS.getString("COMMON");
            CERT1=Base64.getDecoder().decode(common);
        }
        long t1=Long.valueOf((String)sqlValue.get("t1"));
        byte[] CERT1DATA=SM2.byteMerger(AID_1,Apub.getQ().getEncoded(false),SM2.longToBytes(t1));
        Boolean CERT1Verify = SM2sign.verify(this.PTP, null, CERT1DATA, CERT1);
        //获取AID2,B和T2
        String AID2String = (String) sqlValue.get("AID_2");
        byte[] AID_2 = Base64.getDecoder().decode(AID2String);
        String BString = (String) sqlValue.get("B");
        ECPublicKeyParameters Bpub = sm2.RestorePub(Base64.getDecoder().decode(BString));
        ps = con.prepareStatement("select COMMON from SN where CName=\"cert2SIGN\";");
        RS = ps.executeQuery();
        while(RS.next()){
            String common = RS.getString("COMMON");
            CERT2=Base64.getDecoder().decode(common);
        }
        long t2=Long.valueOf((String)sqlValue.get("t2"));
        byte[] CERT2DATA=SM2.byteMerger(AID_2,Bpub.getQ().getEncoded(false),SM2.longToBytes(t2));
        Boolean CERT2Verify = SM2sign.verify(this.PHN, null, CERT2DATA, CERT2);
        System.out.println("Cert1验证结果是:"+CERT1Verify.toString());
        System.out.println("Cert2验证结果是:"+CERT2Verify.toString());
        if(CERT2Verify==Boolean.TRUE && CERT2Verify==Boolean.TRUE && VerifyU1==Boolean.TRUE && VerifyU2==Boolean.TRUE){
            System.out.println("验证通过");
            con.close();
            return true;
        }
        else {
            return false;
        }
    }

    public BigInteger CalculateKSN()throws Exception{
        SM2 sm2=new SM2();
        Map<String, Object> sqlValue = this.autoSqlValue();
        //生成ZUE,ZSN
        //生成ENTLue,ENTLsn，即AID
        byte[] AID_1=Base64.getDecoder().decode((String)sqlValue.get("AID_1"));
        byte[] AID_2=Base64.getDecoder().decode((String)sqlValue.get("AID_2"));
        String SNNameString=(String)sqlValue.get("SNName");
        byte[] SNname = SNNameString.getBytes();
        byte[] AID= SM2.byteMerger(AID_1,AID_2);

        byte[] ENTLue=intToTwoBytes(AID.length);
        byte[] ENTLsn=intToTwoBytes(SNname.length);
        //a
        byte[] a=sm2.getcurve().getA().getEncoded();
        byte[] b=sm2.getcurve().getB().getEncoded();
        byte[] gx=sm2.domainParams.getG().getAffineXCoord().getEncoded();
        byte[] gy=sm2.domainParams.getG().getAffineYCoord().getEncoded();
        ECPublicKeyParameters ueKey = this.PUE;
        ECPublicKeyParameters ueSn=(ECPublicKeyParameters) this.SN.getPublic();
        byte[] xue=ueKey.getQ().getAffineXCoord().getEncoded();
        byte[] yue=ueKey.getQ().getAffineYCoord().getEncoded();
        byte[] xsn=ueSn.getQ().getAffineXCoord().getEncoded();
        byte[] ysn=ueSn.getQ().getAffineYCoord().getEncoded();
        byte[] Zue=SM3.sm3Hash(SM2.byteMerger(ENTLue,AID,a,b,gx,gy,xue,yue));
        byte[] Zsn=SM3.sm3Hash(SM2.byteMerger(ENTLsn,SNname,a,b,gx,gy,xsn,ysn));

        String raBASE64 = (String) sqlValue.get("RA");
        byte[] raByte = Base64.getDecoder().decode(raBASE64);
        ECPublicKeyParameters RA = sm2.RestorePub(raByte);
        this.setRB(sm2.generateKey());
        AsymmetricCipherKeyPair rb = this.getRB();
        String rbPriv = rb.getPrivate().toString();
        ECPublicKeyParameters rbPub=(ECPublicKeyParameters)(rb.getPublic());
        String rbPubString = Base64.getEncoder().encodeToString(rbPub.getQ().getEncoded(false));
        Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "123456");
        PreparedStatement ps = con.prepareStatement("update SN set RB=\""+rbPubString+"\" where id=1");
        ps.execute();
        ps = con.prepareStatement("update UE set RB=\""+rbPubString+"\" where id=1");
        ps.execute();
        ps = con.prepareStatement("update SN set RBPriv=\""+rbPriv+"\" where id=1");
        ps.execute();
        ECPublicKeyParameters RBPub= (ECPublicKeyParameters) this.RB.getPublic();
        //算出V点
        ECPoint V = this.calculateUForSN(RA, this.PHN, this.SN, this.RB);
        //取出A和B
        String AString = (String)sqlValue.get("A");
        byte[] AByte = Base64.getDecoder().decode(AString);
        ECPublicKeyParameters A=sm2.RestorePub(AByte);
        String BString = (String)sqlValue.get("B");
        byte[] BByte = Base64.getDecoder().decode(BString);
        ECPublicKeyParameters B=sm2.RestorePub(BByte);
        byte[] SignDataSN = SM3.sm3Hash(SM2.byteMerger(Zue, Zsn, RA.getQ().getEncoded(false),
                RBPub.getQ().getEncoded(false),
                A.getQ().getEncoded(false), B.getQ().getEncoded(false)));
        byte[] signSN = SM2sign.sign(this.getSN().getPrivate(), null, SignDataSN);
        ps=con.prepareStatement("INSERT INTO UE(CNAME,COMMON) values (\"SIGNSN\",\""+Base64.getEncoder().encodeToString(signSN)
        +"\")");
        ps.execute();
        con.close();
        BigInteger KSN = KDF(V, Zue, Zsn);
        return KSN;

    }
    public AsymmetricCipherKeyPair getSN() {
        return SN;
    }

    public void setSN(AsymmetricCipherKeyPair SN) {
        this.SN = SN;
    }

    public ECPublicKeyParameters getPUE() {
        return PUE;
    }

    public void setPUE(ECPublicKeyParameters PUE) {
        this.PUE = PUE;
    }

    public ECPublicKeyParameters getPTP() {
        return PTP;
    }

    public void setPTP(ECPublicKeyParameters PTP) {
        this.PTP = PTP;
    }
}
