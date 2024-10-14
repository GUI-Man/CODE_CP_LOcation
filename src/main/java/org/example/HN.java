package org.example;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import java.math.BigInteger;
import java.sql.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class HN {
    byte[] AID_2;
    long timestamp;
    CipherParameters bPublic;
    AsymmetricCipherKeyPair HN;
    ECPublicKeyParameters PTP;
    ECPublicKeyParameters PUE;
    SM2 sm2;
    ECPublicKeyParameters PSN;
    public AsymmetricCipherKeyPair getHN() {
        return HN;
    }

    public void setHN(AsymmetricCipherKeyPair HN) {
        this.HN = HN;
    }

    public ECPublicKeyParameters getPTP() {
        return PTP;
    }

    public void setPTP(ECPublicKeyParameters PTP) {
        this.PTP = PTP;
    }

    HN() throws SQLException,ClassNotFoundException{
        this.sm2=new SM2();
        byte[] UEPUBbyte;
        byte[] HNPrivByte;
        byte[] SNPUBbyte;
        byte[] TPPUBByte;
        byte[] HNPUBByte;
        Map<String, Object> sqlmap = autoSqlValue();
        HNPUBByte= Base64.getDecoder().decode((String)sqlmap.get("HNPub"));
        HNPrivByte=Base64.getDecoder().decode((String)sqlmap.get("HNPriv"));
        this.setHN(new AsymmetricCipherKeyPair(sm2.RestorePub(HNPUBByte),sm2.RestorePriv(new BigInteger(HNPrivByte))));
        SNPUBbyte= Base64.getDecoder().decode((String)sqlmap.get("SNPub"));
        this.setPSN(sm2.RestorePub(SNPUBbyte));
        UEPUBbyte=Base64.getDecoder().decode((String)sqlmap.get("UEPub"));
        this.setPUE(sm2.RestorePub(UEPUBbyte));
        TPPUBByte=Base64.getDecoder().decode((String)sqlmap.get("TPPub"));
        this.setPTP(sm2.RestorePub(TPPUBByte));
    }
    public Map<String,Object> autoSqlValue() throws ClassNotFoundException, SQLException {
        Class.forName("com.mysql.jdbc.Driver");
        Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "123456");
        PreparedStatement ps = con.prepareStatement("select * from HN where id=1 ");
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


    public ECPublicKeyParameters getPSN() {
        return PSN;
    }

    public void setPSN(ECPublicKeyParameters PSN) {
        this.PSN = PSN;
    }

    public ECPublicKeyParameters getPUE() {
        return PUE;
    }

    public void setPUE(ECPublicKeyParameters PUE) {
        this.PUE = PUE;
    }


    byte[] SignData;

    public byte[] getAID_2() {
        return AID_2;
    }

    public void setAID_2(byte[] AID_2) {
        this.AID_2 = AID_2;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public CipherParameters getbPublic() {
        return bPublic;
    }

    public void setbPublic(CipherParameters bPublic) {
        this.bPublic = bPublic;
    }

    public byte[] getSignData() {
        return SignData;
    }

    public void setSignData(byte[] signData) {
        SignData = signData;
    }

    public boolean VerifySign_2() throws Exception {
        Map<String, Object> TPParam = this.autoSqlValue();
        byte[] SIGN= Base64.getDecoder().decode((String) TPParam.get("SIGNDATA"));
        byte[] AID_2= Base64.getDecoder().decode((String) TPParam.get("AID_2"));
        ECPublicKeyParameters B = sm2.RestorePub(Base64.getDecoder().decode((String) TPParam.get("B")));
        String Tp=(String) TPParam.get("TimeSTAMPUE");
        long timestamp=Long.valueOf(Tp);
        byte[] timestampByte=SM2.longToBytes(timestamp);
        byte[] BpubByte=Base64.getDecoder().decode((String)TPParam.get("B"));
        ECPublicKeyParameters bPub = sm2.RestorePub(BpubByte);
        byte[] SignData2=SM2.byteMerger(AID_2,timestampByte,bPub.getQ().getEncoded(false));
        //检查时间戳新鲜度,抵御重放攻击
        long timestampCur = System.currentTimeMillis();
        if(timestampCur-timestamp>=3000){
            return false;
        }
        else{
            //检查签名,并且生成证书
            if(SM2sign.verify(this.PUE,null,SignData2,SIGN)){
//             这里设定t2为3分钟，即3*60*1000
                long t2=3*60*1000;
                byte[] t2byte = SM2.longToBytes(t2);
                byte[] CertData=SM2.byteMerger(AID_2,BpubByte,t2byte);
                //生成证书里面的签名
                byte[] sign = SM2sign.sign(this.HN.getPrivate(), null, CertData);
                Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "123456");
                PreparedStatement ps = con.prepareStatement("UPDATE UE set CERT2SIGN=\""+Base64.getEncoder().encodeToString(sign)+"\" where id=1;");
                ps.execute();
                ps = con.prepareStatement("UPDATE HN set CERT2SIGN=\""+Base64.getEncoder().encodeToString(sign)+"\" where id=1;");
                ps.execute();
                ps = con.prepareStatement("UPDATE UE set T2="+t2+" where id=1;");
                ps.execute();
                ps = con.prepareStatement("UPDATE HN set T2="+t2+" where id=1;");
                ps.execute();
                ps = con.prepareStatement("UPDATE UE set B=\""+(String)TPParam.get("B")+"\" where id=1;");
                ps.execute();

                return true;

            }else {
                return SM2sign.verify(this.PUE, null, SignData2, SIGN);
            }
        }


    }

}
