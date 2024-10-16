package org.example;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.sql.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class TP {
    byte[] AID_1;
    long timestamp;
    CipherParameters aPublic;
    AsymmetricCipherKeyPair TP;
    ECPublicKeyParameters PHN;
    ECPublicKeyParameters PSN;
    TP() throws SQLException,ClassNotFoundException{
        this.sm2=new SM2();
        byte[] UEPUBbyte;
        String TPPrivByte;
        byte[] SNPUBbyte;
        byte[] TPPUBbyte;
        byte[] HNPUBByte;
        Map<String, Object> sqlmap = autoSqlValue();
        TPPUBbyte= Base64.getDecoder().decode((String)sqlmap.get("TPPub"));
        TPPrivByte=(String)sqlmap.get("TPPriv");
        this.setTP(new AsymmetricCipherKeyPair(sm2.RestorePub(TPPUBbyte),sm2.RestorePriv(new BigInteger(TPPrivByte))));
        SNPUBbyte= Base64.getDecoder().decode((String)sqlmap.get("SNPub"));
        this.setPSN(sm2.RestorePub(SNPUBbyte));
        UEPUBbyte=Base64.getDecoder().decode((String)sqlmap.get("UEPub"));
        this.setPUE(sm2.RestorePub(UEPUBbyte));
        HNPUBByte=Base64.getDecoder().decode((String)sqlmap.get("HNPub"));
        this.setPHN(sm2.RestorePub(HNPUBByte));
    }
    public static Map<String,Object> autoSqlValue() throws ClassNotFoundException, SQLException {
        Class.forName("com.mysql.jdbc.Driver");
        Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "123456");
        PreparedStatement ps = con.prepareStatement("select * from TP where id=1 ");
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

    public AsymmetricCipherKeyPair getTP() {
        return TP;
    }

    public void setTP(AsymmetricCipherKeyPair TP) {
        this.TP = TP;
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

    public ECPublicKeyParameters getPUE() {
        return PUE;
    }

    public void setPUE(ECPublicKeyParameters PUE) {
        this.PUE = PUE;
    }

    ECPublicKeyParameters PUE;
    SM2 sm2;

    byte[] SignData;
    public byte[] getAID_1() {
        return AID_1;
    }

    public void setAID_1(byte[] AID_1) {
        this.AID_1 = AID_1;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public CipherParameters getaPublic() {
        return aPublic;
    }

    public void setaPublic(CipherParameters aPublic) {
        this.aPublic = aPublic;
    }

    public byte[] getSignData() {
        return SignData;
    }

    public void setSignData(byte[] signData) {
        SignData = signData;
    }

    public boolean VerifySign_1() throws Exception {
        Map<String, Object> TPParam = this.autoSqlValue();
        byte[] SIGN= Base64.getDecoder().decode((String) TPParam.get("SIGNDATA"));
        byte[] AID_1= Base64.getDecoder().decode((String) TPParam.get("AID_1"));
        ECPublicKeyParameters A = sm2.RestorePub(Base64.getDecoder().decode((String) TPParam.get("A")));
        String Tp=(String) TPParam.get("TimeSTAMPUE");
        long timestamp=Long.valueOf(Tp);
        byte[] timestampByte=SM2.longToBytes(timestamp);
        byte[] ApubByte=Base64.getDecoder().decode((String)TPParam.get("A"));
        ECPublicKeyParameters aPub = sm2.RestorePub(ApubByte);
        byte[] SignData1=SM2.byteMerger(AID_1,timestampByte,aPub.getQ().getEncoded(false));
        //检查时间戳新鲜度,抵御重放攻击
        long timestampCur = System.currentTimeMillis();
        if(timestampCur-timestamp>=3000){
            return false;
        }
        else{
            //检查签名,并且生成证书
            if(SM2sign.verify(this.PUE,null,SignData1,SIGN)){
//             这里设定t1为3分钟，即3*60*1000
                long t1=3*60*1000;
                byte[] t1byte = SM2.longToBytes(t1);
                byte[] CertData=SM2.byteMerger(AID_1,ApubByte,t1byte);
                //生成证书里面的签名
                byte[] sign = SM2sign.sign(this.TP.getPrivate(), null, CertData);
                Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "root", "123456");
                PreparedStatement ps = con.prepareStatement("UPDATE UE set CERT1SIGN=\""+Base64.getEncoder().encodeToString(sign)+"\" where id=1;");
                ps.execute();
                ps = con.prepareStatement("UPDATE TP set CERT1SIGN=\""+Base64.getEncoder().encodeToString(sign)+"\" where id=1;");
                ps.execute();
                ps = con.prepareStatement("UPDATE UE set T1="+t1+" where id=1;");
                ps.execute();
                ps = con.prepareStatement("UPDATE TP set T1="+t1+" where id=1;");
                ps.execute();
                ps = con.prepareStatement("UPDATE SN set T1="+t1+" where id=1;");
                ps.execute();
                ps = con.prepareStatement("UPDATE UE set A=\""+(String)TPParam.get("A")+"\" where id=1;");
                ps.execute();

                return true;

            }else {
                return SM2sign.verify(this.PUE, null, SignData1, SIGN);
            }
        }


    }
    public static String AskForSqlCommon(String name)  {
        Connection con= null;
        try {
            con = DriverManager.getConnection("jdbc:mysql://localhost:3306/test","root","123456");
            PreparedStatement ps=con.prepareStatement("Select Common from TP where CName=\""+name+"\";");
            ResultSet rs = ps.executeQuery();
            String result = "";
            while(rs.next()) {
                result=rs.getString("Common");
            }
            return result;
        } catch (SQLException e) {
            return "false";
        }
    }
    public static void RestoreRID() throws SQLException, ClassNotFoundException {
        SM2 sm2 = new SM2();
        String c = org.example.TP.AskForSqlCommon("C");

        Map<String, Object> sqlValue = org.example.TP.autoSqlValue();
        String aid1 = (String)sqlValue.get("AID_1");
        byte[] AID_1 = Base64.getDecoder().decode(aid1);
        BigInteger tpPriv =new BigInteger((String) sqlValue.get("TPPriv"));
        String A=(String) sqlValue.get("A");
        ECPublicKeyParameters Apub = sm2.RestorePub(Base64.getDecoder().decode(A));
        ECPoint result = Apub.getQ().multiply(tpPriv).normalize();
        byte[] HKTP = SM3.extendHash(result.getEncoded(false), 65);
        System.out.println("HKTP在追溯阶段是："+Base64.getEncoder().encodeToString(HKTP));
        byte[] RID=SM2.xorByteArrays(AID_1,HKTP);
        RID=SM2.xorByteArrays(RID,Base64.getDecoder().decode(c));
        System.out.println("恢复出的真实身份是:"+Base64.getEncoder().encodeToString(RID));

    }
}
