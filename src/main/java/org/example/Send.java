package org.example;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.util.Map;

public class Send {
    //第一步请求凭证的发送信息
    public static void UEAskTPforCert(Map<String, Object> info, TP b){
        ECCurve.Fp curve = new SM2().curve;
        b.setAID_1((byte[]) info.get("AID1"));
        b.setaPublic((CipherParameters) curve.decodePoint((byte[])info.get("A")));
        b.setSignData((byte[])info.get("SignData"));
        b.setTimestamp(SM2.bytesToLong((byte[])info.get("timestamp")));
    }
}
