package org.example;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class SM2_convert {
    public SM2 sm2;
    SM2_convert(){
        sm2.getcurve();
    }
    public void test(){

        AsymmetricCipherKeyPair test = this.sm2.generateKey();
        ECPublicKeyParameters aPublic = (ECPublicKeyParameters)test.getPublic();
        ECPoint q = aPublic.getQ();
        System.out.println(q.getXCoord().toString());
        System.out.println(q.getYCoord().toString());

        byte[] encoded = q.getEncoded(true);
        show_Byte_Hex(encoded);
        System.out.println(encoded.length);
        ECPoint ecPoint = SM2.ByteToEcpoint(encoded);
        System.out.println(ecPoint.getXCoord().toString());
        System.out.println(ecPoint.getYCoord().toString());
        ECPrivateKeyParameters aPrivate = (ECPrivateKeyParameters)test.getPrivate();
        byte[] byteArray = aPrivate.getD().toByteArray();
        System.out.println(aPrivate.getD().toString());
        BigInteger Recover=new BigInteger(byteArray);
        System.out.println(Recover.toString());

//        System.out.println(show_Byte_Hex(SM2_BigIntegerToByte(aPrivate.getD())));
//
//        System.out.println("pause");

    }
    
    static public String show_Byte_Hex(byte[] input){
        StringBuilder builder = new StringBuilder();

        for(int i=0;i<input.length;i++){
            builder.append(String.format("%02X", input[i]));
            builder.append(',');
        }
        return builder.toString();
    }
    static public byte[] SM2_BigIntegerToByte(BigInteger d){
        return d.toByteArray();
    }
    static public BigInteger SM2_ByteToBigInteger(byte[] input){
        return new BigInteger(input);
    }
}
