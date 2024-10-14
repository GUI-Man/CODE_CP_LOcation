package org.example;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

import java.security.Security;

public class SM2sign {
    public AsymmetricCipherKeyPair Asigner;
    String SignData="A.E.I.O.U";
    public static byte[] sign(CipherParameters signerPriv,byte[] SignerId,byte[] SignData) throws Exception{
        // 1. 添加 BouncyCastle 提供者
        Security.addProvider(new BouncyCastleProvider());
        Signer signer = new SM2Signer();
        byte[] SignDataByte=SignData;
        CipherParameters priv=signerPriv;
        if(SignerId==null){
            priv=signerPriv;
        }
        else{
            priv = (CipherParameters) new ParametersWithID(signerPriv, SignerId);
        }
        //        CipherParameters priv=(CipherParameters)this.Asigner.getPrivate();
        signer.init(true,priv);
        signer.update(SignDataByte,0,SignDataByte.length);
        byte[] SignatureByte = signer.generateSignature();
        return SignatureByte;
    }
    public static boolean verify(CipherParameters signerPub,byte[] SignerId,byte[] SignData,byte[] SignatureByte){
        SM2Signer signer=new SM2Signer();
        CipherParameters aPublic =signerPub;
        if(SignerId!=null){
         aPublic =(CipherParameters) new ParametersWithID(signerPub, SignerId);
         }
//不加入ID如下
//        CipherParameters aPublic = this.Asigner.getPublic();
        signer.init(false,aPublic);

        signer.update(SignData,0,SignData.length);
        boolean result=signer.verifySignature(SignatureByte);

        return result;
    }
    public byte[] sign() throws Exception{
        // 1. 添加 BouncyCastle 提供者
        Security.addProvider(new BouncyCastleProvider());
        SM2 sm2=new SM2();
        Signer signer = new SM2Signer();
        byte[] SignDataByte=this.SignData.getBytes();
        this.Asigner = sm2.generateKey();
        CipherParameters priv =(CipherParameters) new ParametersWithID((CipherParameters) this.Asigner.getPrivate(), Strings.toByteArray("Habsburg"));

        //        CipherParameters priv=(CipherParameters)this.Asigner.getPrivate();
        signer.init(true,priv);
        signer.update(SignDataByte,0,SignDataByte.length);
        byte[] SignatureByte = signer.generateSignature();
        return SignatureByte;
    }
    public  boolean Verify(byte[] SignatureByte) throws Exception{
        SM2Signer signer=new SM2Signer();
        CipherParameters aPublic =(CipherParameters) new ParametersWithID(this.Asigner.getPublic(), Strings.toByteArray("Osman"));
//不加入ID如下
//        CipherParameters aPublic = this.Asigner.getPublic();
        signer.init(false,aPublic);

        byte[] SignDataByte=this.SignData.getBytes();
        signer.update(SignDataByte,0,SignDataByte.length);
        boolean result=signer.verifySignature(SignatureByte);
        System.out.println(result);
        return result;
    }
}
