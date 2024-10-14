package org.example;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.SM2KeyExchange;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.util.Strings;

import java.util.*;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;

public class SM2 {
    static BigInteger SM2_ECC_P = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16); //素数域
    static BigInteger SM2_ECC_A = new BigInteger("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16); //曲线系数a
    static BigInteger SM2_ECC_B = new BigInteger("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16); //曲线系数b
    static BigInteger SM2_ECC_N = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16); //生成元G的阶数
    static BigInteger SM2_ECC_H = ECConstants.ONE;                                  //余因子为1
    static BigInteger SM2_ECC_GX = new BigInteger("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16); //生成元x坐标
    static BigInteger SM2_ECC_GY = new BigInteger("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16); //生成元x坐标
    public ECCurve.Fp curve;
    public ECPoint g;
    // 比较两个 ECPublicKeyParameters 是否相同
    public static boolean compareECPublicKeyParameters(ECPublicKeyParameters key1, ECPublicKeyParameters key2) {
        if (key1 == key2) return true;
        if (key1 == null || key2 == null) return false;

        // 1. 比较公钥点 ECPoint
        ECPoint point1 = key1.getQ();
        ECPoint point2 = key2.getQ();
        if (!point1.equals(point2)) {
            return false;
        }

        // 2. 比较域参数 ECDomainParameters
        ECDomainParameters params1 = key1.getParameters();
        ECDomainParameters params2 = key2.getParameters();

        if (params1 == params2) return true;
        if (params1 == null || params2 == null) return false;

        // 3. 比较曲线（ECCurve）
        if (!params1.getCurve().equals(params2.getCurve())) {
            return false;
        }

        // 4. 比较基点（G点）
        if (!params1.getG().equals(params2.getG())) {
            return false;
        }

        // 5. 比较阶 (n)
        if (!params1.getN().equals(params2.getN())) {
            return false;
        }

        // 6. 比较升标因子 (h)
        if (!params1.getH().equals(params2.getH())) {
            return false;
        }

        // 如果公钥点和域参数完全一致，返回 true
        return true;
    }
    // 比较两个 ECPrivateKeyParameters 是否相同
    public static boolean compareECPrivateKeyParameters(ECPrivateKeyParameters key1, ECPrivateKeyParameters key2) {
        if (key1 == key2) return true;
        if (key1 == null || key2 == null) return false;

        // 1. 比较私钥的D值（私钥数值）
        if (!key1.getD().equals(key2.getD())) {
            return false;
        }

        // 2. 比较域参数 (ECDomainParameters)
        ECDomainParameters params1 = key1.getParameters();
        ECDomainParameters params2 = key2.getParameters();

        if (params1 == params2) return true;
        if (params1 == null || params2 == null) return false;

        // 3. 比较曲线（ECCurve）
        if (!params1.getCurve().equals(params2.getCurve())) {
            return false;
        }

        // 4. 比较基点（G点）
        if (!params1.getG().equals(params2.getG())) {
            return false;
        }

        // 5. 比较阶 (n)
        if (!params1.getN().equals(params2.getN())) {
            return false;
        }

        // 6. 比较升标因子 (h)
        if (!params1.getH().equals(params2.getH())) {
            return false;
        }

        // 如果私钥和域参数完全一致，返回 true
        return true;
    }
    ECDomainParameters domainParams=null;
    SM2(){
        getcurve();
    }
    //根据byte和curve的domainParam还原公钥
    public ECPublicKeyParameters RestorePub(byte[] encoded){
        getcurve();
        ECPoint d = this.curve.decodePoint(encoded);
        ECPublicKeyParameters privateKeyParameters=new ECPublicKeyParameters(d,this.domainParams);
        return privateKeyParameters;
    }
    //根据Byte和curve的domainParam还原私钥
    public ECPrivateKeyParameters RestorePriv(BigInteger d){
        getcurve();
        ECPrivateKeyParameters privateKeyParameters=new ECPrivateKeyParameters(d,this.domainParams);
        return privateKeyParameters;
    }
    // 将byte数组转换为long类型
    public static long bytesToLong(byte[] bytes) {
        if (bytes == null || bytes.length != 8) {
            throw new IllegalArgumentException("byte数组的长度必须为8");
        }
        long result = 0;
        for (int i = 0; i < 8; i++) {
            result <<= 8; // 左移8位，为下一字节腾出空间
            result |= (bytes[i] & 0xFF); // 将当前字节的值并入result
        }
        return result;
    }
    // 将long类型转换为byte数组
    public static byte[] longToBytes(long value) {
        byte[] result = new byte[8];
        for (int i = 7; i >= 0; i--) {
            result[i] = (byte)(value & 0xFF); // 获取最低8位
            value >>= 8; // 右移8位
        }
        return result;
    }
//    public static ECPoint Mult(ECPoint a,ECPoint b){
//
//    }
    /**
     * 对两个长度相同的 byte[] 数组进行按位异或操作
     *
     * @param array1 第一个 byte[] 数组
     * @param array2 第二个 byte[] 数组
     * @return 结果 byte[] 数组
     * @throws IllegalArgumentException 如果数组长度不相同
     */
    public static byte[] xorByteArrays(byte[] array1, byte[] array2) {
        // 检查两个数组的长度是否相同
        if (array1.length != array2.length) {
            throw new IllegalArgumentException("两个数组的长度必须相同");
        }

        // 创建结果数组
        byte[] result = new byte[array1.length];

        // 逐个字节进行异或操作
        for (int i = 0; i < array1.length; i++) {
            result[i] = (byte) (array1[i] ^ array2[i]);
        }

        return result;
    }
    /**
     *
     * @author Freeman
     * @date 2024/9/29
     */
    // 生成随机盐
    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16]; // 16字节的盐值
        random.nextBytes(salt);
        return salt;
    }
    // 密钥导出函数（PBKDF2）
    public static byte[] deriveKey(String password, byte[] salt, int iterations, int keyLength)
            throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "BC");

        return skf.generateSecret(spec).getEncoded();
    }
    public static  byte[] KDF(String password,int keyLength) {
//        String password = "my_secure_password";
        byte[] salt = generateSalt();  // 生成随机盐
        int iterations = 10000;        // 迭代次数
//        int keyLength = 256;           // 生成的密钥长度 (256 位)
        byte[] derivedKey=null;
        try {
            // 使用PBKDF2算法生成密钥
            derivedKey = deriveKey(password, salt, iterations, keyLength);

            // 输出生成的密钥（以Base64编码显示）
            System.out.println("Generated Key: " + Base64.getEncoder().encodeToString(derivedKey));
            System.out.println("Salt: " + Base64.getEncoder().encodeToString(salt));

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
        return derivedKey;
    }

//获取椭圆曲线

    static {
        //    Java中，安全提供者（Security Provider）是一种实现了特定安全服务的软件模块。它提供了一系列的加密、解密、签名、验证和随机数生成等安全功能。安全提供者基础设施在Java中的作用是为开发人员提供一种扩展和替换标准安全功能的方式，以满足特定的安全需求。
//    Java的安全提供者基础设施是通过Java Cryptography Architecture（JCA）实现的。JCA定义了一组API和框架，用于在Java平台上实现各种安全服务。安全提供者是JCA的核心组件之一，它通过实现JCA规范中定义的接口，向应用程序提供安全功能。
//    安全提供者可以由Java平台提供的默认提供者，也可以是第三方开发的提供者。默认提供者包含在Java开发工具包（JDK）中，并提供了一些常见的加密算法和安全功能。第三方提供者则可以通过扩展JCA接口，实现自定义的加密算法和其他安全功能。
//    使用安全提供者，开发人员可以在应用程序中轻松地切换和配置不同的安全实现。例如，可以根据具体的安全需求选择不同的提供者，或者通过配置文件动态加载和替换提供者。这种灵活性使得Java应用程序能够适应不同的安全环境和要求。
//    总之，Java中的安全提供者基础设施允许开发人员使用标准或自定义的安全功能，以保护和加密数据，验证身份，以及执行其他与安全相关的操作。它为Java应用程序提供了一种可扩展和灵活的安全解决方案。
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void PrintEcpoint(ECPoint G){
        System.out.println("x:"+G.getXCoord().toString());
        System.out.println("y:"+G.getYCoord().toString());
    }
    public static ECPoint ByteToEcpoint(byte[] input){
        //生成ECC曲线和G
        ECCurve curve = new ECCurve.Fp(SM2_ECC_P, SM2_ECC_A, SM2_ECC_B, SM2_ECC_N, SM2_ECC_H);
        return curve.decodePoint(input);

    }
    public ECCurve.Fp getcurve()
    {
        //判断有没有参数
        if(domainParams !=null)return this.curve;
        //生成ECC曲线和G
        this.curve = new ECCurve.Fp(SM2_ECC_P, SM2_ECC_A, SM2_ECC_B, SM2_ECC_N, SM2_ECC_H);
        this.g = this.curve.createPoint(SM2_ECC_GX, SM2_ECC_GY);
        this.domainParams = new ECDomainParameters(curve, g, SM2_ECC_N);
//        System.out.println("你好"+domainParams.getG());
        ECPoint x=domainParams.getG();
//        System.out.println("Pause");
        return this.curve;
    }
    public static SecureRandom Generate256SecureRandom(){
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[256];
        secureRandom.nextBytes(randomBytes);
        return secureRandom;
    }
    /**
     *
     * @author Freeman
     * @date 2024/10/8
     *这是说的椭圆曲线乘法
     */
//    public static ECurveMult(ECPoint x,){
//
//    }
    /**
     *
     * @author Freeman
     * @date 2024/10/8
     *生成公私钥符合参数要求的公私钥对
     */
    public AsymmetricCipherKeyPair generateKey(){
        // 构造曲线
        this.getcurve();
        // 实例化密钥对生成器
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();

        //A用户私钥6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE,这里是指定了一个指定值,事实上数字只是一个强随机数，可以替换
        ECKeyGenerationParameters aKeyGenParams = new ECKeyGenerationParameters(domainParams, SM2.Generate256SecureRandom());
        // 初始化密钥对生成器
        keyPairGenerator.init(aKeyGenParams);
        // 生成密钥对
//		KeyPair keyPair = keyPairGenerator.generateKeyPair();
        AsymmetricCipherKeyPair aKp = keyPairGenerator.generateKeyPair();
        // 甲方公钥
        //PublicKey publicKey = (PublicKey) keyPair.getPublic();
        ECPublicKeyParameters aPub = (ECPublicKeyParameters)aKp.getPublic();
        // 甲方私钥
        //PrivateKey privateKey = (PrivateKey) keyPair.getPrivate();
        ECPrivateKeyParameters aPriv = (ECPrivateKeyParameters)aKp.getPrivate();
        System.out.println("私钥:"+aPriv.getD().toString());
        System.out.println("公钥x:"+aPub.getQ().getAffineXCoord().toBigInteger().toString());
        System.out.println("公钥y:"+aPub.getQ().getAffineYCoord().toBigInteger().toString());
        ECPoint g = domainParams.getG();
        System.out.println("生成元gx:"+g.getAffineXCoord().toBigInteger().toString());
        System.out.println("生成元gy:"+g.getAffineYCoord().toBigInteger().toString());
        ECPoint Xpub = g.multiply(aPriv.getD());
        Xpub = ECAlgorithms.importPoint(Xpub.getCurve(), Xpub).normalize();
        System.out.println("生成元G*私钥D=x:"+Xpub.getAffineXCoord().toBigInteger().toString());
        System.out.println("y:"+Xpub.getAffineYCoord().toBigInteger().toString());

        return aKp;

    }
    public Map<String, Object> initKeyA() throws Exception {

        // 构造曲线
        this.getcurve();
        // 实例化密钥对生成器
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();

        //A用户私钥6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE,这里是指定了一个指定值,事实上数字只是一个强随机数，可以替换
        ECKeyGenerationParameters aKeyGenParams = new ECKeyGenerationParameters(domainParams, SM2.Generate256SecureRandom());
        // 初始化密钥对生成器
        keyPairGenerator.init(aKeyGenParams);
        // 生成密钥对
//		KeyPair keyPair = keyPairGenerator.generateKeyPair();
        AsymmetricCipherKeyPair aKp = keyPairGenerator.generateKeyPair();
        // 甲方公钥
        //PublicKey publicKey = (PublicKey) keyPair.getPublic();
        ECPublicKeyParameters aPub = (ECPublicKeyParameters)aKp.getPublic();
        // 甲方私钥
        //PrivateKey privateKey = (PrivateKey) keyPair.getPrivate();
        ECPrivateKeyParameters aPriv = (ECPrivateKeyParameters)aKp.getPrivate();

        //ra随机数,生成RA
        //ECKeyGenerationParameters aeKeyGenParams = new ECKeyGenerationParameters(domainParams, new TestRandomBigInteger("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563", 16));
        SecureRandom random= new SecureRandom();
        //ECKeyGenerationParameters
        ECKeyGenerationParameters aeKeyGenParams = new ECKeyGenerationParameters(domainParams, random);
        keyPairGenerator.init(aeKeyGenParams);

        AsymmetricCipherKeyPair aeKp = keyPairGenerator.generateKeyPair();

        ECPublicKeyParameters aePub = (ECPublicKeyParameters)aeKp.getPublic();
        ECPrivateKeyParameters aePriv = (ECPrivateKeyParameters)aeKp.getPrivate();
        // 将密钥对存储在Map中
        Map<String, Object> keyMap = new HashMap<String, Object>(4);

        //keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put("aPub", aPub);
        //keyMap.put(PRIVATE_KEY, privateKey);
        keyMap.put("aPriv", aPriv);
        keyMap.put("aePub",aePub);
        keyMap.put("aePriv",aePriv);

        return keyMap;
    }
    /**
     * 初始化乙方密钥
     * 甲方公钥
     * @return Map 乙方密钥Map
     * @throws Exception
     */
    public Map<String, Object> initKeyB() throws Exception {
        //rb ,乙方
        ECKeyGenerationParameters bKeyGenParams = new ECKeyGenerationParameters(domainParams, SM2.Generate256SecureRandom());
        // 初始化算法参数生成器
        // 实例化密钥对儿生成器
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        // 初始化密钥对儿生成器
        keyPairGenerator.init(bKeyGenParams);
        // 生成密钥对儿
        AsymmetricCipherKeyPair bKp = keyPairGenerator.generateKeyPair();
        //获取B用户的公私钥
        ECPublicKeyParameters bPub = (ECPublicKeyParameters)bKp.getPublic();
        ECPrivateKeyParameters bPriv = (ECPrivateKeyParameters)bKp.getPrivate();
        //获取be的参数，rb随机
        SecureRandom random= new SecureRandom();
        //ECKeyGenerationParameters beKeyGenParams = new ECKeyGenerationParameters(domainParams, new TestRandomBigInteger("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80", 16));
        ECKeyGenerationParameters beKeyGenParams = new ECKeyGenerationParameters(domainParams, random);
        keyPairGenerator.init(beKeyGenParams);

        AsymmetricCipherKeyPair beKp = keyPairGenerator.generateKeyPair();

        ECPublicKeyParameters bePub = (ECPublicKeyParameters)beKp.getPublic();
        ECPrivateKeyParameters bePriv = (ECPrivateKeyParameters)beKp.getPrivate();

        // 封装密钥
        Map<String, Object> map = new HashMap<String, Object>(4);

        //map.put(PUBLIC_KEY, publicKey);
        map.put("bPub", bPub);
        //map.put(PRIVATE_KEY, privateKey);
        map.put("bPriv", bPriv);
        map.put("bePub", bePub);
        map.put("bePriv", bePriv);
        return map;
    }

        public static byte generateRandomByte(Random random) {
            // 由于Byte的范围是-128到127，我们生成一个0到255的随机数
            int randomInt = random.nextInt(256);
            // 将生成的随机数映射到Byte范围内
            byte randomByte = (byte) randomInt;
            return randomByte;
        }
        public static byte[] generateByteStream(int length){
            byte[] result=new byte[length];
            for(int i=0;i<length;i++){
                result[i]=generateRandomByte(new Random());
            }
            return result;
        }
    public static byte[] byteMerger(byte[]... arrays) {
        // 计算总长度
        int totalLength = 0;
        for (byte[] array : arrays) {
            totalLength += array.length;
        }

        // 创建新的数组以容纳所有数据
        byte[] result = new byte[totalLength];

        // 合并每个数组
        int currentIndex = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, currentIndex, array.length);
            currentIndex += array.length;
        }

        return result;
    }
//    public static byte[] byteMerger(byte[] byte_1, byte[] byte_2){
//        byte[] byte_3 = new byte[byte_1.length+byte_2.length];
//        System.arraycopy(byte_1, 0, byte_3, 0, byte_1.length);
//        System.arraycopy(byte_2, 0, byte_3, byte_1.length, byte_2.length);
//        return byte_3;
//    }
    public static byte[] KeySelfExchangeB(ECPrivateKeyParameters bPriv,ECPrivateKeyParameters bePriv,ECPublicKeyParameters aPub,ECPublicKeyParameters aePub) throws Exception {
        SM2KeyExchangeSelf exch = new SM2KeyExchangeSelf();
        byte[] AID_1=generateByteStream(256),AID_2=generateByteStream(256);
        byte[] AID=byteMerger(AID_1,AID_2);
        exch.init(new ParametersWithID(new SM2KeyExchangePrivateParametersSelf(false, bPriv, bePriv), AID));
        byte[] k2 = exch.calculateKey(128, new ParametersWithID(new SM2KeyExchangePublicParametersSelf(aPub, aePub), Strings.toByteArray("ALICE123@YAHOO.COM")));
        //isTrue("key 2 wrong", Arrays.areEqual(Hex.decode("55b0ac62a6b927ba23703832c853ded4"), k2));
        return k2;
    }
    public static byte[] KeySelfExchangeA(ECPrivateKeyParameters aPriv,ECPrivateKeyParameters aePriv,ECPublicKeyParameters bPub,ECPublicKeyParameters bePub) throws Exception {

        SM2KeyExchangeSelf exch = new SM2KeyExchangeSelf();
        //init看源码应该是在确认RA是否满足要求
        exch.init(new ParametersWithID(new SM2KeyExchangePrivateParametersSelf(true, aPriv, aePriv), Strings.toByteArray("ALICE123@YAHOO.COM")));
//        exch.calculateUEFirstStep()
        //共享密钥是55b0ac62a6b927ba23703832c853ded4
        // isTrue("key 1 wrong", Arrays.areEqual(Hex.decode("55b0ac62a6b927ba23703832c853ded4"), k1));
        return null;
    }
    /***
     *
     * @param aPriv
     * @param aePriv
     * @param bPub
     * @param bePub
     * @return 协商后的密钥
     * @throws Exception
     */
    public static byte[] KeyExchangeA(ECPrivateKeyParameters aPriv,ECPrivateKeyParameters aePriv,ECPublicKeyParameters bPub,ECPublicKeyParameters bePub) throws Exception {
        SM2KeyExchange exch = new SM2KeyExchange();
        //init看源码应该是在确认RA是否满足要求
        exch.init(new ParametersWithID(new SM2KeyExchangePrivateParameters(true, aPriv, aePriv), Strings.toByteArray("ALICE123@YAHOO.COM")));
        byte[] k1 = exch.calculateKey(128, new ParametersWithID(new SM2KeyExchangePublicParameters(bPub, bePub), Strings.toByteArray("BILL456@YAHOO.COM")));
        //共享密钥是55b0ac62a6b927ba23703832c853ded4
        // isTrue("key 1 wrong", Arrays.areEqual(Hex.decode("55b0ac62a6b927ba23703832c853ded4"), k1));
        return k1;
    }
    public static ECPrivateKeyParameters getPrivateKey(String str,Map<String, Object> keyMap )
            throws Exception {

        ECPrivateKeyParameters key = (ECPrivateKeyParameters) keyMap.get(str);
        return key;
    }

    /**
     * 取得公钥
     *
     * @param keyMap
     *            密钥Map
     * @return byte[] 公钥
     * @throws Exception
     */
    public static ECPublicKeyParameters getPublicKey(String str,Map<String, Object> keyMap )
            throws Exception {

        ECPublicKeyParameters key = (ECPublicKeyParameters) keyMap.get(str);

        return key;
    }
    /****
     * @param bPriv
     * @param bePriv
     * @param aPub
     * @param aePub
     * @return 返回协商后的密钥
     * @throws Exception
     */
    public static byte[] KeyExchangeB(ECPrivateKeyParameters bPriv,ECPrivateKeyParameters bePriv,ECPublicKeyParameters aPub,ECPublicKeyParameters aePub) throws Exception {

        SM2KeyExchange exch = new SM2KeyExchange();
        exch.init(new ParametersWithID(new SM2KeyExchangePrivateParameters(false, bPriv, bePriv), Strings.toByteArray("BILL456@YAHOO.COM")));
        byte[] k2 = exch.calculateKey(128, new ParametersWithID(new SM2KeyExchangePublicParameters(aPub, aePub), Strings.toByteArray("ALICE123@YAHOO.COM")));
        //isTrue("key 2 wrong", Arrays.areEqual(Hex.decode("55b0ac62a6b927ba23703832c853ded4"), k2));
        return k2;
    }
    public void SM2ExchangeDemo2() throws Exception{
        SM2 sm2 = new SM2();
        AsymmetricCipherKeyPair A = sm2.generateKey();
        AsymmetricCipherKeyPair Ae=sm2.generateKey();
        AsymmetricCipherKeyPair B= sm2.generateKey();
        AsymmetricCipherKeyPair Be=sm2.generateKey();
        ECPrivateKeyParameters aPriv = (ECPrivateKeyParameters)A.getPrivate();
        ECPrivateKeyParameters aePriv = (ECPrivateKeyParameters)Ae.getPrivate();

        ECPublicKeyParameters aPub =(ECPublicKeyParameters)A.getPublic();
        ECPublicKeyParameters aePub = (ECPublicKeyParameters)Ae.getPublic();


        //乙方生成的密钥
        ECPrivateKeyParameters bPriv = (ECPrivateKeyParameters)B.getPrivate();
        ECPrivateKeyParameters bePriv = (ECPrivateKeyParameters)Be.getPrivate();

        ECPublicKeyParameters bPub = (ECPublicKeyParameters)B.getPublic();
        ECPublicKeyParameters bePub = (ECPublicKeyParameters)Be.getPublic();
        byte[] mykeyA = SM2.KeyExchangeA(aPriv, aePriv, bPub, bePub);

        byte[] mykeyB = SM2.KeyExchangeB(bPriv, bePriv, aPub, aePub);
        System.out.println(new BigInteger(mykeyB).toString());
        System.out.println(new BigInteger(mykeyA).toString());
    }
    public static void SM2SelfExchangeDemo() throws Exception{
        SM2 sm2=new SM2();
        AsymmetricCipherKeyPair A = sm2.generateKey();
        AsymmetricCipherKeyPair Ae=sm2.generateKey();
        AsymmetricCipherKeyPair B= sm2.generateKey();
        AsymmetricCipherKeyPair Be=sm2.generateKey();
        ECPrivateKeyParameters aPriv = (ECPrivateKeyParameters)A.getPrivate();
        ECPrivateKeyParameters aePriv = (ECPrivateKeyParameters)Ae.getPrivate();

        ECPublicKeyParameters aPub =(ECPublicKeyParameters)A.getPublic();
        ECPublicKeyParameters aePub = (ECPublicKeyParameters)Ae.getPublic();


        //乙方生成的密钥
        ECPrivateKeyParameters bPriv = (ECPrivateKeyParameters)B.getPrivate();
        ECPrivateKeyParameters bePriv = (ECPrivateKeyParameters)Be.getPrivate();

        ECPublicKeyParameters bPub = (ECPublicKeyParameters)B.getPublic();
        ECPublicKeyParameters bePub = (ECPublicKeyParameters)Be.getPublic();
        byte[] mykeyA = SM2.KeySelfExchangeA(aPriv, aePriv, bPub, bePub);

        byte[] mykeyB = SM2.KeySelfExchangeB(bPriv, bePriv, aPub, aePub);
        System.out.println(new BigInteger(mykeyB).toString());
        System.out.println(new BigInteger(mykeyA).toString());
    }
    public static void SM2ExchangeDemo() throws Exception{
        SM2 sm2= new SM2();
        Map<String, Object> keyMapA= sm2.initKeyA(),keyMapB= sm2.initKeyB();;
//甲方生成的密钥
        //aPriv是自己的静态私钥，aePriv是临时私钥
        ECPrivateKeyParameters aPriv = (ECPrivateKeyParameters)keyMapA.get("aPriv");
        ECPrivateKeyParameters aePriv = (ECPrivateKeyParameters)keyMapA.get("aePriv");

        ECPublicKeyParameters aPub =(ECPublicKeyParameters) keyMapA.get("aPub");
        ECPublicKeyParameters aePub = (ECPublicKeyParameters)keyMapA.get("aePub");


        //乙方生成的密钥
        ECPrivateKeyParameters bPriv = (ECPrivateKeyParameters)keyMapB.get("bPriv");
        ECPrivateKeyParameters bePriv = (ECPrivateKeyParameters)keyMapB.get("bePriv");

        ECPublicKeyParameters bPub = (ECPublicKeyParameters)keyMapB.get("bPub");
        ECPublicKeyParameters bePub = (ECPublicKeyParameters)keyMapB.get("bePub");
        //开始协商

            byte[] mykeyA = SM2.KeyExchangeA(aPriv, aePriv, bPub, bePub);

            byte[] mykeyB = SM2.KeyExchangeB(bPriv, bePriv, aPub, aePub);
        System.out.println(new BigInteger(mykeyB).toString());
        System.out.println(new BigInteger(mykeyA).toString());

    }
//    public static void rundemo(){
//        BouncyCastleProvider bcp = new BouncyCastleProvider();
//        Security.addProvider(bcp);
//        try {
//            SM2.SM2ExchangeDemo();
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
//    }
}
