package org.example;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

public class SN {

    AsymmetricCipherKeyPair SN;
    ECPublicKeyParameters PUE;
    ECPublicKeyParameters PTP;
    ECPublicKeyParameters PUN;
    SM2 sm2;

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

    public ECPublicKeyParameters getPUN() {
        return PUN;
    }

    public void setPUN(ECPublicKeyParameters PUN) {
        this.PUN = PUN;
    }
}
