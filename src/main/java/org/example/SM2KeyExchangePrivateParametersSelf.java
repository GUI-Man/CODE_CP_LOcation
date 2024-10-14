//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.example;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

public class SM2KeyExchangePrivateParametersSelf implements CipherParameters {
    private boolean initiator;
    private ECPrivateKeyParameters staticPrivateKey;
    private ECPoint staticPublicPoint;
    private ECPrivateKeyParameters ephemeralPrivateKey;
    private ECPoint ephemeralPublicPoint;
    public boolean isInitiator() {
        return this.initiator;
    }

    public ECPrivateKeyParameters getStaticPrivateKey() {
        return this.staticPrivateKey;
    }

    public ECPoint getStaticPublicPoint() {
        return this.staticPublicPoint;
    }

    public ECPrivateKeyParameters getEphemeralPrivateKey() {
        return this.ephemeralPrivateKey;
    }

    public ECPoint getEphemeralPublicPoint() {
        return this.ephemeralPublicPoint;
    }
    public SM2KeyExchangePrivateParametersSelf(boolean var1, ECPrivateKeyParameters var2, ECPrivateKeyParameters var3) {
        if (var2 == null) {
            throw new NullPointerException("staticPrivateKey cannot be null");
        } else if (var3 == null) {
            throw new NullPointerException("ephemeralPrivateKey cannot be null");
        } else {
            ECDomainParameters var4 = var2.getParameters();
            if (!var4.equals(var3.getParameters())) {
                throw new IllegalArgumentException("Static and ephemeral private keys have different domain parameters");
            } else {
                FixedPointCombMultiplier var5 = new FixedPointCombMultiplier();
                this.initiator = var1;
                this.staticPrivateKey = var2;
                this.staticPublicPoint = var5.multiply(var4.getG(), var2.getD()).normalize();
                this.ephemeralPrivateKey = var3;
                this.ephemeralPublicPoint = var5.multiply(var4.getG(), var3.getD()).normalize();
            }
        }
    }


}
