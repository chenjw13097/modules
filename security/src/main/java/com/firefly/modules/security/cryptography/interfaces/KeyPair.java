package com.firefly.modules.security.cryptography.interfaces;

/**
 * @author Jiawei Chan
 * @date 2019-01-09
 */
public class KeyPair<P, V> {
    private P publicKey;
    private V privateKey;

    public KeyPair(P publicKey, V privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public P getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(P publicKey) {
        this.publicKey = publicKey;
    }

    public V getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(V privateKey) {
        this.privateKey = privateKey;
    }
}
