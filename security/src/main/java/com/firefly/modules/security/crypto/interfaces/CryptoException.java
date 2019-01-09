package com.firefly.modules.security.crypto.interfaces;

/**
 * @author Jiawei Chan
 * @date 2019-01-09
 */
public class CryptoException extends Exception {
    public CryptoException() {
        super();
    }

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(Throwable cause) {
        super(cause);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
