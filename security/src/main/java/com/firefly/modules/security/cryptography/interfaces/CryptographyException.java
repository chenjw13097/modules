package com.firefly.modules.security.cryptography.interfaces;

/**
 * @author Jiawei Chan
 * @date 2019-01-09
 */
public class CryptographyException extends Exception {
    public CryptographyException() {
        super();
    }

    public CryptographyException(String message) {
        super(message);
    }

    public CryptographyException(Throwable cause) {
        super(cause);
    }

    public CryptographyException(String message, Throwable cause) {
        super(message, cause);
    }
}
