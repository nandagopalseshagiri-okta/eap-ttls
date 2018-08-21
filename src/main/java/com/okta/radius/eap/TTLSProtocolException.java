package com.okta.radius.eap;

/**
 * Created by nandagopal.seshagiri on 8/20/18.
 */
public class TTLSProtocolException extends RuntimeException {
    public TTLSProtocolException(String message) {
        super(message);
    }

    public TTLSProtocolException(String message, Exception cause) {
        super(message, cause);
    }
}
