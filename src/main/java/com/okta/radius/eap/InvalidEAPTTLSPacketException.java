package com.okta.radius.eap;

/**
 * Created by nandagopal.seshagiri on 1/23/18.
 */
public class InvalidEAPTTLSPacketException extends RuntimeException {
    public InvalidEAPTTLSPacketException(Exception inner) {
        super(inner);
    }

    public InvalidEAPTTLSPacketException(String msg) {
        super(msg);
    }
}
