package com.okta.radius.eap;

/**
 * Created by nandagopal.seshagiri on 1/12/18.
 */
public class InvalidEAPPacketException extends RuntimeException {
    public InvalidEAPPacketException(Exception inner) {
        super(inner);
    }

    public InvalidEAPPacketException(String msg) {
        super(msg);
    }
}
