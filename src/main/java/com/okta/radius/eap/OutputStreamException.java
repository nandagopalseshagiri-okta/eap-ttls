package com.okta.radius.eap;

/**
 * Created by nandagopal.seshagiri on 1/12/18.
 */
public class OutputStreamException extends RuntimeException {
    public OutputStreamException(Exception inner) {
        super(inner);
    }
}
