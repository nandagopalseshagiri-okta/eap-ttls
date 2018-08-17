package com.okta.radius.eap;

/**
 * Created by nandagopal.seshagiri on 8/15/18.
 */
public class EAPOutputException extends RuntimeException {
    public EAPOutputException(Exception inner) {
        super(inner);
    }
}
