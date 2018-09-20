package com.okta.radius.eap;

import java.nio.ByteBuffer;

/**
 * Created by nandagopal.seshagiri on 9/17/18.
 */
public interface ByteBufferReceiver {
    void receive(ByteBuffer byteBuffer);
}
