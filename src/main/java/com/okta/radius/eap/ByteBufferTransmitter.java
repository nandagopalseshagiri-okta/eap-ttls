package com.okta.radius.eap;

import java.nio.ByteBuffer;

/**
 * Created by nandagopal.seshagiri on 9/18/18.
 */
public interface ByteBufferTransmitter {
    void transmit(ByteBuffer byteBuffer);
}
