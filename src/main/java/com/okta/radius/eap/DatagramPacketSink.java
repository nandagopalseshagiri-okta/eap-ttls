package com.okta.radius.eap;

import java.io.IOException;
import java.net.DatagramPacket;

/**
 * Created by nandagopal.seshagiri on 8/28/18.
 */
public interface DatagramPacketSink {
    void send(DatagramPacket packet) throws IOException;
}
