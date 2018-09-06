package com.okta.radius.eap;

import org.tinyradius.packet.RadiusPacket;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

/**
 * Created by nandagopal.seshagiri on 8/28/18.
 */
public interface EAPMessageHandler {
    void handleEAPMessage(InetSocketAddress fromAddress, ByteBuffer eapPacket,
                          DatagramPacketSink datagramPacketSink, RadiusPacket radiusPacket);
}
