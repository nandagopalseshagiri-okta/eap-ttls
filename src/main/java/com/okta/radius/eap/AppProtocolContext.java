package com.okta.radius.eap;

/**
 * Created by nandagopal.seshagiri on 1/23/18.
 */
public interface AppProtocolContext {
    EAPTTLSPacket makeEAPTTLSPacket();
    EAPPacket makeEAPPacket();
    void setStartFlag();
    void setFragmentFlag();
    void setLengthFlag(long totalTTLSPacketLength);
    void resetFlags();
    int getNetworkMTU();
    void latchToIncomingPacketIdentifier(int packetId);
    void incrementPacketId();
}
