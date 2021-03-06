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
    void setRadiusAccept(boolean radiusAccept);
    void setEapSuccess(boolean eapSuccess);
    boolean getRadiusAccept();
    default RadiusResponseModulator getRadiusResponseModulator() {
        return null;
    }
    default void setRadiusResponseModulator(RadiusResponseModulator radiusResponseModulator) {
    }
    default void enableRadiusResponseModulation(boolean enable) {
    }
}
