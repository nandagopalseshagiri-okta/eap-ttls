package com.okta.radius.eap;

import static com.okta.radius.eap.LogHelper.log;

/**
 * Created by nandagopal.seshagiri on 8/28/18.
 */
public class TargetBoundAppProtocolContext implements AppProtocolContext {
    private byte eapId = 1;
    private byte ttlsId = 0;

    private int flag = 0;
    private Long messageLength;
    private int mtu = 256;
    private String name = "";

    private boolean isServerMode;

    public TargetBoundAppProtocolContext(int mtu, String name, boolean isServerMode) {
        this.mtu = mtu;
        this.name = name;
        this.isServerMode = isServerMode;
    }

    public TargetBoundAppProtocolContext() {
    }

    public static AppProtocolContext makeAppProtocolContext(final int mtu) {
        return makeAppProtocolContext(mtu, "Default", true);
    }

    public static AppProtocolContext makeAppProtocolContext(final int mtu, final String name, boolean isServerMode) {
        return new TargetBoundAppProtocolContext(mtu, name, isServerMode);
    }

    public EAPTTLSPacket makeEAPTTLSPacket() {
        EAPTTLSPacket packet = new EAPTTLSPacket();
        packet.setCode(isServerMode ? 1 : 2);
        packet.setIdentifier(ttlsId & 0x000000FF);
        packet.setFlag(flag);
        packet.setType(21); // 21 is for EAP-TTLS
        if (messageLength != null) {
            packet.setMessageLength(messageLength);
        }
        return packet;
    }

    public EAPPacket makeEAPPacket() {
        EAPPacket packet1 = new EAPPacket();
        packet1.setCode(1);
        packet1.setIdentifier(eapId++ & 0x000000FF);
        return packet1;
    }

    public void setStartFlag() {
        flag = flag | 0x20;
    }

    public void setFragmentFlag() {
        log(name + " Setting more fragment flag");
        flag = flag | 0x40;
    }

    public void setLengthFlag(long totalTTLSPacketLength) {
        log(name + " Setting length flag");
        messageLength = totalTTLSPacketLength;
        // will set both L (Length) and F (fragment) flag
        flag = flag | 0xC0;
    }

    public void resetFlags() {
        log(name + " Resetting flag");
        flag = 0;
    }

    public int getNetworkMTU() {
        return mtu;
    }

    @Override
    public void latchToIncomingPacketIdentifier(int packetId) {
        if (!isServerMode) {
            ttlsId = (byte) (packetId & 0xFF);
        }
    }

    @Override
    public void incrementPacketId() {
        if (isServerMode) {
            ++ttlsId;
        }
    }
}
