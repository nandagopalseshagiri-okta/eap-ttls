package com.okta.radius.eap;

import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Created by nandagopal.seshagiri on 8/17/18.
 */
public class TTLSByteBufferOutputStream implements StreamUtils.ByteBufferOutputStream {
    private DataOutputStream eapttlsOutStream;
    private AppProtocolContext appProtocolContext;
    private StreamUtils.PacketInputStream<EAPTTLSPacket> ttlsPacketInputStream;

    public TTLSByteBufferOutputStream(DataOutputStream ttlsStream,
                                      AppProtocolContext context,
                                      StreamUtils.PacketInputStream<EAPTTLSPacket> packetInputStream) {
        eapttlsOutStream = ttlsStream;
        appProtocolContext = context;
        ttlsPacketInputStream = packetInputStream;
    }

    public DataOutputStream getEapttlsOutStream() {
        return eapttlsOutStream;
    }

    public void write(ByteBuffer byteBuffer) {
        int maxFragmentSize = appProtocolContext.getNetworkMTU();
        if (maxFragmentSize <= 0) {
            maxFragmentSize = 512;
        }

        appProtocolContext.incrementPacketId();
        int remainingLen = byteBuffer.limit();
        for (int i = 0; i < byteBuffer.limit(); i += maxFragmentSize) {
            appProtocolContext.resetFlags();
            boolean transmittingFragment = true;
            if (i == 0 && remainingLen > maxFragmentSize) {
                appProtocolContext.setLengthFlag(byteBuffer.limit());
            } else if (remainingLen > maxFragmentSize) {
                appProtocolContext.setFragmentFlag();
            } else if (remainingLen <= maxFragmentSize){
                transmittingFragment = false;
            }

            remainingLen -= transmitFragment(byteBuffer.array(), i, Math.min(remainingLen, maxFragmentSize), transmittingFragment);
        }
    }

    private int transmitFragment(byte[] array, int offset, int length, boolean transmittingFragment) {
        try {
            System.out.println("Writing packet size = " + length + " as fragment = " + transmittingFragment);
            eapttlsOutStream.write(array, offset, length);
            eapttlsOutStream.flush();
            if (transmittingFragment) {
                waitForAck();
            }
            return length;
        } catch (IOException e) {
            throw new EAPOutputException(e);
        }
    }

    private void waitForAck() {
        StreamUtils.PacketAndData<EAPTTLSPacket> pd = ttlsPacketInputStream.readPacket();
        if (pd.data.limit() != 0) {
            throw new TTLSProtocolException("Expected TTLS ack packet with no data - received data with length = " + pd.data.limit());
        }

        if (pd.packet.getFlag() != 0) {
            throw new TTLSProtocolException("Expected TTLS ack packet with no flags set");
        }
    }
}
