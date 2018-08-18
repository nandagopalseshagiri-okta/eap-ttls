package com.okta.radius.eap;

import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Created by nandagopal.seshagiri on 8/17/18.
 */
public class TTLSByteBufferInputStream implements StreamUtils.ByteBufferInputStream {
    private DataOutputStream eapttlsOutStream;
    private AppProtocolContext appProtocolContext;
    private StreamUtils.PacketInputStream<EAPTTLSPacket> ttlsPacketInputStream;

    public TTLSByteBufferInputStream(DataOutputStream ttlsStream,
                                     AppProtocolContext context,
                                     StreamUtils.PacketInputStream<EAPTTLSPacket> packetInputStream) {
        eapttlsOutStream = ttlsStream;
        appProtocolContext = context;
        ttlsPacketInputStream = packetInputStream;
    }

    @Override
    public ByteBuffer read() {
        StreamUtils.DataCollector bos = new StreamUtils.DataCollector();
        StreamUtils.PacketAndData<EAPTTLSPacket> pd = ttlsPacketInputStream.readPacket();
        bos.write(pd.data.array(), 0, pd.data.limit());
        for (; pd.packet.isAFragment(); bos.write(pd.data.array(), 0, pd.data.limit())) {
            writeAckPacket();
            pd = ttlsPacketInputStream.readPacket();
        }
        return ByteBuffer.wrap(bos.getBytes(), 0, bos.getCount());
    }

    private void writeAckPacket() {
        try {
            eapttlsOutStream.flush();
        } catch (IOException e) {
            throw new EAPOutputException(e);
        }
    }
}
