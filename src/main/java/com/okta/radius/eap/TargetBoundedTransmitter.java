package com.okta.radius.eap;

import com.sun.corba.se.impl.protocol.giopmsgheaders.TargetAddress;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

/**
 * Created by nandagopal.seshagiri on 9/24/18.
 */
public class TargetBoundedTransmitter implements ByteBufferTransmitter {
    public static class TargetAddressInvalidException extends RuntimeException {
    }

    private EAPStackBuilder.TargetAddressProvider targetAddressProvider;
    private DatagramPacketSink datagramPacketSink;

    public TargetBoundedTransmitter(EAPStackBuilder.TargetAddressProvider targetAddressProvider,
                                    DatagramPacketSink datagramPacketSink) {
        this.targetAddressProvider = targetAddressProvider;
        this.datagramPacketSink = datagramPacketSink;
    }

    @Override
    public void transmit(ByteBuffer byteBuffer) {
        if (targetAddressProvider.getTargetIP() == null) {
            throw new TargetAddressInvalidException();
        }

        InetSocketAddress socketAddress = new InetSocketAddress(targetAddressProvider.getTargetIP(),
                targetAddressProvider.getTargetPort());

        DatagramPacket wrapped = new DatagramPacket(byteBuffer.array(), byteBuffer.position(), byteBuffer.remaining(),
                socketAddress);

        try {
            datagramPacketSink.send(wrapped);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
