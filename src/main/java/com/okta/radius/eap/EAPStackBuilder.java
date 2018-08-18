package com.okta.radius.eap;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;

/**
 * Created by nandagopal.seshagiri on 8/17/18.
 */
public class EAPStackBuilder {
    public static class ByteBufferPipe {
        public StreamUtils.ByteBufferInputStream inputStream;
        public StreamUtils.ByteBufferOutputStream outputStream;
    }

    public static ByteBufferPipe buildEAPTTLSStack(DataOutputStream lowerOutputStream,
                                                   StreamUtils.ByteBufferInputStream lowerPacketInputStream,
                                                   AppProtocolContext context) {
        DataOutputStream eapStream = new DataOutputStream(EAPPacket.makeWrappedOutputStream(lowerOutputStream, context));

        DataOutputStream eapTtlsOutputStream = new DataOutputStream(EAPTTLSPacket.makeWrappedOutputStream(eapStream, context));

        EAPPacket.EAPPacketStream eapPacketStream = new EAPPacket.EAPPacketStream(lowerPacketInputStream);
        EAPTTLSPacket.EAPTTLSPacketStream eapttlsPacketStream = new EAPTTLSPacket.EAPTTLSPacketStream(eapPacketStream);

        ByteBufferPipe pipe = new ByteBufferPipe();
        pipe.inputStream = new TTLSByteBufferInputStream(eapTtlsOutputStream, context,
                eapttlsPacketStream);
        pipe.outputStream = new TTLSByteBufferOutputStream(eapTtlsOutputStream, context, eapttlsPacketStream);

        return pipe;
    }

    public interface TargetAddressProvider {
        InetAddress getTargetIP();
        int getTargetPort();
    }

    public static class UdpFlusher extends ByteArrayOutputStream {
        private DatagramSocket udpSocket;
        TargetAddressProvider targetAddressProvider;

        public UdpFlusher(DatagramSocket s, TargetAddressProvider provider) {
            udpSocket = s;
            targetAddressProvider = provider;
        }

        @Override
        public void flush() throws IOException {
            super.flush();
            DatagramPacket dg = new DatagramPacket(this.buf, 0, this.count, targetAddressProvider.getTargetIP(),
                    targetAddressProvider.getTargetPort());
            udpSocket.send(dg);
        }
    }

    public static class UdpByteBufferStream implements StreamUtils.ByteBufferInputStream, TargetAddressProvider {
        private DatagramSocket udpSocket;

        private InetAddress returnAddress;
        private int returnPort;

        public UdpByteBufferStream(DatagramSocket s) {
            udpSocket = s;
        }

        @Override
        public ByteBuffer read() {
            try {
                byte[] buf = new byte[4096];
                DatagramPacket dg = new DatagramPacket(buf, buf.length);
                udpSocket.receive(dg);
                returnAddress = dg.getAddress();
                returnPort = dg.getPort();
                return ByteBuffer.wrap(dg.getData(), 0, dg.getLength());
            } catch (IOException e) {
                throw new EAPOutputException(e);
            }
        }

        @Override
        public InetAddress getTargetIP() {
            return returnAddress;
        }

        @Override
        public int getTargetPort() {
            return returnPort;
        }
    }

    private static class TargetAddressProviderImpl implements TargetAddressProvider {
        private int targetPort;
        private InetAddress targetAddress;

        public TargetAddressProviderImpl(InetAddress address, int port) {
            targetAddress = address;
            targetPort = port;
        }

        @Override
        public InetAddress getTargetIP() {
            return targetAddress;
        }

        @Override
        public int getTargetPort() {
            return targetPort;
        }
    }

    public static ByteBufferPipe makeUdpReadWritePair(int port, AppProtocolContext context) {
        try {
            DatagramSocket socket = new DatagramSocket(port);
            UdpByteBufferStream readStream = new UdpByteBufferStream(socket);
            UdpFlusher writeStream = new UdpFlusher(socket, readStream);
            return buildEAPTTLSStack(new DataOutputStream(writeStream), readStream, context);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static ByteBufferPipe makeUdpReadWritePair(int port, InetAddress address, AppProtocolContext context) {
        try {
            DatagramSocket socket = new DatagramSocket();
            UdpFlusher writeStream = new UdpFlusher(socket, new TargetAddressProviderImpl(address, port));
            UdpByteBufferStream readStream = new UdpByteBufferStream(socket);
            return buildEAPTTLSStack(new DataOutputStream(writeStream), readStream, context);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
