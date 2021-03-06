package com.okta.radius.eap;

import com.google.common.io.BaseEncoding;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static com.okta.radius.eap.EAPStackBuilder.UdpByteBufferStream.datagramSha1;

/**
 * Created by nandagopal.seshagiri on 8/17/18.
 */
public class EAPStackBuilder {
    public static class ByteBufferSinkNSource {
        public StreamUtils.ByteBufferInputStream inputStream;
        public StreamUtils.ByteBufferOutputStream outputStream;
    }

    public static ByteBufferSinkNSource buildEAPTTLSStack(DataOutputStream lowerOutputStream,
                                                          StreamUtils.ByteBufferInputStream lowerPacketInputStream,
                                                          AppProtocolContext context) {
        //DataOutputStream eapStream = new DataOutputStream(EAPPacket.makeWrappedOutputStream(lowerOutputStream, context));

        DataOutputStream eapTtlsOutputStream = new DataOutputStream(EAPTTLSPacket.makeWrappedOutputStream(lowerOutputStream, context));

        //EAPPacket.EAPPacketStream eapPacketStream = new EAPPacket.EAPPacketStream(lowerPacketInputStream);
        EAPTTLSPacket.EAPTTLSPacketStream eapttlsPacketStream = new EAPTTLSPacket.EAPTTLSPacketStream(lowerPacketInputStream);

        ByteBufferSinkNSource pipe = new ByteBufferSinkNSource();
        pipe.inputStream = new TTLSByteBufferInputStream(eapTtlsOutputStream, context,
                eapttlsPacketStream);
        pipe.outputStream = new TTLSByteBufferOutputStream(eapTtlsOutputStream, context, eapttlsPacketStream);

        return pipe;
    }

    public static ByteBufferSinkNSource buildEAPOnlyStack(DataOutputStream lowerOutputStream,
                                                          StreamUtils.ByteBufferInputStream lowerPacketInputStream,
                                                          AppProtocolContext context) {
        final DataOutputStream eapStream = new DataOutputStream(EAPPacket.makeWrappedOutputStream(lowerOutputStream, context));
        final EAPPacket.EAPPacketStream eapPacketStream = new EAPPacket.EAPPacketStream(lowerPacketInputStream);
        ByteBufferSinkNSource pipe = new ByteBufferSinkNSource();
        pipe.inputStream = eapPacketStream;
        pipe.outputStream = new StreamUtils.ByteBufferOutputStream() {
            @Override
            public void write(ByteBuffer byteBuffer) {
                try {
                    eapStream.write(byteBuffer.array(), 0, byteBuffer.limit());
                    eapStream.flush();
                } catch (IOException e) {
                    throw new EAPOutputException(e);
                }
            }
        };
        return pipe;
    }

    public interface TargetAddressProvider {
        InetAddress getTargetIP();
        int getTargetPort();
    }

    public interface TargetAddressSetter {
        void setTargetAddress(InetSocketAddress address);
    }

    public static class UdpFlusher extends ByteArrayOutputStream implements ByteBufferTransmitter {
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
            System.out.println("Sending packet with sha1 = " + datagramSha1(dg) + " size=" + this.count);
            udpSocket.send(dg);
            this.reset();
        }

        @Override
        public void transmit(ByteBuffer byteBuffer) {
            try {
                DatagramPacket dg = new DatagramPacket(byteBuffer.array(), byteBuffer.position(), byteBuffer.remaining(),
                        targetAddressProvider.getTargetIP(), targetAddressProvider.getTargetPort());
                System.out.println("Sending packet with sha1 = " + datagramSha1(dg) + " size=" + byteBuffer.remaining());
                udpSocket.send(dg);
            } catch (IOException e) {
                throw new RuntimeException("Udp transmitter failed with exception", e);
            }
        }
    }

    public static class UdpByteBufferStream implements StreamUtils.ByteBufferInputStream, TargetAddressProvider {
        private DatagramSocket udpSocket;

        private InetAddress returnAddress;
        private int returnPort;

        //private Cache<String, Object> packetCache;

        public UdpByteBufferStream(DatagramSocket s) {
            udpSocket = s;
//            packetCache = CacheBuilder.newBuilder()
//                    .expireAfterWrite(30, TimeUnit.SECONDS)
//                    .maximumSize(100)
//                    .build();
        }

        public static String datagramSha1(DatagramPacket dg) {
            try {
                MessageDigest sha1 = MessageDigest.getInstance("SHA1");
                sha1.update(dg.getData(), 0, dg.getLength());
                return BaseEncoding.base64().encode(sha1.digest());
            } catch (NoSuchAlgorithmException e) {
                return "";
            }
        }

//        private void receiveAndCheckForDup(DatagramPacket dg) {
//            try {
//                while (true) {
//                    udpSocket.receive(dg);
//                    String packetSha = datagramSha1(dg);
//                    if (packetCache.getIfPresent(packetSha) == null) {
//                        return;
//                    }
//                }
//            } catch (Exception e) {
//                throw new EAPOutputException(e);
//            }
//        }

        @Override
        public ByteBuffer read() {
            try {
                byte[] buf = new byte[4096];
                DatagramPacket dg = new DatagramPacket(buf, buf.length);
                udpSocket.receive(dg);
                returnAddress = dg.getAddress();
                returnPort = dg.getPort();
                return ByteBuffer.wrap(dg.getData(), 0, dg.getLength());
            } catch (Exception e) {
                throw new EAPOutputException(e);
            }
        }

        public DatagramPacket readPacket() {
            try {
                byte[] buf = new byte[4096];
                DatagramPacket dg = new DatagramPacket(buf, buf.length);
                udpSocket.receive(dg);
                return dg;
            } catch (Exception e) {
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

    public static ByteBufferSinkNSource makeUdpReadWritePair(int port, AppProtocolContext context) {
        try {
            return makeUdpReadWritePair(new DatagramSocket(port), context);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static ByteBufferSinkNSource makeUdpReadWritePair(DatagramSocket socket, AppProtocolContext context) {
        try {
            UdpByteBufferStream readStream = new UdpByteBufferStream(socket);
            UdpFlusher writeStream = new UdpFlusher(socket, readStream);
            return buildEAPTTLSStack(new DataOutputStream(writeStream), readStream, context);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static ByteBufferSinkNSource makeUdpReadWritePair(int port, InetAddress address, AppProtocolContext context) {
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
