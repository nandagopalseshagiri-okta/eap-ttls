package com.okta;

import com.okta.radius.eap.AppProtocolContext;
import com.okta.radius.eap.EAPOutputException;
import com.okta.radius.eap.EAPPacket;
import com.okta.radius.eap.EAPStackBuilder;
import com.okta.radius.eap.EAPTTLSPacket;
import com.okta.radius.eap.InvalidEAPPacketException;
import com.okta.radius.eap.StreamUtils;
import com.okta.radius.eap.TTLSByteBufferInputStream;
import com.okta.radius.eap.TTLSByteBufferOutputStream;
import junit.framework.TestCase;

import javax.net.ssl.SSLEngine;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * Created by nandagopal.seshagiri on 8/9/18.
 */
public class EAPTTLSPacketTest extends TestCase {


    public void testMakePacketFromStream() {
        byte[] packetData = new byte[] {1, 2, 0, 11, 7, 0, 10, 11, 12, 13, 14};
        StreamUtils.DataCollector bos = new StreamUtils.DataCollector();
        EAPTTLSPacket packet = EAPTTLSPacket.fromStream(new DataInputStream(new ByteArrayInputStream(packetData)), bos);

        assertTrue(packet.getCode() == 1);
        assertTrue(packet.getIdentifier() == 2);
        assertTrue(packet.getLength() == packetData.length);
        assertTrue(packet.getType() == 7);
        assertTrue(packet.getFlag() == 0);

        byte[] data = new byte[] {10, 11, 12, 13, 14};
        assertTrue(Arrays.equals(bos.toByteArray(), data));

        StreamUtils.DataCollector outPacket = new StreamUtils.DataCollector();
        packet.writeToStream(new DataOutputStream(outPacket), data, data.length);

        assertTrue(Arrays.equals(outPacket.toByteArray(), packetData));
    }

    public void testEAPPacketStreaming() {
        byte[] packetData = new byte[] {1, 2, 0, 11, 7, 0, 10, 11, 12, 13, 14};
        StreamUtils.DataCollector bos = new StreamUtils.DataCollector();
        EAPTTLSPacket packet = EAPTTLSPacket.fromStream(new DataInputStream(new ByteArrayInputStream(packetData)), bos);

        AppProtocolContext context = new AppProtocolContext() {
            private byte id = 1;

            public EAPTTLSPacket makeEAPTTLSPacket() {
                return null;
            }

            public EAPPacket makeEAPPacket() {
                EAPPacket packet1 = new EAPPacket();
                packet1.setCode(112);
                packet1.setIdentifier(id++ & 0x000000FF);
                return packet1;
            }

            public void setStartFlag() {
            }

            public void setFragmentFlag() {
            }

            public void setLengthFlag(long totalTTLSPacketLength) {
            }

            public void resetFlags() {
            }

            public int getNetworkMTU() {
                return 0;
            }
        };

        StreamUtils.DataCollector dc = new StreamUtils.DataCollector();
        DataOutputStream eapStream = new DataOutputStream(EAPPacket.makeWrappedOutputStream(dc, context));

        packet.writeToStream(eapStream, bos.getBytes(), bos.getCount());

        byte[] eapPacketData = new byte[] {112, 1, 0, 15, 1, 2, 0, 11, 7, 0, 10, 11, 12, 13, 14};
        assertTrue(Arrays.equals(dc.toByteArray(), eapPacketData));
    }

    public static AppProtocolContext makeAppProtocolContext(final int mtu) {
        return makeAppProtocolContext(mtu, "Default");
    }

    public static AppProtocolContext makeAppProtocolContext(final int mtu, final String name) {
        return new AppProtocolContext() {
            private byte eapId = 1;
            private byte ttlsId = 1;

            private int flag = 0;
            private Long messageLength;

            public EAPTTLSPacket makeEAPTTLSPacket() {
                EAPTTLSPacket packet = new EAPTTLSPacket();
                packet.setCode(1);
                packet.setIdentifier(ttlsId++ & 0x000000FF);
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
                flag = flag | 4;
            }

            public void setFragmentFlag() {
                log(name + " Setting more fragment flag");
                flag = flag | 2;
            }

            public void setLengthFlag(long totalTTLSPacketLength) {
                log(name + " Setting length flag");
                messageLength = totalTTLSPacketLength;
                // will set both L (Length) and F (fragment) flag
                flag = flag | 3;
            }

            public void resetFlags() {
                log(name + " Resetting flag");
                flag = 0;
            }

            public int getNetworkMTU() {
                return mtu;
            }
        };
    }

    private static void log(String str) {
        System.out.println(str);
    }

    public void testEAPTTLS_EAP_Stacking() throws Exception {
        AppProtocolContext context = makeAppProtocolContext(0);

        StreamUtils.DataCollector dc = new StreamUtils.DataCollector();

        DataOutputStream eapStream = new DataOutputStream(EAPPacket.makeWrappedOutputStream(dc, context));

        DataOutputStream eapTtlsStream = new DataOutputStream(EAPTTLSPacket.makeWrappedOutputStream(eapStream, context));

        eapTtlsStream.write(new byte[] {10, 11, 12, 13, 14});
        eapTtlsStream.flush();

        byte[] eapPacketData = new byte[] {1, 1, 0, 15, 1, 1, 0, 11, 21, 0, 10, 11, 12, 13, 14};
        assertTrue(Arrays.equals(dc.toByteArray(), eapPacketData));
    }

    public static class RadiusPacketStream implements StreamUtils.ByteBufferInputStream {
        public ByteBuffer read() {
            return ByteBuffer.wrap(new byte[] {1, 1, 0, 10, 1, 1, 0, 6, 21, 0});
        }
    }

    public void testTTLSPacketStreaming() {
        final byte[] dataBytes = randomBytes(23);
        AppProtocolContext context = makeAppProtocolContext(11);

        final int[] fragmentCounts = new int[] {0};
        StreamUtils.DataCollector dc = new StreamUtils.DataCollector() {
            @Override
            public void flush() {
                ++fragmentCounts[0];
                if (fragmentCounts[0] == 1) {
                    byte[] eapPacketHeader = new byte[]{1, 1, 0, 25, 1, 1, 0, 21, 21, 3, 0, 0, 0, 23};
                    assertTrue(Arrays.equals(Arrays.copyOfRange(this.buf, 0, eapPacketHeader.length), eapPacketHeader));
                    assertTrue(Arrays.equals(Arrays.copyOfRange(this.buf, eapPacketHeader.length, this.count),
                            Arrays.copyOfRange(dataBytes, 0, 11)));
                }

                if (fragmentCounts[0] == 2) {
                    byte[] eapPacketHeader = new byte[]{1, 2, 0, 21, 1, 2, 0, 17, 21, 2};
                    assertTrue(Arrays.equals(Arrays.copyOfRange(this.buf, 0, eapPacketHeader.length), eapPacketHeader));
                    assertTrue(Arrays.equals(Arrays.copyOfRange(this.buf, eapPacketHeader.length, this.count),
                            Arrays.copyOfRange(dataBytes, 11, 22)));
                }

                if (fragmentCounts[0] == 3) {
                    byte[] eapPacketHeader = new byte[]{1, 3, 0, 11, 1, 3, 0, 7, 21, 0};
                    assertTrue(Arrays.equals(Arrays.copyOfRange(this.buf, 0, eapPacketHeader.length), eapPacketHeader));
                    assertTrue(buf[count - 1] == dataBytes[dataBytes.length - 1]);
                }

                this.reset();
            }
        };

        DataOutputStream eapStream = new DataOutputStream(EAPPacket.makeWrappedOutputStream(dc, context));

        DataOutputStream eapTtlsOutputStream = new DataOutputStream(EAPTTLSPacket.makeWrappedOutputStream(eapStream, context));

        RadiusPacketStream radiusPacketStream = new RadiusPacketStream();

        EAPPacket.EAPPacketStream eapPacketStream = new EAPPacket.EAPPacketStream(radiusPacketStream);
        EAPTTLSPacket.EAPTTLSPacketStream eapttlsPacketStream = new EAPTTLSPacket.EAPTTLSPacketStream(eapPacketStream);

        TTLSByteBufferOutputStream ttlsByteBufferOutputStream = new TTLSByteBufferOutputStream(eapTtlsOutputStream, context, eapttlsPacketStream);

        ttlsByteBufferOutputStream.write(ByteBuffer.wrap(dataBytes));

        assertTrue(fragmentCounts[0] == 3);
    }

    public void testTTLSPacketStreamingNoFragmenting() {
        final byte[] dataBytes = randomBytes(23);
        final int mtu = 64;
        AppProtocolContext context = makeAppProtocolContext(mtu);

        final int[] fragmentCounts = new int[] {0};
        StreamUtils.DataCollector dc = new StreamUtils.DataCollector() {
            @Override
            public void flush() {
                ++fragmentCounts[0];
                if (fragmentCounts[0] == 1) {
                    byte[] eapPacketHeader = new byte[]{1, 1, 0, 33, 1, 1, 0, 29, 21, 0};
                    assertTrue(Arrays.equals(Arrays.copyOfRange(this.buf, 0, eapPacketHeader.length), eapPacketHeader));
                    assertTrue(Arrays.equals(Arrays.copyOfRange(this.buf, eapPacketHeader.length, this.count),
                            Arrays.copyOfRange(dataBytes, 0, 23)));
                }

                this.reset();
            }
        };

        DataOutputStream eapStream = new DataOutputStream(EAPPacket.makeWrappedOutputStream(dc, context));

        DataOutputStream eapTtlsOutputStream = new DataOutputStream(EAPTTLSPacket.makeWrappedOutputStream(eapStream, context));

        RadiusPacketStream radiusPacketStream = new RadiusPacketStream();

        EAPPacket.EAPPacketStream eapPacketStream = new EAPPacket.EAPPacketStream(radiusPacketStream);
        EAPTTLSPacket.EAPTTLSPacketStream eapttlsPacketStream = new EAPTTLSPacket.EAPTTLSPacketStream(eapPacketStream);

        TTLSByteBufferOutputStream ttlsByteBufferOutputStream = new TTLSByteBufferOutputStream(eapTtlsOutputStream, context, eapttlsPacketStream);

        ttlsByteBufferOutputStream.write(ByteBuffer.wrap(dataBytes));

        assertTrue(fragmentCounts[0] == 1);
    }


    private static class RadiusPacketStream1 implements StreamUtils.ByteBufferInputStream {
        private int count = 0;
        private byte[] dataBytes = randomBytes(23);
        @Override
        public ByteBuffer read() {
            try {
                ++count;
                if (count == 1) {
                    byte[] eapPacketHeader = new byte[]{1, 1, 0, 25, 1, 1, 0, 21, 21, 3, 0, 0, 0, 23};
                    byte[] frag = Arrays.copyOfRange(dataBytes, 0, 11);
                    StreamUtils.DataCollector bos = new StreamUtils.DataCollector();
                    bos.write(eapPacketHeader);
                    bos.write(frag);
                    return ByteBuffer.wrap(bos.getBytes(), 0, bos.getCount());
                }
                if (count == 2) {
                    byte[] eapPacketHeader = new byte[]{1, 2, 0, 21, 1, 2, 0, 17, 21, 2};
                    byte[] frag = Arrays.copyOfRange(dataBytes, 11, 22);
                    StreamUtils.DataCollector bos = new StreamUtils.DataCollector();
                    bos.write(eapPacketHeader);
                    bos.write(frag);
                    return ByteBuffer.wrap(bos.getBytes(), 0, bos.getCount());
                }
                if (count == 3) {
                    byte[] eapPacketHeader = new byte[]{1, 3, 0, 11, 1, 3, 0, 7, 21, 0};
                    byte[] frag = Arrays.copyOfRange(dataBytes, 22, 23);
                    StreamUtils.DataCollector bos = new StreamUtils.DataCollector();
                    bos.write(eapPacketHeader);
                    bos.write(frag);
                    return ByteBuffer.wrap(bos.getBytes(), 0, bos.getCount());
                }
                throw new RuntimeException("Not expecting more than one call");
            } catch (IOException e) {
                throw new EAPOutputException(e);
            }
        }

        public byte[] getDataBytes() {
            return dataBytes;
        }
    }

    public void testTTLSInput() {
        AppProtocolContext context = makeAppProtocolContext(11);

        final int[] fragmentAckCounts = new int[] {0};
        StreamUtils.DataCollector dc = new StreamUtils.DataCollector() {
            @Override
            public void flush() {
                ++fragmentAckCounts[0];
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                EAPPacket eapPacket = EAPPacket.fromStream(new DataInputStream(new ByteArrayInputStream(this.buf, 0, this.count)), bos);
                assertTrue(eapPacket.getCode() == 1);
                StreamUtils.DataCollector dc = new StreamUtils.DataCollector();
                EAPTTLSPacket eapttlsPacket = EAPTTLSPacket.fromStream(new DataInputStream(new ByteArrayInputStream(bos.toByteArray())), dc);
                assertTrue(eapttlsPacket.getLength() == 6);
                assertTrue(dc.getCount() == 0);
            }
        };

        DataOutputStream eapStream = new DataOutputStream(EAPPacket.makeWrappedOutputStream(dc, context));

        DataOutputStream eapTtlsOutputStream = new DataOutputStream(EAPTTLSPacket.makeWrappedOutputStream(eapStream, context));

        RadiusPacketStream1 radiusPacketStream = new RadiusPacketStream1();

        EAPPacket.EAPPacketStream eapPacketStream = new EAPPacket.EAPPacketStream(radiusPacketStream);
        EAPTTLSPacket.EAPTTLSPacketStream eapttlsPacketStream = new EAPTTLSPacket.EAPTTLSPacketStream(eapPacketStream);

        TTLSByteBufferInputStream ttlsByteBufferInputStream = new TTLSByteBufferInputStream(eapTtlsOutputStream, context,
                eapttlsPacketStream);

        ByteBuffer data = ttlsByteBufferInputStream.read();
        assertTrue(Arrays.equals(Arrays.copyOfRange(data.array(), 0, data.limit()), radiusPacketStream.getDataBytes()));
        assertTrue(fragmentAckCounts[0] == 2);
    }

    private StreamUtils.ByteBufferOutputStream clientOutstream;
    private StreamUtils.ByteBufferInputStream clientInStream;

    private StreamUtils.ByteBufferOutputStream serverOutStream;
    private StreamUtils.ByteBufferInputStream serverInStream;

    private void createUdpOutputStreams() {
        try {
            int port = 2003;
            AppProtocolContext contextServer = EAPTTLSPacketTest.makeAppProtocolContext(256, "Server");
            AppProtocolContext contextClient = EAPTTLSPacketTest.makeAppProtocolContext(256, "Client");
            EAPStackBuilder.ByteBufferSinkNSource server = EAPStackBuilder.makeUdpReadWritePair(port, contextServer);
            EAPStackBuilder.ByteBufferSinkNSource client = EAPStackBuilder.makeUdpReadWritePair(port, InetAddress.getByName("127.0.0.1"),
                    contextClient);
            clientOutstream = client.outputStream;
            serverInStream = server.inputStream;

            clientInStream = client.inputStream;
            serverOutStream = server.outputStream;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void testTTLSOverUdp() throws Exception {
        createUdpOutputStreams();
        final byte[] testData = randomBytes(500);
        final byte[] testData2 = randomBytes(500);

        Thread server = new Thread(new Runnable() {
            @Override
            public void run() {
                ByteBuffer data = serverInStream.read();
                assertTrue(Arrays.equals(Arrays.copyOfRange(data.array(), 0, data.limit()), testData));

                serverOutStream.write(ByteBuffer.wrap(testData2));
            }
        });

        server.start();
        Thread.sleep(1000);
        clientOutstream.write(ByteBuffer.wrap(testData));

        ByteBuffer data = clientInStream.read();
        assertTrue(Arrays.equals(Arrays.copyOfRange(data.array(), 0, data.limit()), testData2));
    }

    private static byte[] randomBytes(int len) {
        byte[] a = new byte[len];
        new Random().nextBytes(a);
        return a;
    }

    public static class TargetBoundAppProtocolContext implements AppProtocolContext {
        @Override
        public EAPTTLSPacket makeEAPTTLSPacket() {
            return null;
        }

        @Override
        public EAPPacket makeEAPPacket() {
            return null;
        }

        @Override
        public void setStartFlag() {

        }

        @Override
        public void setFragmentFlag() {

        }

        @Override
        public void setLengthFlag(long totalTTLSPacketLength) {

        }

        @Override
        public void resetFlags() {

        }

        @Override
        public int getNetworkMTU() {
            return 0;
        }
    }

    public static class SourceBasedMultiplexingPacketQueue {
        private Map<InetSocketAddress, SSLEngineSocketLessHandshake.MemQueuePipe> sourceIPPortToSS = new ConcurrentHashMap<>();

        public StreamUtils.ByteBufferInputStream addSourceNSinkFor(InetSocketAddress source, ByteBuffer packet) {
            SSLEngineSocketLessHandshake.MemQueuePipe queuePipe = null;
            synchronized (this) {
                if (sourceIPPortToSS.containsKey(source)) {
                    queuePipe = sourceIPPortToSS.get(source);
                } else {
                    queuePipe = new SSLEngineSocketLessHandshake.MemQueuePipe(new ArrayBlockingQueue<ByteBuffer>(50));
                    sourceIPPortToSS.put(source, queuePipe);
                }
            }

            if (packet != null) {
                queuePipe.write(packet);
            }

            return queuePipe;
        }

        public boolean routePacketIfKnownSource(InetSocketAddress source, ByteBuffer packet) {
            SSLEngineSocketLessHandshake.MemQueuePipe queuePipe = sourceIPPortToSS.get(source);
            if (queuePipe == null) {
                return false;
            }

            queuePipe.write(packet);
            return true;
        }
    }

    public interface EAPMessageHandler {
        void handleEAPMessage(InetSocketAddress fromAddress, ByteBuffer eapPacket);
        void setDataOuputStream(DataOutputStream globalOutputStream);
    }

    public static class EAPOrchestrator implements EAPMessageHandler {
        private SSLEngineSocketLessHandshake.MemQueuePipe eapInPacketQueue =
                new SSLEngineSocketLessHandshake.MemQueuePipe(new ArrayBlockingQueue<ByteBuffer>(50));

        private EAPStackBuilder.ByteBufferSinkNSource eapSinkNSource;

        private SourceBasedMultiplexingPacketQueue multiplexingPacketQueue =
                new SourceBasedMultiplexingPacketQueue();

        private DataOutputStream globalOutputStream;

        private volatile boolean eapProcessorStopped = false;

        private ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(20);;

        private SSLEngine newSSLEngine() {
            //TODO: Make the right ssl engine object after setting the right parameters
            return null;
        }

        private void onEAPIdentityPacketReceived(InetSocketAddress fromAddress) {
            StreamUtils.ByteBufferInputStream packetStream = multiplexingPacketQueue.addSourceNSinkFor(fromAddress, null);
            EAPStackBuilder.ByteBufferSinkNSource ss = EAPStackBuilder.buildEAPTTLSStack(globalOutputStream, packetStream,
                    new TargetBoundAppProtocolContext());

            final SSLEngineSocketLessHandshake.SSLByteBufferIOStream sslByteBufferIOStream =
                    new SSLEngineSocketLessHandshake.SSLByteBufferIOStream(newSSLEngine(), ss.outputStream, ss.inputStream,
                    4096*4, 4096*4, "server");

            threadPoolExecutor.submit(new Runnable() {
                @Override
                public void run() {
                    eapPacketProcessingThread(sslByteBufferIOStream);
                }
            });
        }

        @Override
        public void handleEAPMessage(InetSocketAddress fromAddress, ByteBuffer eapPacket) {
            if (multiplexingPacketQueue.routePacketIfKnownSource(fromAddress, eapPacket)) {
                return;
            }

            EAPPacket.EAPPacketStream eapPacketStream = (EAPPacket.EAPPacketStream) eapSinkNSource.inputStream;
            try {
                eapInPacketQueue.write(eapPacket);
                StreamUtils.PacketAndData<EAPPacket> packetAndData = eapPacketStream.readPacket();
                if (packetAndData.packet.getCode() != 1 || packetAndData.data.limit() <= 0) {
                    // if it is not a response EAP packet or there is no data return
                    return;
                }

                if (packetAndData.data.array()[0] != 1) {
                    // not a identity packet - ignore
                    return;
                }

                onEAPIdentityPacketReceived(fromAddress);
            } catch (InvalidEAPPacketException e) {
                // ignore invalid eap packets.
            }
        }

        @Override
        public void setDataOuputStream(DataOutputStream globalOutputStream) {
            this.globalOutputStream = globalOutputStream;
            eapSinkNSource = EAPStackBuilder.buildEAPOnlyStack(globalOutputStream, eapInPacketQueue, new TargetBoundAppProtocolContext());
        }


        private void eapPacketProcessingThread(SSLEngineSocketLessHandshake.SSLByteBufferIOStream sslByteBufferIOStream) {
            while (!eapProcessorStopped) {
                sslByteBufferIOStream.read();
                // TODO: once the hand-shake is done - we should forward to upstream protocol
                // for now we just break out.
                break;
            }
        }
    }
}
