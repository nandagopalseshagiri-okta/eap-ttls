package com.okta;

import com.okta.radius.eap.AppProtocolContext;
import com.okta.radius.eap.EAPOutputException;
import com.okta.radius.eap.EAPPacket;
import com.okta.radius.eap.EAPTTLSPacket;
import com.okta.radius.eap.StreamUtils;
import junit.framework.TestCase;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

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

    private AppProtocolContext makeAppProtocolContext(final int mtu) {
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
                flag = flag | 2;
            }

            public void setLengthFlag(long totalTTLSPacketLength) {
                messageLength = totalTTLSPacketLength;
                // will set both L (Length) and F (fragment) flag
                flag = flag | 3;
            }

            public void resetFlags() {
                flag = 0;
            }

            public int getNetworkMTU() {
                return mtu;
            }
        };
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

    public static class TTLSByteBufferOutputStream implements StreamUtils.ByteBufferOutputStream {
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

        public void write(ByteBuffer byteBuffer) {
            int maxFragmentSize = appProtocolContext.getNetworkMTU();
            if (maxFragmentSize <= 0) {
                maxFragmentSize = 512;
            }

            int remainingLen = byteBuffer.limit();
            for (int i = 0; i < byteBuffer.limit(); i += maxFragmentSize) {
                appProtocolContext.resetFlags();
                if (i == 0) {
                    appProtocolContext.setLengthFlag(byteBuffer.limit());
                } else if (remainingLen > maxFragmentSize){
                    appProtocolContext.setFragmentFlag();
                }

                remainingLen -= transmitFragment(byteBuffer.array(), i, Math.min(remainingLen, maxFragmentSize));
            }
        }

        private int transmitFragment(byte[] array, int offset, int length) {
            try {
                eapttlsOutStream.write(array, offset, length);
                eapttlsOutStream.flush();
                waitForAck();
                return length;
            } catch (IOException e) {
                throw new EAPOutputException(e);
            }
        }

        private void waitForAck() {
            StreamUtils.PacketAndData<EAPTTLSPacket> pd = ttlsPacketInputStream.readPacket();
            assertTrue(pd.data.limit() == 0);
        }
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

    private byte[] randomBytes(int len) {
        byte[] a = new byte[len];
        new Random().nextBytes(a);
        return a;
    }
}
