package com.okta.radius.eap;

import com.google.common.base.Charsets;
import org.tinyradius.attribute.RadiusAttribute;
import org.tinyradius.packet.RadiusPacket;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Created by nandagopal.seshagiri on 9/5/18.
 */
public class RadiusPacketSink implements DatagramPacketSink {
    private String radiusStateValue;
    private DatagramPacketSink lowerLevelSink;
    private SSLEngineSocketLessHandshake.RadiusRequestInfoProvider radiusRequestInfoProvider;
    private String shareSecret;
    private AppProtocolContext appProtocolContext;

    private static final int MAX_ATTR_LEN = 253;
    private static final int RADIUS_ACCESS_CHALLENGE = 11;
    private static final int RADIUS_ACCESS_ACCEPT = 2;

    public static final int EAP_MESSAGE_ATTR = 79;
    public static final int RADIUS_STATE_ATTR = 24;
    public static final int MESSAGE_AUTHENTICATOR_ATTR = 80;

    public static class RadiusRequestInfoProviderImpl implements SSLEngineSocketLessHandshake.RadiusRequestInfoProvider,
            EAPStackBuilder.TargetAddressSetter, ByteBufferReceiver {
        private RadiusPacket radiusPacket;

        private InetSocketAddress targetAddress;

        private ByteBufferReceiver chainedReceiver;

        public RadiusRequestInfoProviderImpl(RadiusPacket startingRadiusPacket) {
            radiusPacket = startingRadiusPacket;
        }

        @Override
        public RadiusPacket getRequestPacket() {
            return radiusPacket;
        }

        @Override
        public void setRequestPacket(RadiusPacket packet) {
            radiusPacket = packet;
        }


        @Override
        public InetAddress getTargetIP() {
            checkTargetAddress();
            return targetAddress.getAddress();
        }

        @Override
        public int getTargetPort() {
            checkTargetAddress();
            return targetAddress.getPort();
        }

        @Override
        public void setTargetAddress(InetSocketAddress address) {
            targetAddress = address;
        }

        @Override
        public void receive(ByteBuffer byteBuffer) {
            if (chainedReceiver != null) {
                this.chainedReceiver.receive(byteBuffer);
            }
        }

        public ByteBufferReceiver chain(ByteBufferReceiver chainedReceiver) {
            this.chainedReceiver = chainedReceiver;
            return chainedReceiver;
        }

        private void checkTargetAddress() {
            if (targetAddress == null) {
                throw new RuntimeException("Target address is not set");
            }
        }
    }

    public RadiusPacketSink(String radiusState, SSLEngineSocketLessHandshake.RadiusRequestInfoProvider rrpp, String sharedSecret,
                            DatagramPacketSink lowerSink, AppProtocolContext appProtocolContext) {
        this.radiusStateValue = radiusState;
        this.lowerLevelSink = lowerSink;
        this.radiusRequestInfoProvider = rrpp;
        this.shareSecret = sharedSecret;
        this.appProtocolContext = appProtocolContext;
    }

    @Override
    public void send(DatagramPacket packet) throws IOException {
        MACAdaptedRadiusPacket radiusPacket = new MACAdaptedRadiusPacket();
        radiusPacket.setPacketType(appProtocolContext.getRadiusAccept() ? RADIUS_ACCESS_ACCEPT : RADIUS_ACCESS_CHALLENGE);

        RadiusPacket radiusRequest = radiusRequestInfoProvider.getRequestPacket();
        radiusPacket.setPacketIdentifier(radiusRequest.getPacketIdentifier());

        for(int offset = 0; addEAPAttr(EAP_MESSAGE_ATTR, packet, offset, radiusPacket); offset += MAX_ATTR_LEN) {
        }

        byte[] stateBytes = radiusStateValue.getBytes(Charsets.UTF_8);

        radiusPacket.addAttribute(new RadiusAttribute(RADIUS_STATE_ATTR, stateBytes));

        RadiusAttribute macAttr = new RadiusAttribute(MESSAGE_AUTHENTICATOR_ATTR, new byte[16]);
        radiusPacket.addAttribute(macAttr);

        if (appProtocolContext.getRadiusResponseModulator() != null) {
            appProtocolContext.getRadiusResponseModulator().modulateResponse(radiusRequest, radiusPacket);
        }

        HmacMD5OutputStream hmacMD5OutputStream = new HmacMD5OutputStream(this.shareSecret);
        radiusPacket.encodeResponsePacket(hmacMD5OutputStream, this.shareSecret, radiusRequest);

        macAttr.setAttributeData(hmacMD5OutputStream.getResult());

        radiusPacket.setMacMode(false);

        StreamUtils.DataCollector bos = new StreamUtils.DataCollector(4096);
        radiusPacket.encodeResponsePacket(bos, this.shareSecret, radiusRequest);

        DatagramPacket wrapped = new DatagramPacket(bos.getBytes(), 0, bos.getCount(), packet.getSocketAddress());

        lowerLevelSink.send(wrapped);
        System.out.println("###### Sending RADIUS packet out with id = " + radiusPacket.getPacketIdentifier()
                + " size = " + packet.getLength());
    }

    private static boolean addEAPAttr(int attrType, DatagramPacket packet, int offset, RadiusPacket radiusPacket) {
        if (packet.getData().length <= offset) {
            return false;
        }

        int toIndex = offset + Math.min(MAX_ATTR_LEN, packet.getData().length - offset);

        radiusPacket.addAttribute(new RadiusAttribute(attrType, Arrays.copyOfRange(packet.getData(), offset, toIndex)));
        return true;
    }

    private static class HmacMD5OutputStream extends OutputStream {
        private Mac hmacMD5;
        private byte[] result;
        public HmacMD5OutputStream(String key) {
            try {
                hmacMD5 = Mac.getInstance("HmacMD5");
                SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(Charsets.UTF_8), "HmacMD5");
                hmacMD5.init(keySpec);
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void write(int b) throws IOException {
            hmacMD5.update((byte) (b & 0xFF));
        }

        public void write(byte b[], int off, int len) throws IOException {
            hmacMD5.update(b, off, len);
        }

        @Override
        public void flush() {
            result = hmacMD5.doFinal();
        }

        public byte[] getResult() {
            return result;
        }
    }

    private static class MACAdaptedRadiusPacket extends RadiusPacket {
        private boolean macMode = true;

        public void setMacMode(boolean macMode) {
            this.macMode = macMode;
        }

        protected byte[] createResponseAuthenticator(String sharedSecret, int packetLength, byte[] attributes, byte[] requestAuthenticator) {
            if (macMode) {
                return requestAuthenticator;
            }
            return super.createResponseAuthenticator(sharedSecret, packetLength, attributes, requestAuthenticator);
        }
    }
}
