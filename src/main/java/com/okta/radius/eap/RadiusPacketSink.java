package com.okta.radius.eap;

import com.google.common.base.Charsets;
import org.tinyradius.attribute.RadiusAttribute;
import org.tinyradius.packet.RadiusPacket;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Created by nandagopal.seshagiri on 9/5/18.
 */
public class RadiusPacketSink implements DatagramPacketSink {
    private String radiusStateValue;
    private DatagramPacketSink lowerLevelSink;
    private SSLEngineSocketLessHandshake.RadiusRequestPacketProvider radiusRequestPacketProvider;
    private String shareSecret;

    private static final int MAX_ATTR_LEN = 253;
    private static final int RADIUS_ACCESS_CHALLENGE = 11;

    public static final int EAP_MESSAGE_ATTR = 79;
    public static final int RADIUS_STATE_ATTR = 24;
    public static final int MESSAGE_AUTHENTICATOR_ATTR = 80;

    public static class RadiusRequestPacketProviderImpl implements SSLEngineSocketLessHandshake.RadiusRequestPacketProvider {
        private RadiusPacket radiusPacket;

        public RadiusRequestPacketProviderImpl(RadiusPacket startingRadiusPacket) {
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
    }

    public RadiusPacketSink(String radiusState, SSLEngineSocketLessHandshake.RadiusRequestPacketProvider rrpp, String sharedSecret,
                            DatagramPacketSink lowerSink) {
        this.radiusStateValue = radiusState;
        this.lowerLevelSink = lowerSink;
        this.radiusRequestPacketProvider = rrpp;
        this.shareSecret = sharedSecret;
    }

    @Override
    public void send(DatagramPacket packet) throws IOException {
        MACAdaptedRadiusPacket radiusPacket = new MACAdaptedRadiusPacket();
        radiusPacket.setPacketType(RADIUS_ACCESS_CHALLENGE);

        RadiusPacket radiusRequest = radiusRequestPacketProvider.getRequestPacket();
        radiusPacket.setPacketIdentifier(radiusRequest.getPacketIdentifier());

        for(int offset = 0; addEAPAttr(EAP_MESSAGE_ATTR, packet, offset, radiusPacket); offset += MAX_ATTR_LEN) {
        }

        byte[] stateBytes = radiusStateValue.getBytes(Charsets.UTF_8);

        radiusPacket.addAttribute(new RadiusAttribute(RADIUS_STATE_ATTR, stateBytes));

        RadiusAttribute macAttr = new RadiusAttribute(MESSAGE_AUTHENTICATOR_ATTR, new byte[16]);
        radiusPacket.addAttribute(macAttr);

        HmacMD5OutputStream hmacMD5OutputStream = new HmacMD5OutputStream(this.shareSecret);
        radiusPacket.encodeResponsePacket(hmacMD5OutputStream, this.shareSecret, radiusRequest);

        macAttr.setAttributeData(hmacMD5OutputStream.getResult());

        radiusPacket.setMacMode(false);

        StreamUtils.DataCollector bos = new StreamUtils.DataCollector(4096);
        radiusPacket.encodeResponsePacket(bos, this.shareSecret, radiusRequest);

        DatagramPacket wrapper = new DatagramPacket(bos.getBytes(), 0, bos.getCount(), packet.getSocketAddress());

        lowerLevelSink.send(wrapper);
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
