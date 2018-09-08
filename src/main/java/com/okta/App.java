package com.okta;

import com.okta.radius.eap.AppProtocolContext;
import com.okta.radius.eap.DatagramPacketSink;
import com.okta.radius.eap.EAPOrchestrator;
import com.okta.radius.eap.EAPPacket;
import com.okta.radius.eap.EAPStackBuilder;
import com.okta.radius.eap.EAPTTLSPacket;
import com.okta.radius.eap.LogHelper;
import org.tinyradius.attribute.RadiusAttribute;
import org.tinyradius.packet.RadiusPacket;
import org.tinyradius.util.RadiusServer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.List;

import static com.okta.radius.eap.EAPTTLSPacket.makeWrappedOutputStream;

public class App
{
    static byte[] readPacket() {
        return new byte[0];
    }

    private static class DataCollector extends ByteArrayOutputStream {
        public byte[] getBytes() {
            return buf;
        }
    }

    public static byte[] feedDownProtocolStack(byte[] input, AppProtocolContext context) {
        DataCollector dc = new DataCollector();
        EAPTTLSPacket packet = context.makeEAPTTLSPacket();
        packet.writeToStream(new DataOutputStream(EAPPacket.makeWrappedOutputStream(dc, context)), input, input.length);
        return dc.getBytes();
    }

    public static String sharedSecret = "notImportant";

    public static class TestRadiusServer extends RadiusServer {
        @Override
        public String getSharedSecret(InetSocketAddress inetSocketAddress) {
            return sharedSecret;
        }

        @Override
        public String getUserPassword(String s) {
            return null;
        }

        public RadiusPacket fromDatagram(DatagramPacket datagramPacket) {
            try {
                return makeRadiusPacket(datagramPacket, sharedSecret);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    };

    private static ByteBuffer combine(List<RadiusAttribute> attributes) {
        ByteBuffer buffer = ByteBuffer.allocate(attributes.size() * 256);
        for (RadiusAttribute a : attributes) {
            buffer.put(a.getAttributeData());
        }
        buffer.flip();
        return buffer;
    }

    public static void testRadiusServerIntegration(int port, String sharedSecret) throws Exception {
        final DatagramSocket socket = new DatagramSocket(port);
        EAPStackBuilder.UdpByteBufferStream readStream = new EAPStackBuilder.UdpByteBufferStream(socket);
        EAPOrchestrator eapOrchestrator = new EAPOrchestrator(sharedSecret);
        TestRadiusServer rs = new TestRadiusServer();

        DatagramPacketSink dps = new DatagramPacketSink() {
            @Override
            public void send(DatagramPacket packet) throws IOException {
                socket.send(packet);
            }
        };

        while (true) {
            DatagramPacket dp = readStream.readPacket();
            byte actualPacketType = 0;
            if (dp.getData().length > 0) {
                actualPacketType = dp.getData()[0];
                dp.getData()[0] = 2;
            }
            RadiusPacket packet = rs.fromDatagram(dp);
            List<RadiusAttribute> attrs = packet.getAttributes(79);
            if (attrs.isEmpty()) {
                System.out.println("No EAP message in the RADIUS packet - ignoring packet");
                continue;
            }

            System.out.println("Received RADIUS packet with EAP message id=" + packet.getPacketIdentifier());

            ByteBuffer eapData = combine(attrs);
            eapOrchestrator.handleEAPMessage((InetSocketAddress) dp.getSocketAddress(), eapData, dps, packet);
        }
    }

    public static void main( String[] args ) {
        try {
            int port = 1812;
            String ss = App.sharedSecret;
            if (args.length > 0) {
                port = Integer.parseInt(args[0]);
            }
            if (args.length > 1) {
                ss = args[1];
            }
            testRadiusServerIntegration(port, ss);
        } catch (Exception e) {
            LogHelper.log("Failed with exception e = " + e);
        }
    }
}
