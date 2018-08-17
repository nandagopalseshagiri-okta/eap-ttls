package com.okta;

import com.okta.radius.eap.AppProtocolContext;
import com.okta.radius.eap.EAPPacket;
import com.okta.radius.eap.EAPTTLSPacket;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;

import static com.okta.radius.eap.EAPTTLSPacket.makeWrappedOutputStream;

/**
 * Hello world!
 *
 */
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

    private static class AppProtocolContextImpl implements AppProtocolContext {
        public EAPTTLSPacket makeEAPTTLSPacket() {
            byte[] packetData = new byte[] {1, 2, 0, 5, 7, 0, 10, 11, 12, 13, 14};
            ByteArrayOutputStream bos = new ByteArrayOutputStream(128);
            EAPTTLSPacket packet = EAPTTLSPacket.fromStream(new DataInputStream(new ByteArrayInputStream(packetData)), bos);
            return packet;
        }

        public EAPPacket makeEAPPacket() {
            return new EAPPacket();
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
    }

    public static byte[] feedDownProtocolStack(byte[] input, AppProtocolContext context) {
        DataCollector dc = new DataCollector();
        EAPTTLSPacket packet = context.makeEAPTTLSPacket();
        packet.writeToStream(new DataOutputStream(EAPPacket.makeWrappedOutputStream(dc, context)), input, input.length);
        return dc.getBytes();
    }

    public static void main( String[] args ) {
        AppProtocolContextImpl appProtocolContext = new AppProtocolContextImpl();

        EAPTTLSPacket packet = appProtocolContext.makeEAPTTLSPacket();
    }
}
