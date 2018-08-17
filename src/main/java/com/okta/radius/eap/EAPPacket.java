package com.okta.radius.eap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

/**
 * Created by nandagopal.seshagiri on 1/12/18.
 */
public class EAPPacket {
    private int code;
    private int identifier;
    // private short length - can be derived from the data.length
    // private byte[] data;

    private static int MIN_PACKET_LENGTH = 4;
    private static int MAX_DATA_LENGTH = 0xffff;

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public int getIdentifier() {
        return identifier;
    }

    public void setIdentifier(int identifier) {
        this.identifier = identifier;
    }

    public static EAPPacket fromStream(DataInputStream dis, OutputStream os) {
        try {
            EAPPacket packet = new EAPPacket();
            packet.code = dis.readByte() & 0x000000FF;
            packet.identifier = dis.readByte() & 0x000000FF;
            int length = dis.readShort();
            if (length < MIN_PACKET_LENGTH || length > MAX_DATA_LENGTH) {
                throw new InvalidEAPPacketException("Invalid packet length = " + String.valueOf(length));
            }

            byte[] data = new byte[length - MIN_PACKET_LENGTH];
            if (data.length > 0) {
                dis.read(data);
                os.write(data);
                os.flush();
            }
            return packet;
        } catch (IOException e) {
            throw new InvalidEAPPacketException(e);
        }
    }

    public void writeToStream(DataOutputStream dos, byte[] data, int length) {
        try {
            dos.writeByte(code);
            dos.writeByte(identifier);
            dos.writeShort(length + MIN_PACKET_LENGTH);
            dos.write(data, 0, length);
            dos.flush();
        } catch (IOException e) {
            throw new OutputStreamException(e);
        }
    }

    private static class WrappedOutputStream extends ByteArrayOutputStream {
        private OutputStream outer;
        private AppProtocolContext context;

        public WrappedOutputStream(OutputStream outer, AppProtocolContext context) {
            super(256);
            this.outer = outer;
            this.context = context;
        }

        @Override
        public void flush() throws IOException {
            super.flush();
            EAPPacket packet = context.makeEAPPacket();
            packet.writeToStream(new DataOutputStream(outer), this.buf, this.count);
            this.reset();
        }
    }

    public static OutputStream makeWrappedOutputStream(OutputStream os, AppProtocolContext context) {
        return new WrappedOutputStream(os, context);
    }

    public static class EAPPacketStream extends StreamUtils.PacketInputStreamImpl<EAPPacket> {
        public EAPPacketStream(StreamUtils.ByteBufferInputStream lls) {
            super(lls);
        }

        public EAPPacket createPacketFromStream(DataInputStream dataInputStream, OutputStream outputStream) {
            return fromStream(dataInputStream, outputStream);
        }
    }
}
