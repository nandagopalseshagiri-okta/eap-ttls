package com.okta.radius.eap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

/**
 * Created by nandagopal.seshagiri on 1/23/18.
 */
public class EAPTTLSPacket {
    private static int MIN_DATA_LENGTH = 6;
    private static int MAX_DATA_LENGTH = 0xffff;

    // 1 byte
    private int code;

    // 1 byte
    private int identifier;

    // 2 byte
    private int length;

    // 1 byte
    private int type;

    // 1 byte
    private int flag;

    // 4 bytes
    // The complete length of the TLS packet before fragmentation
    private long messageLength;

    // Rest of the packet's data is payload
    // private byte[] data


    public int getCode() {
        return code;
    }

    public int getIdentifier() {
        return identifier;
    }

    public int getLength() {
        return length;
    }

    public int getType() {
        return type;
    }

    public int getFlag() {
        return flag;
    }

    public long getMessageLength() {
        return messageLength;
    }

    public boolean hasMessageLength() {
        return (flag & 0x80) == 0x80;
    }

    public boolean isAFragment() {
        return (flag & 0x40) == 0x40;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public void setIdentifier(int identifier) {
        this.identifier = identifier;
    }

    public void setType(int type) {
        this.type = type;
    }

    public void setFlag(int flag) {
        this.flag = flag;
    }

    public void setMessageLength(long messageLength) {
        this.messageLength = messageLength;
    }

    public static EAPTTLSPacket fromStream(DataInputStream di, OutputStream os) {
        try {
            EAPTTLSPacket packet = new EAPTTLSPacket();
            packet.code = di.readByte() & 0x000000FF;
            packet.identifier = di.readByte() & 0x000000FF;
            packet.length = di.readShort() & 0x0000FFFF;
            if (packet.length < MIN_DATA_LENGTH || packet.length > MAX_DATA_LENGTH) {
                throw new InvalidEAPTTLSPacketException("Invalid packet length = " + packet.length);
            }

            packet.type = di.readByte() & 0x000000FF;
            packet.flag = di.readByte() & 0x000000FF;
            if (packet.hasMessageLength()) {
                packet.messageLength = di.readInt() & 0x00000000FFFFFFFFL;
            }

            byte[] data = new byte[packet.length - MIN_DATA_LENGTH - (packet.hasMessageLength() ? 4 : 0)];
            if (data.length > 0) {
                di.read(data);
                os.write(data);
                os.flush();
            }
            return packet;
        } catch (IOException e) {
            throw new InvalidEAPTTLSPacketException(e);
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
            EAPTTLSPacket packet = context.makeEAPTTLSPacket();
            packet.writeToStream(new DataOutputStream(outer), this.buf, this.count);
            this.reset();
        }
    }

    public static OutputStream makeWrappedOutputStream(OutputStream os, AppProtocolContext context) {
        return new WrappedOutputStream(os, context);
    }

    public void writeToStream(DataOutputStream dos, byte[] data, int len) {
        try {
            dos.writeByte(code);
            dos.writeByte(identifier);
            length = MIN_DATA_LENGTH + len + (hasMessageLength() ? 4 : 0);
            dos.writeShort(length);
            dos.writeByte(type);
            dos.writeByte(flag);
            if (hasMessageLength()) {
                dos.writeInt((int) messageLength);
            }
            dos.write(data, 0, len);
            dos.flush();
        } catch (IOException e) {
            throw new OutputStreamException(e);
        }
    }

    public static class EAPTTLSPacketStream extends StreamUtils.PacketInputStreamImpl<EAPTTLSPacket> {
        public EAPTTLSPacketStream(StreamUtils.ByteBufferInputStream lls) {
            super(lls);
        }

        public EAPTTLSPacket createPacketFromStream(DataInputStream dataInputStream, OutputStream outputStream) {
            return fromStream(dataInputStream, outputStream);
        }
    }
}
