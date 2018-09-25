package com.okta.radius.eap;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Created by nandagopal.seshagiri on 9/18/18.
 */
public class EAPTTLSTransceiver implements ByteBufferReceiver, ByteBufferTransmitter {
    // It is ok to pass null for lower level stream as reading from the stream will never be done from here
    private EAPTTLSPacket.EAPTTLSPacketStream eapttlsPacketStream = new EAPTTLSPacket.EAPTTLSPacketStream(null);

    private AppProtocolContext appProtocolContext;

    private StreamUtils.DataCollector receiveBuffer = new StreamUtils.DataCollector();

    private boolean readingFragment = false;

    private ByteBufferReceiver byteBufferReceiver;

    private boolean waitingForAck = false;

    private StreamUtils.DataCollector transmitBuffer = new StreamUtils.DataCollector();

    private int transmitBufferPosition = 0;

    private ByteBufferTransmitter byteBufferTransmitter;

    private DataOutputStream eapTtlsOutputStream;

    public EAPTTLSTransceiver(AppProtocolContext context, ByteBufferReceiver receiver, ByteBufferTransmitter transmitter) {
        appProtocolContext = context;
        byteBufferReceiver = receiver;
        byteBufferTransmitter = transmitter;
        TransmitterOutputStreamAdapter lowerOutputStream = new TransmitterOutputStreamAdapter(byteBufferTransmitter);
        eapTtlsOutputStream = new DataOutputStream(EAPTTLSPacket.makeWrappedOutputStream(lowerOutputStream,
                appProtocolContext));
    }

    @Override
    public void receive(ByteBuffer byteBuffer) {
        StreamUtils.PacketAndData<EAPTTLSPacket> pd = eapttlsPacketStream.fromByteBuffer(byteBuffer);
        if (waitingForAck) {
            waitingForAck = false;
            ensureAck(pd);
            transmitFromTransmitBuffer(getMaxFragmentSize(), 0);
            return;
        }

        receiveBuffer.write(pd.data.array(), 0, pd.data.limit());
        if (!readingFragment) {
            appProtocolContext.latchToIncomingPacketIdentifier(pd.packet.getIdentifier());
            readingFragment = pd.packet.isAFragment();
        }

        if (pd.packet.isAFragment()) {
            writeAckPacket();
        } else {
            readingFragment = false;
            if (byteBufferReceiver != null) {
                byteBufferReceiver.receive(ByteBuffer.wrap(receiveBuffer.getBytes(), 0, receiveBuffer.getCount()));
            }
            receiveBuffer.reset();
        }
    }

    @Override
    public void transmit(ByteBuffer byteBuffer) {
        int maxFragmentSize = getMaxFragmentSize();
        if (transmitBuffer.getCount() <= transmitBufferPosition && byteBuffer.limit() <= maxFragmentSize && !waitingForAck) {
            // no pending data in transmit buffer and the byteBuffer to be sent is less than or equal to maxFragmentSize
            // so do direct transmit without copying to transmit buffer.
            transmitFragment(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit(), false);
            return;
        }

        transmitBuffer.write(byteBuffer.array(), byteBuffer.position(), byteBuffer.remaining());
        if (waitingForAck) {
            // cannot transmit while we are waiting for ack for the last sent packet
            return;
        }

        transmitFromTransmitBuffer(maxFragmentSize, byteBuffer.remaining());
    }

    private int getMaxFragmentSize() {
        int maxFragmentSize = appProtocolContext.getNetworkMTU();
        if (maxFragmentSize <= 0) {
            maxFragmentSize = 512;
        }
        return maxFragmentSize;
    }

    private void transmitFromTransmitBuffer(int maxFragmentSize, int fullLength) {
        int remainingLen = transmitBuffer.getCount() - transmitBufferPosition;
        if (remainingLen <= 0) {
            System.out.println("Nothing to transmit FromTransmitBuffer remaining length = " + remainingLen);
            return;
        }
        appProtocolContext.resetFlags();
        boolean transmittingFragment = true;
        if (transmitBufferPosition == 0 && remainingLen > maxFragmentSize) {
            appProtocolContext.setLengthFlag(fullLength);
        } else if (remainingLen > maxFragmentSize) {
            appProtocolContext.setFragmentFlag();
        } else if (remainingLen <= maxFragmentSize){
            transmittingFragment = false;
        }

        transmitBufferPosition += transmitFragment(transmitBuffer.getBytes(), transmitBufferPosition,
                Math.min(remainingLen, maxFragmentSize), transmittingFragment);

        if (transmitBufferPosition >= transmitBuffer.getCount()) {
            transmitBuffer.reset();
            transmitBufferPosition = 0;
        }
    }

    private int transmitFragment(byte[] array, int offset, int length, boolean transmittingFragment) {
        try {
            appProtocolContext.incrementPacketId();
            System.out.println("Writing packet size = " + length + " as fragment = " + transmittingFragment);
            eapTtlsOutputStream.write(array, offset, length);
            eapTtlsOutputStream.flush();
            waitingForAck = transmittingFragment;
            return length;
        } catch (IOException e) {
            throw new EAPOutputException(e);
        }
    }

    // Expect the caller to have set the right flags in the context to ensure that packet with
    // right flags go out.
    public void transmitEmptyEAPPacket() {
        writeAckPacket();
    }

    private void writeAckPacket() {
        try {
            eapTtlsOutputStream.flush();
        } catch (IOException e) {
            throw new EAPOutputException(e);
        }
    }

    private void ensureAck(StreamUtils.PacketAndData<EAPTTLSPacket> pd) {
        if (pd.data.limit() != 0) {
            throw new TTLSProtocolException("Expected TTLS ack packet with no data - received data with length = " + pd.data.limit());
        }

        if (pd.packet.getFlag() != 0) {
            throw new TTLSProtocolException("Expected TTLS ack packet with no flags set");
        }
    }

    private static class TransmitterOutputStreamAdapter extends ByteArrayOutputStream {
        private ByteBufferTransmitter byteBufferTransmitter;

        public TransmitterOutputStreamAdapter(ByteBufferTransmitter byteBufferTransmitter) {
            this.byteBufferTransmitter = byteBufferTransmitter;
        }

        @Override
        public void flush() throws IOException {
            super.flush();
            byteBufferTransmitter.transmit(ByteBuffer.wrap(buf, 0, count));
            this.reset();
        }
    }
}
