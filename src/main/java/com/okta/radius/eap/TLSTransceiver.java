package com.okta.radius.eap;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;

import static com.okta.radius.eap.SSLEngineSocketLessHandshake.SSLByteBufferIOStream.expand;
import static com.okta.radius.eap.SSLEngineSocketLessHandshake.isEngineClosed;
import static com.okta.radius.eap.SSLEngineSocketLessHandshake.log;
import static com.okta.radius.eap.SSLEngineSocketLessHandshake.runDelegatedTasks;

/**
 * Created by nandagopal.seshagiri on 9/17/18.
 */
public class TLSTransceiver implements ByteBufferReceiver, ByteBufferTransmitter {
    private static final int MAX_BUFFER_LIMIT = 16 * 1024 * 1024;
    private boolean sslHandShakeDone = false;
    private SSLEngine sslEngine;

    private Object handShaker;

    private int netBufferMax = 4096;
    private int appBufferMax = 4096;
    private String name;
    private ByteBuffer unwrapBuffer;
    private boolean hasUnreadData = false;

    private SSLEngineResult sslEngineResult;

    private ByteBuffer outgoingEncBuffer;
    private ByteBufferTransmitter transmitter;
    private ByteBufferReceiver chainedReceiver;

    public TLSTransceiver(SSLEngine se, String nameForLogging, ByteBufferTransmitter transmitter,
                          ByteBufferReceiver chainedReceiver) {
        sslEngine = se;

        SSLSession session = se.getSession();
        appBufferMax = session.getApplicationBufferSize();
        netBufferMax = session.getPacketBufferSize();

        name = nameForLogging;
        unwrapBuffer = ByteBuffer.allocate(netBufferMax * 2);
        outgoingEncBuffer = ByteBuffer.allocate(netBufferMax);
        this.transmitter = transmitter;
        this.chainedReceiver = chainedReceiver;
    }

    public SSLEngine getSslEngine() {
        return sslEngine;
    }

    public ByteBufferReceiver chain(ByteBufferReceiver chainedReceiver) {
        this.chainedReceiver = chainedReceiver;
        return chainedReceiver;
    }

    public ByteBufferTransmitter chain(ByteBufferTransmitter chainedTransmitter) {
        this.transmitter = chainedTransmitter;
        return chainedTransmitter;
    }

    private void storeSSLHandshakerRef() {
        if (handShaker != null) {
            return;
        }
        try {
            Class sslEngineImpl = sslEngine.getClass();
            Field hsField = sslEngineImpl.getDeclaredField("handshaker");
            hsField.setAccessible(true);

            handShaker = hsField.get(sslEngine);
        } catch (Exception e) {
        }
    }

    public Object releaseHandShaker() {
        Object t = handShaker;
        handShaker = null;
        return t;
    }

    @Override
    public void receive(ByteBuffer byteBuffer) {
        checkState();
        try {
            ByteBuffer appData = unwrap(byteBuffer);
            storeSSLHandshakerRef();
            if (appData != null) {
                appData.flip();
                if (appData.limit() > 0 && chainedReceiver != null) {
                    chainedReceiver.receive(appData);
                }
            }
        } catch (Exception e) {
            throw new TTLSProtocolException("Error when receiving data", e);
        }
    }

    @Override
    public void transmit(ByteBuffer byteBuffer) {
        checkState();
        try {
            wrap(byteBuffer, false);
        } catch (Exception e) {
            throw new TTLSProtocolException("Error when transmitting data", e);
        }
    }

    private ByteBuffer unwrap(ByteBuffer peerData) throws Exception {
        if (hasUnreadData) {
            log("---- " + name + " Read start -----");
            if (peerData == null) {
                log("Received a null byte buffer");
                return null;
            }

            concatToUnwrapBuf(peerData);

            log(name + ": read buffer with limit=" + peerData.limit());
        } else {
            unwrapBuffer.clear();
            unwrapBuffer.put(peerData);
            unwrapBuffer.flip();
        }

        ByteBuffer incomingPlainBuffer = ByteBuffer.allocate(appBufferMax + 50);
        SSLEngineResult.HandshakeStatus handshakeStatus = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
        do {
            int totalBytes = unwrapBuffer.remaining();
            sslEngineResult = sslEngine.unwrap(unwrapBuffer, incomingPlainBuffer);
            hasUnreadData = totalBytes > sslEngineResult.bytesConsumed();
            log(name + " hasUnreadData=" + hasUnreadData + " unwrap: ", sslEngineResult);
            if (sslEngineResult.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                wrap(ByteBuffer.wrap(new byte[]{0}), true);
            } else if (sslEngineResult.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED ||
                    sslEngineResult.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                sslHandShakeDone = true;
            } else {
                handshakeStatus = runDelegatedTasks(sslEngineResult, sslEngine);
                if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                    wrap(ByteBuffer.wrap(new byte[]{0}), true);
                }
            }
        } while (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP && hasUnreadData);
        return incomingPlainBuffer;
    }

    private void wrap(ByteBuffer appData, boolean dummyData) throws Exception {
        log("***** " + name + " Write start ******");

        SSLEngineResult.HandshakeStatus finalStatus = SSLEngineResult.HandshakeStatus.FINISHED;
        do {
            sslEngineResult = sslEngine.wrap(appData, outgoingEncBuffer);
            log(name + " wrap: ", sslEngineResult);

            if (sslEngineResult.bytesConsumed() >= appData.limit() &&
                    (sslEngineResult.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED ||
                            sslEngineResult.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING)) {
                // we are assuming that hand-shake data and app data will not be encrypted together
                // inside the outgoingEncBuffer in one call to wrap.
                sslHandShakeDone = true;
            } else if (sslEngineResult.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                outgoingEncBuffer = expand(outgoingEncBuffer);
            } else if (sslEngineResult.getStatus() != SSLEngineResult.Status.OK) {
                log("SSL engine wrap status is not OK " + sslEngineResult.getStatus());
            }

            finalStatus = runDelegatedTasks(sslEngineResult, sslEngine);
        } while (finalStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP);


        if (outgoingEncBuffer.position() <= 0) {
            log(name + " Writing outgoingEncBuffer with sub zero length=" + outgoingEncBuffer.position());
        } else {
            if (sslHandShakeDone && dummyData) {
                return;
            }
            if (sslHandShakeDone || (!hasUnreadData &&
                    finalStatus != SSLEngineResult.HandshakeStatus.NEED_WRAP)) {
                // Explaining here when we do not want to write to output stream,
                // If there is unread data from last unwrap then we should wait and consume it before
                // sending out wrapped output because there could be more wrapped data after we consume
                // the data from remote peer via next unwrap call.
                // Or, if the handshake result comes out as NEED_WRAP - loop and call wrap again to get more
                // data before sending out the partial data.

                // If we are done with handshaking don't look at anything - just send the output buffer from
                // wrap
                outgoingEncBuffer.flip();
                transmitter.transmit(outgoingEncBuffer);
                outgoingEncBuffer.clear();
            }
        }
    }

    private void concatToUnwrapBuf(ByteBuffer data) {
        ByteBuffer newUnwrap = unwrapBuffer;
        if (data.limit() > (unwrapBuffer.capacity() - unwrapBuffer.remaining())) {
            newUnwrap = allocate(data.limit() + unwrapBuffer.remaining());
        } else {
            unwrapBuffer.compact();
        }

        if (newUnwrap != unwrapBuffer) {
            newUnwrap.put(unwrapBuffer);
        }

        newUnwrap.put(data);

        unwrapBuffer = newUnwrap;
        unwrapBuffer.flip();
    }

    private ByteBuffer allocate(int size) {
        if (size > MAX_BUFFER_LIMIT) {
            throw new RuntimeException("Cannot allocate buffer size " + size);
        }

        return ByteBuffer.allocate(size);
    }

    private void checkState() {
        if (isEngineClosed(sslEngine)) {
            throw new TTLSProtocolException("sslEngine is closed cannot transmit or receive");
        }
    }
}
