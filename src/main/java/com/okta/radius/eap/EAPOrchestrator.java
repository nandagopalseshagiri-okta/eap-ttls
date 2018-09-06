package com.okta.radius.eap;

import org.tinyradius.packet.RadiusPacket;

import javax.net.ssl.SSLEngine;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * Created by nandagopal.seshagiri on 8/28/18.
 */
public class EAPOrchestrator implements EAPMessageHandler {

    public static class TragetNotBoundException extends RuntimeException {
    }

    private static class TargetedDataoutputStream extends ByteArrayOutputStream {
        private DatagramPacketSink datagramPacketSink;
        private InetSocketAddress target;

        public TargetedDataoutputStream(DatagramPacketSink dps, InetSocketAddress address) {
            datagramPacketSink = dps;
            target = address;
        }

        @Override
        public void flush() throws IOException {
            if (target == null) {
                throw new TragetNotBoundException();
            }
            super.flush();
            datagramPacketSink.send(new DatagramPacket(this.buf, 0, this.count, target));
            this.reset();
        }
    }
    private SSLEngineSocketLessHandshake.MemQueuePipe eapInPacketQueue =
            new SSLEngineSocketLessHandshake.MemQueuePipe(new ArrayBlockingQueue<ByteBuffer>(50));

    private EAPStackBuilder.ByteBufferSinkNSource eapSinkNSource;

    private SourceBasedMultiplexingPacketQueue multiplexingPacketQueue =
            new SourceBasedMultiplexingPacketQueue();

    private volatile boolean eapProcessorStopped = false;

    private ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(20);
    ;

    private SSLEngine newSSLEngine() {
        //TODO: Make the right ssl engine object after setting the right parameters
        return null;
    }

    private String shareSecret;

    public EAPOrchestrator(String sharedSecret) {
        // It is ok to pass null for output stream because NO packets will be attempted to be written via
        // this returned eapSink.
        eapSinkNSource = EAPStackBuilder.buildEAPOnlyStack(null, eapInPacketQueue, new TargetBoundAppProtocolContext());
        this.shareSecret = sharedSecret;
    }

    private void onEAPIdentityPacketReceived(InetSocketAddress fromAddress,
                                             RadiusPacket radiusRequest,
                                             DatagramPacketSink datagramPacketSink) {

        UUID uuidRadiusState = UUID.randomUUID();
        RadiusPacketSink radiusPacketSink = new RadiusPacketSink(uuidRadiusState.toString(), radiusRequest, shareSecret,
                datagramPacketSink);

        TargetedDataoutputStream tds = new TargetedDataoutputStream(radiusPacketSink, fromAddress);
        StreamUtils.ByteBufferInputStream packetStream = multiplexingPacketQueue.addSourceNSinkFor(uuidRadiusState, null);
        final TargetBoundAppProtocolContext boundAppProtocolContext = new TargetBoundAppProtocolContext();
        final EAPStackBuilder.ByteBufferSinkNSource ss = EAPStackBuilder.buildEAPTTLSStack(new DataOutputStream(tds), packetStream,
                boundAppProtocolContext);

        final SSLEngineSocketLessHandshake.SSLByteBufferIOStream sslByteBufferIOStream =
                new SSLEngineSocketLessHandshake.SSLByteBufferIOStream(newSSLEngine(), ss.outputStream, ss.inputStream,
                        4096 * 4, 4096 * 4, "server");

        threadPoolExecutor.submit(new Runnable() {
            @Override
            public void run() {
                eapPacketProcessingThread(sslByteBufferIOStream,
                        ((TTLSByteBufferOutputStream) ss.outputStream).getEapttlsOutStream(), boundAppProtocolContext);
            }
        });
    }

    @Override
    public void handleEAPMessage(InetSocketAddress fromAddress, ByteBuffer eapPacket,
                                 DatagramPacketSink datagramPacketSink, RadiusPacket radiusPacket) {
        if (multiplexingPacketQueue.routePacketIfKnownSource(radiusPacket, eapPacket)) {
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

            onEAPIdentityPacketReceived(fromAddress, radiusPacket, datagramPacketSink);
        } catch (InvalidEAPPacketException e) {
            // ignore invalid eap packets.
        }
    }

    private void eapPacketProcessingThread(SSLEngineSocketLessHandshake.SSLByteBufferIOStream sslByteBufferIOStream,
                                           DataOutputStream eapTTLSSink,
                                           TargetBoundAppProtocolContext context) {
        try {
            context.setStartFlag();
            // not writing any data - just EAP TTLS packet indicating start of TTLS
            eapTTLSSink.flush();
            context.resetFlags();

            while (!eapProcessorStopped) {
                sslByteBufferIOStream.read();
                // TODO: once the hand-shake is done - we should forward to upstream protocol and finally send EAP SUCCESS
                // for now we just break out.
                break;
            }
        } catch (Exception e) {
            System.out.println("Caught exception in eapPacketProcessingThread e=" + e);
        }
    }
}
