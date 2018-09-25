package com.okta.radius.eap;

import org.tinyradius.packet.RadiusPacket;

import javax.net.ssl.SSLEngine;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.UUID;
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
            new SSLEngineSocketLessHandshake.MemQueuePipe();

    private EAPStackBuilder.ByteBufferSinkNSource eapSinkNSource;

    private SourceBasedMultiplexingPacketQueue multiplexingPacketQueue =
            new SourceBasedMultiplexingPacketQueue();

    private volatile boolean eapProcessorStopped = false;

    private ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(20);

    private SSLContextInitializer sslContextInitializer;



    private SSLEngine newSSLEngine() {
        SSLEngine serverEngine = sslContextInitializer.getSslc().createSSLEngine();
        serverEngine.setUseClientMode(false);
        serverEngine.setNeedClientAuth(false);
        serverEngine.setEnabledProtocols(new String[] {"TLSv1"});
        return serverEngine;
    }

    private String shareSecret;

    public EAPOrchestrator(String sharedSecret) {
        // It is ok to pass null for output stream because NO packets will be attempted to be written via
        // this returned eapSink.
        eapSinkNSource = EAPStackBuilder.buildEAPOnlyStack(null, eapInPacketQueue, new TargetBoundAppProtocolContext());
        this.shareSecret = sharedSecret;
        Path path = FileSystems.getDefault().getPath("keystore.jks");
        sslContextInitializer = new SSLContextInitializer(path.toAbsolutePath().toString(), path.toAbsolutePath().toString(), "password");
    }

    private void onEAPIdentityPacketReceived(InetSocketAddress fromAddress,
                                             RadiusPacket radiusRequest,
                                             DatagramPacketSink datagramPacketSink) {

        UUID uuidRadiusState = UUID.randomUUID();
        final TargetBoundAppProtocolContext boundAppProtocolContext = new TargetBoundAppProtocolContext(256, "server", true);
        RadiusPacketSink.RadiusRequestInfoProviderImpl rrpp = new RadiusPacketSink.RadiusRequestInfoProviderImpl(radiusRequest);
        RadiusPacketSink radiusPacketSink = new RadiusPacketSink(uuidRadiusState.toString(), rrpp, shareSecret,
                datagramPacketSink, boundAppProtocolContext);

        TargetedDataoutputStream tds = new TargetedDataoutputStream(radiusPacketSink, fromAddress);
        StreamUtils.ByteBufferInputStream packetStream = multiplexingPacketQueue.addSourceNSinkFor(uuidRadiusState, rrpp);

        final EAPStackBuilder.ByteBufferSinkNSource ss = EAPStackBuilder.buildEAPTTLSStack(new DataOutputStream(tds), packetStream,
                boundAppProtocolContext);

        final SSLEngineSocketLessHandshake.SSLByteBufferIOStream sslByteBufferIOStream =
                new SSLEngineSocketLessHandshake.SSLByteBufferIOStream(newSSLEngine(), ss.outputStream, ss.inputStream, "server");

        threadPoolExecutor.submit(new Runnable() {
            @Override
            public void run() {
                eapPacketProcessingThread(sslByteBufferIOStream,
                        ((TTLSByteBufferOutputStream) ss.outputStream).getEapttlsOutStream(), boundAppProtocolContext);
            }
        });
    }

    private void onEAPIdentityPacketReceivedEx(InetSocketAddress fromAddress,
                                             RadiusPacket radiusRequest,
                                             DatagramPacketSink datagramPacketSink) {
        UUID uuidRadiusState = UUID.randomUUID();
        final TargetBoundAppProtocolContext contextServer = new TargetBoundAppProtocolContext(256, "server", true);
        RadiusPacketSink.RadiusRequestInfoProviderImpl rrpp = new RadiusPacketSink.RadiusRequestInfoProviderImpl(radiusRequest);
        RadiusPacketSink radiusPacketSink = new RadiusPacketSink(uuidRadiusState.toString(), rrpp, shareSecret,
                datagramPacketSink, contextServer);

        TargetBoundedTransmitter targetBoundedTransmitter = new TargetBoundedTransmitter(rrpp, radiusPacketSink);

        TLSTransceiver tlsTransceiver = new TLSTransceiver(newSSLEngine(), "server", null, null);
        EAPTTLSTransceiver eapttlsTransceiver = new EAPTTLSTransceiver(contextServer, tlsTransceiver, targetBoundedTransmitter);
        tlsTransceiver.chain((ByteBufferTransmitter) eapttlsTransceiver);

        rrpp.chain(eapttlsTransceiver);

        multiplexingPacketQueue.addSourceNSinkFor(uuidRadiusState, rrpp);

        rrpp.setRequestPacket(radiusRequest);
        rrpp.setTargetAddress(fromAddress);

        RadiusAttributeReceiver radiusAttributeReceiver = new RadiusAttributeReceiver(contextServer);

        tlsTransceiver.chain(radiusAttributeReceiver);

        contextServer.setStartFlag();
        // not writing any data - just EAP TTLS packet indicating start of TTLS
        eapttlsTransceiver.transmitEmptyEAPPacket();
        contextServer.resetFlags();
    }

    @Override
    public void handleEAPMessage(InetSocketAddress fromAddress, ByteBuffer eapPacket,
                                 DatagramPacketSink datagramPacketSink, RadiusPacket radiusPacket) {
        if (multiplexingPacketQueue.routePacketIfKnownSource(fromAddress, radiusPacket, eapPacket)) {
            return;
        }

        EAPPacket.EAPPacketStream eapPacketStream = (EAPPacket.EAPPacketStream) eapSinkNSource.inputStream;
        try {
            eapInPacketQueue.write(eapPacket);
            StreamUtils.PacketAndData<EAPPacket> packetAndData = eapPacketStream.readPacket();
            if (packetAndData.packet.getCode() != 2 || packetAndData.data.limit() <= 0) {
                // if it is not a response EAP packet or there is no data return
                return;
            }

            if (packetAndData.data.array()[0] != 1) {
                // not a identity packet - ignore
                return;
            }

            onEAPIdentityPacketReceivedEx(fromAddress, radiusPacket, datagramPacketSink);
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
                System.out.println("Done with SSL handshake... exiting");
                // TODO: once the hand-shake is done - we should forward to upstream protocol and finally send EAP SUCCESS
                // for now we just break out.
                break;
            }
        } catch (Exception e) {
            System.out.println("Caught exception in eapPacketProcessingThread e=" + e);
        }
    }
}
