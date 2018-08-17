package com.okta.radius.eap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

/**
 * Created by nandagopal.seshagiri on 1/23/18.
 */
public class StreamUtils {
    public static void pipe(InputStream is, OutputStream os) throws IOException {
        byte[] bandwidthBuf = new byte[256];
        while (true) {
            int readCount = is.read(bandwidthBuf);
            if (readCount == -1) {
                break;
            }

            os.write(bandwidthBuf, 0, readCount);

            if (readCount < bandwidthBuf.length) {
                break;
            }
        }
    }

    public interface ByteBufferInputStream {
        ByteBuffer read();
    }

    public interface ByteBufferOutputStream {
        void write(ByteBuffer byteBuffer);
    }

    public static class PacketAndData<P> {
        public P packet;
        public ByteBuffer data;
    }

    public interface PacketInputStream<P> extends ByteBufferInputStream {
        PacketAndData<P> readPacket();
    }

    public static abstract class PacketInputStreamImpl<T> implements StreamUtils.PacketInputStream<T> {
        private StreamUtils.ByteBufferInputStream lowerLayerStream;

        public PacketInputStreamImpl(StreamUtils.ByteBufferInputStream lls) {
            lowerLayerStream = lls;
        }

        public ByteBuffer read() {
            return readPacket().data;
        }

        public StreamUtils.PacketAndData<T> readPacket() {
            ByteBuffer eapTTLSData = lowerLayerStream.read();
            StreamUtils.DataCollector bos = new StreamUtils.DataCollector();
            StreamUtils.PacketAndData<T> pd = new StreamUtils.PacketAndData<T>();
            pd.packet = createPacketFromStream(new DataInputStream(new ByteArrayInputStream(eapTTLSData.array(), 0, eapTTLSData.limit())), bos);
            pd.data = ByteBuffer.wrap(bos.getBytes(), 0, bos.getCount());
            return pd;
        }

        public abstract T createPacketFromStream(DataInputStream dataInputStream, OutputStream outputStream);
    }

    public static class DataCollector extends ByteArrayOutputStream {
        public byte[] getBytes() {
            return buf;
        }

        public int getCount() {
            return this.count;
        }
    }
}
