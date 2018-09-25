package com.okta.radius.eap;

import com.google.common.base.Charsets;
import org.tinyradius.attribute.RadiusAttribute;
import org.tinyradius.attribute.StringAttribute;
import org.tinyradius.dictionary.DefaultDictionary;

import java.nio.ByteBuffer;

/**
 * Created by nandagopal.seshagiri on 9/24/18.
 */
public class RadiusAttributeReceiver implements ByteBufferReceiver {
    private  AppProtocolContext appProtocolContext;
    private String username;
    private String password;

    public RadiusAttributeReceiver(AppProtocolContext context) {
        appProtocolContext = context;
    }

    @Override
    public void receive(ByteBuffer byteBuffer) {
        username = null;
        password = null;

        int initialPos = byteBuffer.position();
        int attrBoundaryPos = initialPos;
        while (byteBuffer.hasRemaining()) {
            int code = byteBuffer.getInt();
            int flagAndLength = byteBuffer.getInt();
            int flag = (int) ((flagAndLength & 0x00000000FF000000L) >> 24);

            int vendorId = -1;
            int lengthOffset = 0;
            if ((flag & 0x80) == 0x80) {
                vendorId = byteBuffer.getInt();
                lengthOffset = 4;
            }

            long length = flagAndLength & 0x0000000000ffffffL;

            int attributeLength = (int) (length & 0x00FFFFFF) - (lengthOffset + 8);

            if (attributeLength < 0 || attributeLength > byteBuffer.remaining()) {
                String message = "Invalid attribute length exception " + attributeLength + " > " + byteBuffer.remaining();
                System.out.println(message);
                throw new RuntimeException(message);
            }

            byte[] attrValue = new byte[attributeLength];
            byteBuffer.get(attrValue);

            RadiusAttribute ra = null;

            if (code != 2) {
                ra = RadiusAttribute.createRadiusAttribute(DefaultDictionary.getDefaultDictionary(), vendorId, code);
                ra.setAttributeData(attrValue);
            } else {
                ra = new StringAttribute(code, passwordFromBytes(attrValue));
            }

            System.out.println("Read attribute of type = " + ra.getAttributeType());

            if (ra.getAttributeType() == 1 || ra.getAttributeType() == 2) {
                ensureUnPwd(ra);
            }

            attrBoundaryPos = byteBuffer.position() - attrBoundaryPos;

            while ((attrBoundaryPos % 4) != 0) {
                byteBuffer.get();
                ++attrBoundaryPos;
            }
        }
    }

    private String passwordFromBytes(byte[] passwordBytes) {
        return new String(passwordBytes, Charsets.UTF_8);
    }

    private void ensureUnPwd(RadiusAttribute ra) {
        if (!(ra instanceof StringAttribute)) {
            String message = "Invalid attribute type " + ra.getClass().getSimpleName();
            System.out.println(message);
            throw new RuntimeException(message);
        }

        StringAttribute sa = (StringAttribute) ra;
        if (sa.getAttributeType() == 1) {
            username = sa.getAttributeValue();
        } else if (sa.getAttributeType() == 2) {
            password = sa.getAttributeValue();
        }

        if (username != null && password != null) {
            System.out.printf("Recevied both username=%s and password=%s - marking success\n", username, password);
            appProtocolContext.setRadiusAccept(true);
            appProtocolContext.setEapSuccess(true);
        }
    }
}
