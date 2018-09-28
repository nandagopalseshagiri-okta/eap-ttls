package com.okta.radius.eap;

import org.tinyradius.packet.RadiusPacket;

/**
 * Created by nandagopal.seshagiri on 9/28/18.
 */
public interface RadiusResponseModulator {
    void modulateResponse(RadiusPacket request, RadiusPacket response);
}
