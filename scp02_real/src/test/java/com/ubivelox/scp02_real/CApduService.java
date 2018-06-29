package com.ubivelox.scp02_real;

import com.ubivelox.gaia.GaiaException;

import exception.UbiveloxException;

public interface CApduService
{
    // C-APDU 구현
    public String sendApdu(final String cApdu) throws GaiaException, UbiveloxException;
}
