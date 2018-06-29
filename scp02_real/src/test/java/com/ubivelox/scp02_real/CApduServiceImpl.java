package com.ubivelox.scp02_real;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import com.ubivelox.gaia.GaiaException;
import com.ubivelox.gaia.util.GaiaUtils;

import exception.UbiveloxException;

public class CApduServiceImpl implements CApduService
{
    TerminalFactory terminalFactory = null;
    CardTerminals   cardTerminals   = null;
    CardTerminal    cardTerminal    = null;
    Card            card            = null;





    @Override
    public String sendApdu(final String cApdu) throws GaiaException, UbiveloxException
    {
        byte[] rApdu = null;

        try
        {
            if ( this.terminalFactory == null )
            {

                this.terminalFactory = TerminalFactory.getDefault();
                this.cardTerminals = this.terminalFactory.terminals();
                this.cardTerminal = this.cardTerminals.list()
                                                      .get(0);
                this.card = this.cardTerminal.connect("T=0");
            }

            CardChannel cardChannel = this.card.getBasicChannel();

            ResponseAPDU responseApdu = cardChannel.transmit(new CommandAPDU(GaiaUtils.convertHexaStringToByteArray(cApdu)));

            rApdu = responseApdu.getBytes();

        }
        catch ( CardException e )
        {
            throw new UbiveloxException("카드 에러");
        }

        return GaiaUtils.convertByteArrayToHexaString(rApdu);
    }
}
