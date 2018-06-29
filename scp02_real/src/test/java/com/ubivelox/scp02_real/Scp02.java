package com.ubivelox.scp02_real;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ubivelox.gaia.GaiaException;
import com.ubivelox.gaia.util.GaiaUtils;

import exception.UbiveloxException;

public class Scp02
{

    // D1 : 8050000008EC78EEA2438008A6
    // D2 : 00009151026881950639FF02000D4EB131EA95DE5D29FCFE72F724DC
    // D3 : 848200001070CA81178C079A4A114998A816CBF511
    // ENC Key : 404043434545464649494A4A4C4C4F4F
    // MAC Key : 404043434545464649494A4A4C4C4F4F
    // DE Key : 404043434545464649494A4A4C4C4F4F

    private static final Logger logger = LoggerFactory.getLogger(Scp02.class);

    static CApduService         capduService;





    public static CApduService getCapduService()
    {
        return capduService;
    }





    public static void setCapduService(final CApduService capduService)
    {
        Scp02.capduService = capduService;
    }

    public static class OffCard
    {
        public static String InitializeUpdate_C_APDU     = "";
        public static String ExternalAuthenticate_C_APDU = "";
    }

    // public static class CyberCard
    // {
    // public static String InitializeUpdate_R_APDU = "00009151026881950639FF02000D4EB131EA95DE5D29FCFE72F724DC";
    // }

    public static class Key
    {
        public static String ENCKey = "404043434545464649494A4A4C4C4F4F";
        public static String MACKey = "404043434545464649494A4A4C4C4F4F";
        public static String DEKKey = "404043434545464649494A4A4C4C4F4F";
        // public static final String MACKey = "505053535555565659595A5A5C5C5F5F";
        // public static final String DEKKey = "606063636565666669696A6A6C6C6F6F";
    }





    public static void getMutualAuthentication(final String hostChallenge) throws GaiaException, UbiveloxException
    {
        logger.info(capduService.sendApdu(externalAuthenticate(capduService.sendApdu(initializeUpdate(hostChallenge)), 0)));

    }





    // off-Card가 Card로 보내는 APDU
    public static String initializeUpdate(final String hostChallenge) throws GaiaException, UbiveloxException
    {
        GaiaUtils.checkHexaString(hostChallenge);

        if ( hostChallenge.length() != 16 )
        {
            throw new UbiveloxException("data가 일치 하지 않음");
        }

        String cAPDU = OffCard.InitializeUpdate_C_APDU.substring(0, 10) + hostChallenge;
        logger.info("cAPDU: " + cAPDU);
        return cAPDU;
    }





    public static String getSessionKeyENC(final String sessionTypeOrg, final String sequence_counter) throws UbiveloxException, GaiaException
    {
        GaiaUtils.checkNullOrEmpty(sessionTypeOrg, sequence_counter);
        // constant for C-MAC: '0101'
        // constant for R-MAC: '0102'
        // constant for S-ENC: '0182'
        // constant for DEK: '0181'

        byte[] keyType = null;
        String sessionType = "";

        if ( sessionTypeOrg.contains("C-MAC") )
        {
            keyType = GaiaUtils.convertHexaStringToByteArray(Key.MACKey + Key.MACKey.substring(0, 16));
            sessionType = "0101";
        }
        else if ( sessionTypeOrg.contains("R-MAC") )
        {
            sessionType = "0102";
        }
        else if ( sessionTypeOrg.contains("S-ENC") )
        {
            keyType = GaiaUtils.convertHexaStringToByteArray(Key.ENCKey + Key.ENCKey.substring(0, 16));
            sessionType = "0182";
        }
        else if ( sessionTypeOrg.contains("DEK") )
        {
            keyType = GaiaUtils.convertHexaStringToByteArray(Key.DEKKey + Key.DEKKey.substring(0, 16));
        }

        String S_ENC = Ddes.encrypt(sessionType + sequence_counter + "000000000000000000000000", "DESede", "DESede/CBC/NoPadding", keyType);
        logger.info("S_ENC : " + S_ENC);
        return S_ENC;
    }





    // off-Card가 Card로 보내는 ExternalAuthenticate APDU
    public static String externalAuthenticate(final String InitializeUpdateRAPDUORG, final int derivationType) throws UbiveloxException, GaiaException
    {
        GaiaUtils.checkHexaString(InitializeUpdateRAPDUORG);

        setDerivationType(derivationType);

        logger.info("InitializeUpdateRAPDU : " + InitializeUpdateRAPDUORG);

        String InitializeUpdateRAPDU = InitializeUpdateRAPDUORG;
        if ( ("9000").equals(InitializeUpdateRAPDU.substring(InitializeUpdateRAPDU.length() - 4, InitializeUpdateRAPDU.length())) )
        {
            InitializeUpdateRAPDU = InitializeUpdateRAPDU.substring(0, InitializeUpdateRAPDU.length() - 4);
        }
        else
        {
            throw new UbiveloxException("잘못된 CAPDU");
        }

        // host cryptogram과 MAC 생성

        String sequenceCounter = InitializeUpdateRAPDU.substring(24, 28);

        String hostChallenge = OffCard.InitializeUpdate_C_APDU.substring(10, OffCard.InitializeUpdate_C_APDU.length());

        String cardChallenge = InitializeUpdateRAPDU.substring(28, 40);

        String sessionkey = getSessionKeyENC("S-ENC", sequenceCounter);
        byte[] sessionkeyByteArray = GaiaUtils.convertHexaStringToByteArray(sessionkey + sessionkey.substring(0, sessionkey.length() / 2));

        // String cardCryptogramTmp = Ddes.encrypt(hostChallenge + sequenceCounter + cardChallenge + "8000000000000000", "DESede", "DESede/CBC/NoPadding", sessionkeyByteArray);

        String hostCryptogramTmp = Ddes.encrypt(sequenceCounter + cardChallenge + hostChallenge + "8000000000000000", "DESede", "DESede/CBC/NoPadding", sessionkeyByteArray);

        String hostCryptogram = hostCryptogramTmp.substring(hostCryptogramTmp.length() - 16, hostCryptogramTmp.length());

        // S-MAC 구하고

        sessionkey = getSessionKeyENC("C-MAC", sequenceCounter);

        sessionkeyByteArray = GaiaUtils.convertHexaStringToByteArray(sessionkey);

        // C-MAC 구해야함 Retail Mac

        // 848200001070CA81178C079A4A114998A8 16CBF511
        String externalAuthenticateCAPDU = OffCard.ExternalAuthenticate_C_APDU + hostCryptogram;

        String dataTmp = externalAuthenticateCAPDU + "800000";

        byte[] result = Ddes.retailMac(sessionkeyByteArray, GaiaUtils.convertHexaStringToByteArray(dataTmp));

        logger.info("retailMac : " + GaiaUtils.convertByteArrayToHexaString(result));
        return externalAuthenticateCAPDU + GaiaUtils.convertByteArrayToHexaString(result);
    }





    private static void setDerivationType(final int derivationType)
    {
        switch ( derivationType )
        {
            case 0:
                Key.ENCKey = "404043434545464649494A4A4C4C4F4F";
                Key.MACKey = "404043434545464649494A4A4C4C4F4F";
                Key.DEKKey = "404043434545464649494A4A4C4C4F4F";
                break;
            case 1:
                Key.ENCKey = "404043434545464649494A4A4C4C4F4F";
                Key.MACKey = "404043434545464649494A4A4C4C4F4F";
                Key.DEKKey = "404043434545464649494A4A4C4C4F4F";
                break;
            case 2:
                Key.ENCKey = "404043434545464649494A4A4C4C4F4F";
                Key.MACKey = "404043434545464649494A4A4C4C4F4F";
                Key.DEKKey = "404043434545464649494A4A4C4C4F4F";
                break;

            default:
                break;
        }

    }

}
