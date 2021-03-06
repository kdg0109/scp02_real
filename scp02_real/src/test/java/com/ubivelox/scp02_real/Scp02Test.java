package com.ubivelox.scp02_real;

import static org.mockito.Mockito.when;

import org.junit.Test;
import org.powermock.api.mockito.PowerMockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ubivelox.gaia.GaiaException;
import com.ubivelox.scp02_real.Scp02.OffCard;

import exception.UbiveloxException;

// @RunWith(PowerMockRunner.class)
// @PrepareForTest(CApduService.class)
public class Scp02Test
{

    private static final Logger logger = LoggerFactory.getLogger(Scp02Test.class);





    @Test
    public void mockTest() throws Exception
    {
        OffCard.InitializeUpdate_C_APDU = "8050000008D1853EB979B8A918";
        OffCard.ExternalAuthenticate_C_APDU = "8482000010";

        CApduService capduService = PowerMockito.mock(CApduService.class);// 가짜 만들기
        when(capduService.sendApdu("8050000008D1853EB979B8A918")).thenReturn("0000517786E8AA51042D010200018F3D497C0D1257C74F30E21BD3AC9000");
        when(capduService.sendApdu("84820000108BD933FA46AA5EA6FF2E8FBA2D6D2E4E")).thenReturn("9000");
        Scp02.setCapduService(capduService);
        Scp02.getMutualAuthentication("D1853EB979B8A918");
    }





    @Test
    public void testReadPhoto() throws Exception
    {
        // Select APDU 명령
        String APDU = "00A4040008A000000003000000";

        CApduService CApduServiceImpl = new CApduServiceImpl();

        String rApduString = CApduServiceImpl.sendApdu(APDU);

        logger.info("RAPDU : " + rApduString);
        if ( ("9000").equals(rApduString.substring(rApduString.length() - 4, rApduString.length())) )
        {
            logger.info("RAPDU : " + rApduString);

            OffCard.InitializeUpdate_C_APDU = "8050000008D1853EB979B8A918";
            OffCard.ExternalAuthenticate_C_APDU = "8482000010";

            Scp02.setCapduService(CApduServiceImpl);
            Scp02.getMutualAuthentication("D1853EB979B8A918");

        }
        else
        {
            throw new UbiveloxException("잘못된 CAPDU");
        }
    }





    @Test
    public void test() throws GaiaException, UbiveloxException
    {
        CApduService capduService = PowerMockito.mock(CApduServiceImpl.class);// 가짜 만들기

        settingAPDU("8050000008EC78EEA2438008A6", "00009151026881950639FF02000D4EB131EA95DE5D29FCFE72F724DC9000", "848200001070CA81178C079A4A114998A816CBF511");
        when(capduService.sendApdu("8050000008EC78EEA2438008A6")).thenReturn("00009151026881950639FF02000D4EB131EA95DE5D29FCFE72F724DC9000");
        when(capduService.sendApdu("848200001070CA81178C079A4A114998A816CBF511")).thenReturn("");
        Scp02.setCapduService(capduService);
        Scp02.getMutualAuthentication("EC78EEA2438008A6");

        // settingAPDU("8050000008EC78EEA2438008A6", "000070060A7A2AE436E401020005BD1A6BE9D3D58EAF9F5FAA5795F19000", "848200001070CA81178C079A4A114998A816CBF511");
        // when(capduService.sendApdu("8050000008EC78EEA2438008A6")).thenReturn("000070060A7A2AE436E401020005BD1A6BE9D3D58EAF9F5FAA5795F19000");
        // when(capduService.sendApdu("848200001070CA81178C079A4A114998A816CBF511")).thenReturn("");
        // Scp02.setCapduService(capduService);
        // Scp02.getMutualAuthentication("EC78EEA2438008A6");

        // settingAPDU("8050000008129662F59920C835", "000091510268819506390102000A381AD0F539849DBF08E431EDC88A", "84820300104EDEB2A02F676522F80AA680FE762E76");
        // CApduService capduService = PowerMockito.mock(CApduService.class);// 가짜 만들기
        // when(capduService.sendApdu("8050000008129662F59920C835")).thenReturn("000091510268819506390102000A381AD0F539849DBF08E431EDC88A");
        // when(capduService.sendApdu("84820300104EDEB2A02F676522F80AA680FE762E76")).thenReturn("");
        // Scp02.setCapduService(capduService);
        // Scp02.getMutualAuthentication("129662F59920C835");
        //
        // settingAPDU("8050000008276B46913289214B", "000091510268819506390102000BD547B3AA4F2EA6EEE912DF2E44A4", "84820300100186640BBDBA5D37E484BFC0B63996E6");
        // when(capduService.sendApdu("8050000008276B46913289214B")).thenReturn("000091510268819506390102000BD547B3AA4F2EA6EEE912DF2E44A4");
        // when(capduService.sendApdu("84820300100186640BBDBA5D37E484BFC0B63996E6")).thenReturn("");
        // Scp02.getMutualAuthentication("276B46913289214B");
        //
        // settingAPDU("80500000083A492DC3FA86384C", "000091510268819506390102000C1CDDC545ED0992D8F0BB71A35D9F", "8482030010DF15C0C6C1351EE042084673FA5A46C3");
        // when(capduService.sendApdu("80500000083A492DC3FA86384C")).thenReturn("000091510268819506390102000C1CDDC545ED0992D8F0BB71A35D9F");
        // when(capduService.sendApdu("8482030010DF15C0C6C1351EE042084673FA5A46C3")).thenReturn("");
        // Scp02.getMutualAuthentication("3A492DC3FA86384C");
        //
        // settingAPDU("80500000085A9FEC552345B239", "000091510268819506390102000DAE37775A85C803EB4515F28E9956", "848203001003D59CBCB2341016FC86E4999C913D33");
        // when(capduService.sendApdu("80500000085A9FEC552345B239")).thenReturn("000091510268819506390102000DAE37775A85C803EB4515F28E9956");
        // when(capduService.sendApdu("848203001003D59CBCB2341016FC86E4999C913D33")).thenReturn("");
        // Scp02.getMutualAuthentication("5A9FEC552345B239");
        //
        // settingAPDU("8050000008C4DF0A31CD8B4D95", "000091510268819506390102000E20E75E9D474F41F0C7F7D0DB7F5B", "84820300105D28FF04DF25F04ACE782987DD84DBDA");
        // when(capduService.sendApdu("8050000008C4DF0A31CD8B4D95")).thenReturn("000091510268819506390102000E20E75E9D474F41F0C7F7D0DB7F5B");
        // when(capduService.sendApdu("84820300105D28FF04DF25F04ACE782987DD84DBDA")).thenReturn("");
        // Scp02.setCapduService(capduService);
        // Scp02.getMutualAuthentication("C4DF0A31CD8B4D95");
        //
        // settingAPDU("805000000856E75049691AE308", "000091510268819506390102000F767538D9E255459C4DAFFC13FEAE", "8482030010FD13EE725A87FF67514CB94EC62177B5");
        // when(capduService.sendApdu("805000000856E75049691AE308")).thenReturn("000091510268819506390102000F767538D9E255459C4DAFFC13FEAE");
        // when(capduService.sendApdu("8482030010FD13EE725A87FF67514CB94EC62177B5")).thenReturn("");
        // Scp02.getMutualAuthentication("56E75049691AE308");
        //
        // settingAPDU("80500000086490AE0212C81FFC", "0000915102688195063901020010468755CE6D49C7053CD4399D2A29", "84820300107BE04857CC6ABDDB714A2181489D1A34");
        // when(capduService.sendApdu("80500000086490AE0212C81FFC")).thenReturn("0000915102688195063901020010468755CE6D49C7053CD4399D2A29");
        // when(capduService.sendApdu("84820300107BE04857CC6ABDDB714A2181489D1A34")).thenReturn("");
        // Scp02.getMutualAuthentication("6490AE0212C81FFC");

    }





    private void settingAPDU(final String initializeUpdate_C_APDU, final String initializeUpdate_R_APDU, final String externalAuthenticate_C_APDU)
    {
        OffCard.InitializeUpdate_C_APDU = initializeUpdate_C_APDU;
        // CyberCard.InitializeUpdate_R_APDU = initializeUpdate_R_APDU;
        OffCard.ExternalAuthenticate_C_APDU = externalAuthenticate_C_APDU;

    }
}
