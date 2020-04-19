package simpleapdu;

import applets.SimpleApplet;
import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.Scanner;
import javax.crypto.KeyAgreement;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;

/**
 * Test class.
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author Petr Svenda (petrs), Dusan Klinec (ph4r05)
 */
public class SimpleAPDU {
    private static String APPLET_AID = "482871d58ab7465e5e05";
    private static byte APPLET_AID_BYTE[] = Util.hexStringToByteArray(APPLET_AID);

    private static final String STR_APDU_GETRANDOM = "B054100000";
    private static final String STR_APDU_ENCRYPT = "B05000001001020304050607080102030405060708";
    private static final byte[] INSTALL_PAR = new byte[] 
        {
        };
    
    /**
 * This method converts the EC public key (ECPublicKey#getW()) into ECPublicKey
 * @param cardPublicKey as W
 * @param curveName (for example "P-224")
 * @return java.security.interfaces.ECPublicKey
 */
public ECPublicKey ucPublicKeyToPublicKey(byte[] cardPublicKey, String curveName) {
    //for example curveName = "P-224";
    java.security.interfaces.ECPublicKey ecPublicKey = null; // java.security.interfaces.ECPublicKey
    java.security.KeyFactory kf = null;

    org.bouncycastle.jce.spec.ECNamedCurveParameterSpec ecNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec(curveName);
    org.bouncycastle.math.ec.ECCurve curve = ecNamedCurveParameterSpec.getCurve();
    java.security.spec.EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, ecNamedCurveParameterSpec.getSeed());
    java.security.spec.ECPoint ecPoint = ECPointUtil.decodePoint(ellipticCurve, cardPublicKey);
    java.security.spec.ECParameterSpec ecParameterSpec = EC5Util.convertSpec(ellipticCurve, ecNamedCurveParameterSpec);
    java.security.spec.ECPublicKeySpec publicKeySpec = new java.security.spec.ECPublicKeySpec(ecPoint, ecParameterSpec);

    try {
        kf = java.security.KeyFactory.getInstance("EC", "BC");
    } catch (Exception e) {
        System.out.println("Caught Exception kf : " + e.toString());
    }

    try {
        ecPublicKey = (ECPublicKey) kf.generatePublic(publicKeySpec);
    } catch (Exception e) {
        System.out.println("Caught Exception public key: " + e.toString());
    }

    return ecPublicKey;
}

    /**
     * Main entry point.
     *
     * @param args
     */
    public static void main(String[] args) {
        try {
            SimpleAPDU main = new SimpleAPDU();
            
            // PIN generation
            SecureRandom secRandom = new SecureRandom();
            byte[] PIN = new byte[4];
            for (int i = 0; i < 4; i++){
                PIN[i] = (byte) (secRandom.nextInt(10));
            }      
            
            System.out.print("PIN is: ");
            for (int i = 1; i < 8; i+=2){
                System.out.print(Util.bytesToHex(PIN).charAt(i));
            }
            System.out.println();
            
            
            final RunConfig runCfg = RunConfig.getDefaultConfig();
            runCfg.setAppletToSimulate(SimpleApplet.class); 
            runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL); // Use local simulator

            byte[] INSTALL_DATA = Util.hexStringToByteArray("0A" + APPLET_AID + "010104" + Util.bytesToHex(PIN));
            runCfg.setInstallData(INSTALL_DATA);
            
            // Clear PIN
            for (int i = 0; i < 4; i++){
                PIN[i] = (byte) (0);
            }
            main.session(runCfg);
            
            
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }
    
    public int session(RunConfig runCfg) throws Exception{
        
        final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);
        
        // Connect to first available card
            System.out.print("Connecting to card...");
            if (!cardMngr.Connect(runCfg)) {
                System.out.println(" Failed.");
                return -1;
            }
            System.out.println(" Done.");
            
            Scanner myObj = new Scanner(System.in);  // Create a Scanner object
            System.out.println("Enter PIN:");

            String PINstring = myObj.nextLine();  // Read user input
            
            // Validate input
            if (!PINstring.matches("[0-9]{4}")){
                System.out.print("Incorrect PIN format.");
            }
            
            // Convert PIN to byte array
            byte[] PIN = new byte[4];
            for (int i = 0; i < 4; i++){
                PIN[i] = (byte) (PINstring.charAt(i) - '0');
            }
            
            ecdh(cardMngr, PIN);
            
            cardMngr.Disconnect(false);
            return 0;
    }
    
    public void ecdh(CardManager cardMngr, byte[] PIN) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(128);
        KeyPair kp = kpg.generateKeyPair();
        byte[] ourPk = kp.getPublic().getEncoded();
        
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(Util.hexStringToByteArray("B0590000")));
        System.out.println(response);
        
        final ResponseAPDU response2 = cardMngr.transmit(new CommandAPDU(0xB0, 0x5a, 0x00, 0x00, ourPk));
        System.out.println(response2);
        
        ECPublicKey theirPub = ucPublicKeyToPublicKey(response.getData(), "secp128r1");
        
        
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(kp.getPrivate());
        ka.doPhase(theirPub, true);
        byte[] sharedSecret = ka.generateSecret();   
        
        
        
    }
    
    public void setAndVerifyPIN() throws Exception {
        final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);
        final RunConfig runCfg = RunConfig.getDefaultConfig();
        runCfg.setAppletToSimulate(SimpleApplet.class); 
        runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL); // Use local simulator
        
        
        byte[] INSTALL_DATA = Util.hexStringToByteArray("0A" + APPLET_AID + "01010401020304");
        runCfg.setInstallData(INSTALL_DATA);

        // Connect to first available card
        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            System.out.println(" Failed.");
        }
        System.out.println(" Done.");
        
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(0xB0, 0x55, 0x00, 0x00, new byte[] {0x01, 0x02, 0x03, 0x04}));
        System.out.println(response);
        
        // Wrong PIN
        byte[] badPIN = new byte[] {0x01, 0x01, 0x03, 0x04};
        final ResponseAPDU responseBad = cardMngr.transmit(new CommandAPDU(0xB0, 0x55, 0x00, 0x00, badPIN));
        System.out.println(responseBad);
        
    }

    public void demoGetRandomDataCommand() throws Exception {
        // CardManager abstracts from real or simulated card, provide with applet AID
        final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);          
        
        // Get default configuration for subsequent connection to card (personalized later)
        final RunConfig runCfg = RunConfig.getDefaultConfig();

        // B) If running in the simulator 
        runCfg.setAppletToSimulate(SimpleApplet.class); // main class of applet to simulate
        runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL); // Use local simulator
        
        // Connect to first available card
        // NOTE: selects target applet based on AID specified in CardManager constructor
        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            System.out.println(" Failed.");
        }
        System.out.println(" Done.");

        // Transmit single APDU
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(Util.hexStringToByteArray(STR_APDU_GETRANDOM)));
        byte[] data = response.getData();
        
        final ResponseAPDU response2 = cardMngr.transmit(new CommandAPDU(0xB0, 0x54, 0x00, 0x00, data)); // Use other constructor for CommandAPDU
        
        System.out.println(response);
    }

    public void demoEncryptDecrypt() throws Exception {
        final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);
        final RunConfig runCfg = RunConfig.getDefaultConfig();
        //runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL); // Use real card
        runCfg.setAppletToSimulate(SimpleApplet.class); 
        runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL); // Use local simulator

        // Connect to first available card
        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            System.out.println(" Failed.");
        }
        System.out.println(" Done.");

        
        // Task 1
        // TODO: Prepare and send APDU with 32 bytes of data for encryption, observe output
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(Util.hexStringToByteArray(STR_APDU_ENCRYPT)));

        // Task 2
        // TODO: Extract the encrypted data from the card's response. Send APDU with this data for decryption
        byte[] data = response.getData();
        
        
        final ResponseAPDU decrypted = cardMngr.transmit(new CommandAPDU(0xB0, 0x51, 0x00, 0x00, data));
        // TODO: Compare match between data for encryption and decrypted data
        
        // Task 3
        // TODO: What is the value of AES key used inside applet? Use debugger to figure this out

        // Task 4
        // TODO: Prepare and send APDU for setting different AES key, then encrypt and verify (with http://extranet.cryptomathic.com/aescalc/index
    }        
}
