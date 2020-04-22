package simpleapdu;

import applets.SimpleApplet;
import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;
import java.security.SecureRandom;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import java.util.Arrays;
import javacard.security.*;
import java.util.Scanner;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

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
    
    private byte[] staticEncKey;
    Mac sha = null;
    Cipher aesE = null;
    Cipher aesD = null;
    


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
        byte[] sessionEncKey = new byte[16];
        byte[] sessionMacKey = new byte[16];
        byte[] fresh = new byte[32];
        sha = Mac.getInstance("HmacSHA256");
        SecretKeySpec mac;
        aesE = Cipher.getInstance("AES/CBC/NoPadding");
        aesD = Cipher.getInstance("AES/CBC/NoPadding");
        
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
                return -2;
            }
            
            // Convert PIN to byte array
            byte[] PIN = new byte[4];
            for (int i = 0; i < 4; i++){
                PIN[i] = (byte) (PINstring.charAt(i) - '0');
            }
            
            ecdh(cardMngr, PIN);
            sessionEncKey = sessionKey(cardMngr, true);
            sessionMacKey = sessionKey(cardMngr, false);
            
            mac = new SecretKeySpec(sessionMacKey, "HmacSHA256");
            sha.init(mac);
            
            byte[] ivArray = new byte[16];
            Arrays.fill(ivArray, (byte)0);
            SecretKeySpec keyspec = new SecretKeySpec(sessionEncKey, "AES");
            IvParameterSpec ivspec = new IvParameterSpec(ivArray);
            aesD.init(Cipher.DECRYPT_MODE, keyspec, ivspec);
            aesE.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
            
            // send over protected channel for card to send back ffffffffffffffffffffffff 
            byte[] data = Util.hexStringToByteArray("B0570000ffffffffffffffffffffffff");
            byte[] encryptedData = aesE.doFinal(data);
            byte[] signedData = sign(encryptedData);
            
            // Transmit single APDU over secure channel
            final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(0xB0, 0x5f, 0x00, 0x00, signedData));
            
            byte[] responseData = response.getData();
            if (verify(responseData)) {
                byte[] encryptedResponse = new byte[responseData.length - 32];
                System.arraycopy(responseData, 0, encryptedResponse, 0, responseData.length - 32);
                byte[] decryptedResponse = aesD.doFinal(encryptedResponse);
                System.out.println(Arrays.toString(decryptedResponse));
            }
            
            cardMngr.Disconnect(false);
            return 0;
    }
    
    /**
     * 
     * @param cardMngr Card manager
     * @param enc true if we want Applet to produce ENC key, false if MAC
     * @return
     * @throws Exception 
     */
    private byte[] sessionKey(CardManager cardMngr, boolean enc) throws Exception {
        byte[] derivData = derivationData(cardMngr, enc);
        
        MessageDigest digest = MessageDigest.getInstance("MD5");
        byte[] encKeyHash = digest.digest(staticEncKey);
        
        // DERIVE SESSION KEY
        SecretKeySpec secretKeySpec = new SecretKeySpec(encKeyHash, "AES");
        
        Cipher cipherAes = Cipher.getInstance("AES/CBC/NoPadding");
        
        // Set IV to 0
        byte[] ivArray = new byte[16];
        Arrays.fill(ivArray, (byte)0);
        IvParameterSpec ivSpec = new IvParameterSpec(ivArray);
        
        cipherAes.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        return cipherAes.doFinal(derivData);
    }
    
    private byte[] derivationData(CardManager cardMngr, boolean enc) throws Exception {
        byte[] derivData = new byte[16];
        byte[] hostChal = new byte[8];
        ResponseAPDU response;
        
        SecureRandom.getInstanceStrong().nextBytes(hostChal);
        if (enc){
            response = cardMngr.transmit(new CommandAPDU(0xB0, 0x5d, 0x00, 0x00, hostChal));
        } else {
            response = cardMngr.transmit(new CommandAPDU(0xB0, 0x5e, 0x00, 0x00, hostChal));
        }
        byte[] cardChal = response.getData();
        
        System.arraycopy(cardChal, 0, derivData, 0, 4);
        System.arraycopy(hostChal, 0, derivData, 4, 4);
        System.arraycopy(cardChal, 4, derivData, 8, 4);
        System.arraycopy(hostChal, 4, derivData, 12, 4);
        
        return derivData;
    }
    
    private boolean verifyChallenge(Mac mac, byte[] cardPubW, byte[] hostPubW, byte[] cardTempPub, byte[] challenge){
        byte[] concatedKeys = new byte[cardPubW.length + hostPubW.length + cardTempPub.length];
        System.arraycopy(cardPubW, 0, concatedKeys, 0, cardPubW.length);
        System.arraycopy(hostPubW, 0, concatedKeys, cardPubW.length, hostPubW.length);
        System.arraycopy(cardTempPub, 0, concatedKeys, cardPubW.length + hostPubW.length, cardTempPub.length);
        
        
        byte[] chall = mac.doFinal(concatedKeys);
        
        return Arrays.equals(chall, challenge);
    }
    
    private byte[] generateChallenge(Mac mac, byte[] hostPubW, byte[] cardPubW){
        byte[] concatedKeys = new byte[cardPubW.length + hostPubW.length + 1];
        System.arraycopy(hostPubW, 0, concatedKeys, 0, hostPubW.length);
        System.arraycopy(cardPubW, 0, concatedKeys, hostPubW.length, cardPubW.length);
        concatedKeys[concatedKeys.length - 1] = 0x0;
        
        return mac.doFinal(concatedKeys);
    }
    
    public void ecdh(CardManager cardMngr, byte[] PIN) throws Exception {
        KeyPair kp = new KeyPair(KeyPair.ALG_EC_FP, 
                    KeyBuilder.LENGTH_EC_FP_128);
        kp.genKeyPair();
        ECPrivateKey privKey = (ECPrivateKey) kp.getPrivate();
        ECPublicKey pubKey = (ECPublicKey) kp.getPublic();
        
        byte temp[] = new byte[255];

        byte pubKeyW[] = new byte[33];
        int len = pubKey.getW(pubKeyW, (short) 0);
        
        //Send pub key;
        final ResponseAPDU response2 = cardMngr.transmit(new CommandAPDU(0xB0, 0x5a, 0x00, 0x00, pubKeyW));
        System.out.println(response2);
        
        KeyPair kp2 = new KeyPair(KeyPair.ALG_EC_FP, 
                    KeyBuilder.LENGTH_EC_FP_128);
        kp2.genKeyPair();
        ECPrivateKey tempPrivKey = (ECPrivateKey) kp2.getPrivate();
        ECPublicKey tempPubKey = (ECPublicKey) kp2.getPublic();
        byte[] cardPubW = response2.getData();
        
        
        MessageDigest digest = MessageDigest.getInstance("MD5");
        byte[] key = digest.digest(PIN);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        
        Cipher cipherAes = Cipher.getInstance("AES/CBC/NoPadding");
        
        // Set IV to 0
        byte[] ivArray = new byte[16];
        Arrays.fill(ivArray, (byte)0);
        IvParameterSpec ivSpec = new IvParameterSpec(ivArray);
        
        cipherAes.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
 
        SecureRandom random = new SecureRandom();
        len = tempPubKey.getW(temp,(short) 0);
        byte tempPubKeyW[] = new byte[len + (16 - (len % 16))];
        len = tempPubKey.getW(tempPubKeyW, (short) 0);
        for (int i = len; i < tempPubKeyW.length; i++){
            tempPubKeyW[i] = (byte) random.nextInt(); // against offline
        }
          
       
        final ResponseAPDU response3 = cardMngr.transmit(new CommandAPDU(0xB0, 0x5b, 0x00, 0x00, cipherAes.doFinal(tempPubKeyW)));
        System.out.println(response3);
        byte[] cardTempPub = Arrays.copyOf(response3.getData(), 33);
        byte[] challenge = Arrays.copyOfRange(response3.getData(), 33, response3.getData().length);

        KeyAgreement ka = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        ka.init(tempPrivKey);
        len = ka.generateSecret(cardTempPub, (short) 0, (short) cardTempPub.length, temp, (short) 0);
        
        
        byte[] tempSecret = Arrays.copyOf(temp, 16); //secret key
        
        
        Mac sha256HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(tempSecret, "HmacSHA256");
        sha256HMAC.init(secretKey);
        
        boolean cardChallengeOK = verifyChallenge(sha256HMAC, cardPubW, pubKeyW, cardTempPub, challenge);
        if (cardChallengeOK){
            System.out.println("Card challenge is OK!");
        } else {
            System.out.println("Card challenge is NOK!");
        }
        
        byte[] hostChallenge = generateChallenge(sha256HMAC, pubKeyW, cardPubW);
        
        final ResponseAPDU response4 = cardMngr.transmit(new CommandAPDU(0xB0, 0x5c, 0x00, 0x00, hostChallenge));
        System.out.println(response4);
        
        ka = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        ka.init(privKey);
        int secretLen = ka.generateSecret(cardPubW, (short) 0, (short) cardPubW.length, temp, (short) 0);
        byte[] finalSecret = Arrays.copyOfRange(temp, 0, secretLen);
        
        byte[] cardSecret = response4.getData();
        
        //DEBUG
        if (Arrays.equals(cardSecret, finalSecret)){
            System.out.println("Final secrets are the same");
            staticEncKey = finalSecret;
        } else {
            System.out.println("Final secrets are NOT the same");
        }

        // </verify>
        int kek = 5;
        
    }
    
    byte[] sign(byte[] data) throws Exception {
        short dataLen = (short) data.length;
        byte[] signedData = new byte[(short) 32 + dataLen];
        
        // COPY ORIGINAL DATA FIRST
        System.arraycopy(data, (short) 0, signedData, (short) 0, dataLen);
        short signLen = 0;
        
        // ADD SIGNATURE AFTER OG DATA
        System.arraycopy(sha.doFinal(data), (short) 0, signedData, dataLen, (short) 32);
        
        return signedData;
    }
    
    boolean verify(byte[] signedData) throws Exception {
        short dataLen = (short) (signedData.length - 32);
        byte data[] = new byte[dataLen];
        byte signature[] = new byte[32];
        System.arraycopy(signedData, dataLen, signature, (short) 0, (short) 32);
        System.arraycopy(signedData, (short) 0, data, (short) 0, dataLen);
        byte[] digest = sha.doFinal(data);
        return Arrays.equals(digest, signature);
    }
    
    byte[] encrypt(byte[] data) throws Exception {
        short dataLen = (short) data.length;
        byte[] encryptedData = new byte[dataLen];
        
        
        
        return encryptedData;
    }
    
    byte[] decrypt(byte[] data) throws Exception {
        short dataLen = (short) data.length;
        byte[] decryptedData = new byte[dataLen];
        
        
        
        return decryptedData;
    }
    
    /*
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
*/
}
