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
public class SecureCardChannel {
    private static String APPLET_AID = "482871d58ab7465e5e05";
    private static byte APPLET_AID_BYTE[] = Util.hexStringToByteArray(APPLET_AID);

    private static final String STR_APDU_GETRANDOM = "B054100000";
    
    private byte[] staticEncKey;
    private Mac sha = null;
    private Cipher aesE = null;
    private Cipher aesD = null;
    private CardManager cardMngr = null;
    private SecureRandom secRandom = new SecureRandom();
    private RunConfig runCfg = null;
    private byte[] nonce = new byte[32];
    
    /**
     * Main entry point.
     *
     * @param args
     */
    public SecureCardChannel() throws Exception{
        cardMngr = new CardManager(true, APPLET_AID_BYTE);
        aesE = Cipher.getInstance("AES/CBC/NoPadding");
        aesD = Cipher.getInstance("AES/CBC/NoPadding");
        sha = Mac.getInstance("HmacSHA256");

        // PIN generation
        byte[] PIN = new byte[4];
        for (int i = 0; i < 4; i++){
            PIN[i] = (byte) (secRandom.nextInt(10));
        }      

        System.out.print("PIN is: ");
        for (int i = 1; i < 8; i+=2){
            System.out.print(Util.bytesToHex(PIN).charAt(i));
        }
        System.out.println();

        runCfg = RunConfig.getDefaultConfig();
        runCfg.setAppletToSimulate(SimpleApplet.class); 
        runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL); // Use local simulator

        byte[] INSTALL_DATA = Util.hexStringToByteArray("0A" + APPLET_AID + "010104" + Util.bytesToHex(PIN));
        runCfg.setInstallData(INSTALL_DATA);     
        
        //Forget Pin
        for (int i = 0; i < 4; i++){
            PIN[i] = (byte) (0);
        }
        PIN = null;
        
    }

    public boolean initSession() throws Exception{     
        byte[] sessionEncKey = new byte[16];
        byte[] sessionMacKey = new byte[16];
        byte[] nonceDerivData = new byte[16];
        SecretKeySpec mac;

        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            System.out.println(" Failed.");
            return false;
        }
        System.out.println(" Done."); //TODO: move to constructor, forget runcfg after?

        Scanner scanner = new Scanner(System.in);  // Create a Scanner object
        System.out.println("Enter PIN:");

        String PINstring = scanner.nextLine();  // Read user input

        // Validate input
        if (!PINstring.matches("[0-9]{4}")){
            System.out.print("Incorrect PIN format.");
            return false;
        }

        // Convert PIN to byte array
        byte[] PIN = new byte[4];
        for (int i = 0; i < 4; i++){
            PIN[i] = (byte) (PINstring.charAt(i) - '0');
        }

        ecdh(PIN);
        
        //forget PIN
        Arrays.fill(PIN, (byte)0);
        PIN = null;


        sessionEncKey = sessionKey(true, nonceDerivData);
        sessionMacKey = sessionKey(false, nonceDerivData);

        mac = new SecretKeySpec(sessionMacKey, "HmacSHA256");
        sha.init(mac);
        nonce = sha.doFinal(nonceDerivData);

        byte[] ivArray = new byte[16];
        Arrays.fill(ivArray, (byte)0);
        SecretKeySpec keyspec = new SecretKeySpec(sessionEncKey, "AES");
        IvParameterSpec ivspec = new IvParameterSpec(ivArray);
        aesD.init(Cipher.DECRYPT_MODE, keyspec, ivspec);
        aesE.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);

        return true;
    }
    
    public byte[] transmit() throws Exception{
         // send over protected channel for card to send back ffffffffffffffffffffffff 
        byte[] data = Util.hexStringToByteArray("B0570000ffffffffffffffffffffffff");
        byte[] dataWithNonce = addNonce(data);

        // update nonce
        nonce = sha.doFinal(nonce);
        // encrypt data + nonce
        byte[] encryptedData = encrypt(dataWithNonce);
        // sign
        byte[] signedData = sign(encryptedData);

        // Transmit single APDU over secure channel
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(0xB0, 0x5f, 0x00, 0x00, signedData));

        byte[] responseData = response.getData();
        
        if (!verify(responseData)) {
            System.out.println("Oopsie, bad signature");
        } 
        
        byte[] encryptedResponse = new byte[responseData.length - 32];
        System.arraycopy(responseData, 0, encryptedResponse, 0, responseData.length - 32);
        byte[] decryptedResponse = decrypt(encryptedResponse);
        
        
        if(!verifyNonce(decryptedResponse)){
            System.out.println("Bad nonce.");
        } 
        
        // Remove nonce
        byte[] withoutNonce = new byte[decryptedResponse.length - 32];
        System.arraycopy(decryptedResponse, 0, withoutNonce, 0, decryptedResponse.length - 32);
        System.out.println(Arrays.toString(withoutNonce));

        cardMngr.Disconnect(false);
        return new byte[1];
    }
    
    /**
     * 
     * @param cardMngr Card manager
     * @param enc true if we want Applet to produce ENC key, false if MAC
     * @return
     * @throws Exception 
     */
    private byte[] sessionKey(boolean enc, byte[] nonceDerivData) throws Exception {
        byte[] derivData = derivationData(enc);
        
        // Get derivation data for freshness nonce when generating MAC key
        if (!enc){
            System.arraycopy(derivData, 0, nonceDerivData, 0, 16);
        }
        
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
    
    private byte[] derivationData(boolean enc) throws Exception {
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
    
    private boolean ecdh(byte[] PIN) throws Exception {
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
        byte tempPubKeyW[] = new byte[48]; //33byte W + padding
        len = tempPubKey.getW(tempPubKeyW, (short) 0);
        for (int i = len; i < tempPubKeyW.length; i++){
            tempPubKeyW[i] = (byte) random.nextInt(); // against offline
        }
          
       
        final ResponseAPDU response3 = cardMngr.transmit(new CommandAPDU(0xB0, 0x5b, 0x00, 0x00, cipherAes.doFinal(tempPubKeyW)));
        
        byte[] cardTempPub = Arrays.copyOf(response3.getData(), 33);
        byte[] challenge = Arrays.copyOfRange(response3.getData(), 33, response3.getData().length);

        KeyAgreement ka = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        ka.init(tempPrivKey);
        ka.generateSecret(cardTempPub, (short) 0, (short) cardTempPub.length, temp, (short) 0);
        
        byte[] tempSecret = Arrays.copyOf(temp, 16); //secret key
        //clear
        
        secRandom.nextBytes(tempPubKeyW);
        secRandom.nextBytes(temp);
        tempPrivKey.clearKey();
        tempPubKey.clearKey();
        
        
        Mac sha256HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(tempSecret, "HmacSHA256");
        sha256HMAC.init(secretKey);
        
        boolean cardChallengeOK = verifyChallenge(sha256HMAC, cardPubW, pubKeyW, cardTempPub, challenge);
        if (!cardChallengeOK){ //if not ok then stop TODO
            System.out.println("Card challenge is NOK!");
            return false;
        } else {
            System.out.println("Card challenge is OK!"); // TODO DELETE THIS
        }
        
        byte[] hostChallenge = generateChallenge(sha256HMAC, pubKeyW, cardPubW);
        
        final ResponseAPDU response4 = cardMngr.transmit(new CommandAPDU(0xB0, 0x5c, 0x00, 0x00, hostChallenge));
        
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
        
        return true;
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
    
    private boolean verify(byte[] signedData) throws Exception {
        short dataLen = (short) (signedData.length - 32);
        byte data[] = new byte[dataLen];
        byte signature[] = new byte[32];
        System.arraycopy(signedData, dataLen, signature, (short) 0, (short) 32);
        System.arraycopy(signedData, (short) 0, data, (short) 0, dataLen);
        byte[] digest = sha.doFinal(data);
        return Arrays.equals(digest, signature);
    }
    
    private byte[] encrypt(byte[] data) throws Exception {
        return aesE.doFinal(data);
    }
    
    private byte[] decrypt(byte[] data) throws Exception {
        return aesD.doFinal(data);
    }
    
    boolean verifyNonce(byte[] data){
        short noncePos = (short) (data.length - 32); 
        byte[] cardNonce = new byte[32];
        System.arraycopy(data, noncePos, cardNonce, (short) 0, (short) 32);
        boolean good = Arrays.equals(nonce, cardNonce);
        if (!good){
            return false;
        }
        return true;
    }
    
    private byte[] addNonce(byte[] data){
        short dataLen = (short) data.length;
        byte[] withNonce = new byte[(short) 32 + dataLen];
        System.arraycopy(data, (short) 0, withNonce, (short) 0, dataLen);
        // ADD NONCE AFTER OG DATA
        System.arraycopy(nonce, (short) 0, withNonce, dataLen, (short) 32);
        return withNonce;
    }
    
}