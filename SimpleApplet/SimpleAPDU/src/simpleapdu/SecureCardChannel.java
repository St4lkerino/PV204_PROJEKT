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
        Arrays.fill(PIN, (byte)0);
        PIN = null;
        
    }

    /**
     * initiates a session with the card, basically runs the protocol
     * @return whether the protocol succeeded or not
     */
    public boolean initSession() throws Exception{   
        aesE = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        aesD = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        sha = Mac.getInstance("HmacSHA256");
        

        byte[] sessionEncKey = new byte[16];
        byte[] sessionMacKey = new byte[16];
        byte[] nonceDerivData = new byte[16];
        

        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            System.out.println(" Failed.");
            return false;
        }
        System.out.println(" Done."); 

        Scanner scanner = new Scanner(System.in);  // Create a Scanner object
        int ecdhRetVal = 1;
        
        while (ecdhRetVal > 0){
            System.out.println("Enter PIN:");
            String PINstring = scanner.nextLine();  // Read user input

            // Validate input
            if (!PINstring.matches("[0-9]{4}")){
                System.out.print("Incorrect PIN format.");
                continue;
            }

            // Convert PIN to byte array
            byte[] PIN = new byte[4];
            for (int i = 0; i < 4; i++){
                PIN[i] = (byte) (PINstring.charAt(i) - '0');
            }

            ecdhRetVal = ecdh(PIN);
            
            if (ecdhRetVal == 0){
                return false;
            }

            //forget PIN
            Arrays.fill(PIN, (byte)0);
            PIN = null;
        }
        

        sessionEncKey = sessionKey(true, nonceDerivData);
        sessionMacKey = sessionKey(false, nonceDerivData);

        SecretKeySpec mac = new SecretKeySpec(sessionMacKey, "HmacSHA256");
        sha.init(mac);
        nonce = sha.doFinal(nonceDerivData);

        byte[] ivArray = new byte[16];
        Arrays.fill(ivArray, (byte)0);
        SecretKeySpec encKeyspec = new SecretKeySpec(sessionEncKey, "AES");
        IvParameterSpec ivspec = new IvParameterSpec(ivArray);
        aesD.init(Cipher.DECRYPT_MODE, encKeyspec, ivspec);
        aesE.init(Cipher.ENCRYPT_MODE, encKeyspec, ivspec);

        return true;
    }
    
    /**
     * nulls the digests , removes nonce, disconnects the card
     */
    public void endSession() throws Exception {
        aesE = null;
        aesD = null;
        sha = null;
        secRandom.nextBytes(nonce);
        cardMngr.Disconnect(false);
    }
    
    /**
     * Get random data from the card, sends the APDU over protected channel
     * @param len expected length of data
     * @return array with the random data
     */
    public byte[] getRandom(short len) throws Exception {
        byte[] command = Util.hexStringToByteArray("B054000000");
        command[2] = (byte) len;
        return transmit(command);
    }
    
    /**
     * Get back same data from card over protected channel, this is a testing function
     * @param data data to be sent back
     * @return array with the data received from card
     */
    public byte[] returnData(byte[] data) throws Exception {
        byte[] command = Util.hexStringToByteArray("B0570000"); 
        byte[] apdu = new byte[data.length + 4];
        System.arraycopy(command, 0, apdu, 0, command.length);
        System.arraycopy(data, 0, apdu, command.length, data.length);
        return transmit(apdu);
    }
    
    /**
     * Send buffer to the card over protected channel
     * @param data data to be sent
     * @return array received response from the card
     */
    private byte[] transmit(byte[] data) throws Exception{
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
            throw new Exception("Bad signature");
        } 
        
        byte[] encryptedResponse = new byte[responseData.length - 32];
        System.arraycopy(responseData, 0, encryptedResponse, 0, responseData.length - 32);
        byte[] decryptedResponse = decrypt(encryptedResponse);
        
        
        if(!verifyNonce(decryptedResponse)){
            throw new Exception("Bad nonce");
        } 
        
        // Remove nonce
        byte[] withoutNonce = new byte[decryptedResponse.length - 32];
        System.arraycopy(decryptedResponse, 0, withoutNonce, 0, decryptedResponse.length - 32);

        return withoutNonce;
    }
    
    /**
     * Method generating enc and MAC keys for the session
     * @param cardMngr Card manager
     * @param enc true if we want Applet to produce ENC key, false if MAC
     * @return the key
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
    
    /**
     * Compile derivation data from card and host challenges
     * @param enc true if we are using the data for encryption key, false if for MAC key
     * @return derivationData
     * @throws Exception 
     */
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
    
    /**
     * Verifies a challenge received from the card. 
     * Challenge = HMAC_SHA256 (card pub key . host pub key . card temporary pub key)
     * key is the shared secret from temporary pub keys using ecdh
     * @param mac the HMAC digest
     * @param cardPubW card public key
     * @param hostPubW host public key
     * @param cardTempPub card temporary public key
     * @param challenge card challenge
     * @return whether the hashes match
     */
    private boolean verifyChallenge(Mac mac, byte[] cardPubW, byte[] hostPubW, byte[] cardTempPub, byte[] challenge){
        byte[] concatedKeys = new byte[cardPubW.length + hostPubW.length + cardTempPub.length];
        System.arraycopy(cardPubW, 0, concatedKeys, 0, cardPubW.length);
        System.arraycopy(hostPubW, 0, concatedKeys, cardPubW.length, hostPubW.length);
        System.arraycopy(cardTempPub, 0, concatedKeys, cardPubW.length + hostPubW.length, cardTempPub.length);
        
        
        byte[] chall = mac.doFinal(concatedKeys);
        
        return Arrays.equals(chall, challenge);
    }
    
    /**
     * Generates a challenge received for the card. 
     * Challenge = HMAC_SHA256 (host pub key . card pub key . 0)
     * key is the shared secret from temporary pub keys using ecdh
     * @param mac HMAC digest
     * @param hostPubW host pub key
     * @param cardPubW card pub key
     * @return  host challenge
     */    
    private byte[] generateChallenge(Mac mac, byte[] hostPubW, byte[] cardPubW){
        byte[] concatedKeys = new byte[cardPubW.length + hostPubW.length + 1];
        System.arraycopy(hostPubW, 0, concatedKeys, 0, hostPubW.length);
        System.arraycopy(cardPubW, 0, concatedKeys, hostPubW.length, cardPubW.length);
        concatedKeys[concatedKeys.length - 1] = 0x0;
        
        return mac.doFinal(concatedKeys);
    }
    
    /**
     * This derives a shared secret using ECDH with ACDHEKE protocol
     * @param PIN the pin obtained from the input
     * @return <0, 3) are number of tries left, -1 is success
     * @throws Exception 
     */
    private int ecdh(byte[] PIN) throws Exception {
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
        int retValue = response3.getSW();
        
        
        if (retValue >= 0x63C0 && retValue < 0x63C3){
            return retValue - 0x63C0;
        }
        
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
        
        //clear secret
        secRandom.nextBytes(tempSecret);
        
        boolean cardChallengeOK = verifyChallenge(sha256HMAC, cardPubW, pubKeyW, cardTempPub, challenge);
        if (!cardChallengeOK){
            final ResponseAPDU abortResponse = cardMngr.transmit(new CommandAPDU(0xB0, 0x60, 0x00, 0x00, 0x00));
            retValue = abortResponse.getSW();
            if (retValue >= 0x63C0 && retValue < 0x63C3){
                return retValue - 0x63C0;
            }
            return 0;
        }
        
        byte[] hostChallenge = generateChallenge(sha256HMAC, pubKeyW, cardPubW);
        
        final ResponseAPDU response4 = cardMngr.transmit(new CommandAPDU(0xB0, 0x5c, 0x00, 0x00, hostChallenge));
        
        ka = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        ka.init(privKey);
        int secretLen = ka.generateSecret(cardPubW, (short) 0, (short) cardPubW.length, temp, (short) 0);
        byte[] finalSecret = Arrays.copyOfRange(temp, 0, secretLen);
        
        staticEncKey = finalSecret;
        //DEBUG
        secRandom.nextBytes(temp);   
        return -1;
    }
    
    /**
     * Generate HMAC of the data and append it to the new array, together with data
     * @param data
     * @return array with data + HMAC
     * @throws Exception 
     */
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
    
    /**
     * Verify HMAC of received data, appended to the end of the data array
     * @param signedData data + HMAC
     * @return true if verification is successfull
     * @throws Exception 
     */
    private boolean verify(byte[] signedData) throws Exception {
        short dataLen = (short) (signedData.length - 32);
        byte data[] = new byte[dataLen];
        byte signature[] = new byte[32];
        System.arraycopy(signedData, dataLen, signature, (short) 0, (short) 32);
        System.arraycopy(signedData, (short) 0, data, (short) 0, dataLen);
        byte[] digest = sha.doFinal(data);
        return Arrays.equals(digest, signature);
    }
    
    /**
     * Encrypt buffer to be sent over to the card over protected channel
     * @param data data to be encrypted
     * @return array with encrypted data
     */
    private byte[] encrypt(byte[] data) throws Exception {
        return aesE.doFinal(data);
    }
    
    /**
     * Decrypt buffer received from the card over protected channel
     * @param data data to be decrypted
     * @return array with decrypted data
     */
    private byte[] decrypt(byte[] data) throws Exception {
        return aesD.doFinal(data);
    }
    
    /**
     * Verify freshness of incoming data by checking the nonce appended at the end of the array
     * @param data data with the nonce
     * @return true if the nonce is valid
     */
    private boolean verifyNonce(byte[] data){
        short noncePos = (short) (data.length - 32); 
        byte[] cardNonce = new byte[32];
        System.arraycopy(data, noncePos, cardNonce, (short) 0, (short) 32);
        boolean good = Arrays.equals(nonce, cardNonce);
        if (!good){
            return false;
        }
        return true;
    }
    
    /**
     * Put the data together with a valid freshness nonce to a new array
     * @param data without nonce
     * @return array containig original data and valid freshness nonce
     */
    private byte[] addNonce(byte[] data){
        short dataLen = (short) data.length;
        byte[] withNonce = new byte[(short) 32 + dataLen];
        System.arraycopy(data, (short) 0, withNonce, (short) 0, dataLen);
        // ADD NONCE AFTER OG DATA
        System.arraycopy(nonce, (short) 0, withNonce, dataLen, (short) 32);
        return withNonce;
    }
    
}
