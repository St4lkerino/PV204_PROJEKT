package applets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;



public class SimpleApplet extends javacard.framework.Applet {

    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_ENCRYPT = (byte) 0x50;
    final static byte INS_DECRYPT = (byte) 0x51;
    final static byte INS_SETKEY = (byte) 0x52;
    final static byte INS_HASH = (byte) 0x53;
    final static byte INS_RANDOM = (byte) 0x54;
    final static byte INS_VERIFYPIN = (byte) 0x55;
    final static byte INS_SETPIN = (byte) 0x56;
    final static byte INS_RETURNDATA = (byte) 0x57;
    final static byte INS_SIGNDATA = (byte) 0x58;
    final static byte INS_KEYPAIR = (byte) 0x59;
    final static byte INS_EXCHANGE_PUBS = (byte) 0x5a;
    final static byte INS_GET_HOST_TMP_PUB = (byte) 0x5b;
    final static byte INS_GET_HOST_CHALLENGE = (byte) 0x5c;
    final static byte INS_ENC_KEY = (byte) 0x5d;
    final static byte INS_MAC_KEY = (byte) 0x5e;
    final static byte INS_PROCESS_PROTECTED = (byte) 0x5f;
    final static byte INS_ABORT = (byte) 0x60;

    final static short ARRAY_LENGTH = (short) 0xff;
    final static byte AES_BLOCK_LENGTH = (short) 0x16;

    final static short SW_BAD_TEST_DATA_LEN = (short) 0x6680;
    final static short SW_KEY_LENGTH_BAD = (short) 0x6715;
    final static short SW_CIPHER_DATA_LENGTH_BAD = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE = (short) 0x6711;
    final static short SW_BAD_PIN = (short) 0x6900;
    final static short SW_BAD_SIGNATURE = (short) 0x6901;
    final static short SW_BAD_NONCE = (short) 0x6902;

    final static short SW_Exception = (short) 0xff01;
    final static short SW_ArrayIndexOutOfBoundsException = (short) 0xff02;
    final static short SW_ArithmeticException = (short) 0xff03;
    final static short SW_ArrayStoreException = (short) 0xff04;
    final static short SW_NullPointerException = (short) 0xff05;
    final static short SW_NegativeArraySizeException = (short) 0xff06;
    final static short SW_CryptoException_prefix = (short) 0xf100;
    final static short SW_SystemException_prefix = (short) 0xf200;
    final static short SW_PINException_prefix = (short) 0xf300;
    final static short SW_TransactionException_prefix = (short) 0xf400;
    final static short SW_CardRuntimeException_prefix = (short) 0xf500;

    private Cipher m_encryptCipher = null;
    private Cipher m_decryptCipher = null;
    private RandomData m_secureRandom = null;
    private MessageDigest m_hash = null;
    private OwnerPIN m_pin = null;
    private AESKey pin = null;
    private KeyPair kp;
    private KeyPair m_tempKeyPair;
    private ECPrivateKey m_privKey;
    private ECPublicKey m_pubKey;
    private ECPrivateKey m_tempPrivKey;
    private ECPublicKey m_tempPubKey;
    private byte[] m_tempHostPubW = null;
    private byte[] m_hostPubW = null;
    private MessageDigest md5_hash = null;
    private Signature  m_hmac_sha256 = null;
    private Signature m_sign = null;
    private Signature m_verify = null;
    private HMACKey m_tempSessionHMACKey = null;
    private AESKey m_staticEncKey = null;
    private AESKey m_sessionEncKey = null;
    private HMACKey m_sessionMacKey = null;
    private Cipher m_staticEncCipher = null;
    private final byte[] nonce = new byte[32];
    
    //this would be persistent
    private short m_maxNumberOfTriesLeft = 3;
    
    
    
    final static short EXPECTING_PUBLIC_KEY = 1;
    final static short EXPECTING_TEMPORARY_KEY = 2;
    final static short EXPECTING_CHALLENGE_ECDH = 3;
    final static short EXPECTING_ENC_KEY = 4;
    final static short EXPECTING_MAC_KEY = 5;
    final static short EXPECTING_TRAFFIC = 6;
    
    private short m_protocolState;

    private KeyAgreement keyAgreement;

    // TEMPORARRY ARRAY IN RAM
    private byte m_ramArray[] = null;
    // PERSISTENT ARRAY IN EEPROM
    private byte m_dataArray[] = null;

    /**
     * SimpleApplet default constructor Only this class's install method should
     * create the applet object.
     */
    protected SimpleApplet(byte[] buffer, short offset, byte length) {
        // data offset is used for application specific parameter.
        // initialization with default offset (AID offset).
        short dataOffset = offset;
        boolean isOP2 = false;

        if (length > 9) {
            // Install parameter detail. Compliant with OP 2.0.1.

            // | size | content
            // |------|---------------------------
            // |  1   | [AID_Length]
            // | 5-16 | [AID_Bytes]
            // |  1   | [Privilege_Length]
            // | 1-n  | [Privilege_Bytes] (normally 1Byte)
            // |  1   | [Application_Proprietary_Length]
            // | 0-m  | [Application_Proprietary_Bytes]
            // shift to privilege offset
            dataOffset += (short) (1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short) (1 + buffer[dataOffset]);

            // go to proprietary data
            dataOffset++;

            m_dataArray = new byte[ARRAY_LENGTH];
            Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);

            // CREATE OBJECTS FOR CBC CIPHERING
            m_encryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            m_decryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

            // CREATE RANDOM DATA GENERATORS
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);

            // SET PIN
            m_pin = new OwnerPIN((byte) 5, (byte) 4); // 5 tries, 4 digits in pin
            m_pin.update(buffer, (byte) dataOffset, (byte) buffer[dataOffset - 1]); // set initial random pin

            // INIT HASH ENGINE
            m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);

            md5_hash = MessageDigest.getInstance(MessageDigest.ALG_MD5, false);
            
            m_hmac_sha256 = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
            m_sign = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
            m_verify = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);

            pin = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, (short) 128, true);

            md5_hash.doFinal(buffer, dataOffset, buffer[dataOffset - 1], m_ramArray, (short) 0);
            pin.setKey(m_ramArray, (short) 0);
            m_secureRandom.nextBytes(m_ramArray, (short) 0, (short) 16);

            // update flag
            isOP2 = true;
            m_protocolState = EXPECTING_PUBLIC_KEY;

        }

        // register this instance
        register();
    }

    /**
     * Method installing the applet.
     *
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        // applet  instance creation 
        new SimpleApplet(bArray, bOffset, bLength);
    }

    /**
     * Select method returns true if applet selection is supported.
     *
     * @return boolean status of selection.
     */
    public boolean select() {
        clearSessionData();

        return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect() {
        clearSessionData();
    }

    /**
     * Method processing an incoming APDU.
     *
     * @see APDU
     * @param apdu the incoming APDU
     * @exception ISOException with the response bytes defined by ISO 7816-4
     */
    public void process(APDU apdu) throws ISOException {
        // get the buffer with incoming APDU
        byte[] apduBuffer = apdu.getBuffer();

        // ignore the applet select command dispached to the process
        if (selectingApplet()) {
            return;
        }
        
        try {
            // APDU instruction parser
            if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) {
                // These are only supported outside protected channel
                switch (apduBuffer[ISO7816.OFFSET_INS]) {
                    case INS_EXCHANGE_PUBS:
                        if (m_protocolState == EXPECTING_PUBLIC_KEY){
                            exchangePubKeys(apdu);
                        }                        
                        break;
                        
                    case INS_GET_HOST_TMP_PUB:
                        if (m_protocolState == EXPECTING_TEMPORARY_KEY){
                            
                        }
                        GetEncryptedTempPub(apdu);
                        break;
                        
                    case INS_GET_HOST_CHALLENGE:
                        if (m_protocolState == EXPECTING_CHALLENGE_ECDH){
                            GetHostChallenge(apdu);
                        }
                        break;
                        
                    case INS_ENC_KEY:
                        if (m_protocolState == EXPECTING_ENC_KEY){
                            sessionEncKey(apdu);
                        } 
                        break;
                        
                    case INS_MAC_KEY:
                        if (m_protocolState == EXPECTING_MAC_KEY){
                            sessionMacKey(apdu);
                        }    
                        break;
                        
                    case INS_PROCESS_PROTECTED:
                        if (m_protocolState == EXPECTING_TRAFFIC){
                            processProtected(apdu);
                        }
                        break;
                        
                    case INS_ABORT:
                        abort();
                        break;
                        
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                        break;
                }
            } else {
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }

            // Capture all reasonable exceptions and change into readable ones (instead of 0x6f00) 
        } catch (ISOException e) {
            throw e; // Our exception from code, just re-emit
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(SW_ArrayIndexOutOfBoundsException);
        } catch (ArithmeticException e) {
            ISOException.throwIt(SW_ArithmeticException);
        } catch (ArrayStoreException e) {
            ISOException.throwIt(SW_ArrayStoreException);
        } catch (NullPointerException e) {
            ISOException.throwIt(SW_NullPointerException);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(SW_NegativeArraySizeException);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (SW_CryptoException_prefix | e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short) (SW_SystemException_prefix | e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt((short) (SW_PINException_prefix | e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short) (SW_TransactionException_prefix | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (SW_CardRuntimeException_prefix | e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(SW_Exception);
        }
    }
    
    void abort(){
        if (m_maxNumberOfTriesLeft > 0){
            m_maxNumberOfTriesLeft--;
        }
        m_protocolState = EXPECTING_PUBLIC_KEY;
        ISOException.throwIt((short) ((short) 0x63C0 + (short) m_maxNumberOfTriesLeft));
    }
    
    
    public byte[] process(byte[] apduBuffer) throws ISOException {
        // These are supported inside nad outside protected
        switch (apduBuffer[ISO7816.OFFSET_INS]) {
            case INS_RETURNDATA:
                return ReturnData(apduBuffer);
            default:
                // The INS code is not supported by the dispatcher
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
        }
        return null;
    }

    void processProtected(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = (short) apdu.setIncomingAndReceive();
        
        byte[] signedData = new byte[dataLen];
        Util.arrayCopy(apdubuf, (short) (ISO7816.OFFSET_CDATA), signedData, (short) 0, (short) dataLen);
        
        //short dataLen = (short) (apdubuf.length - 32);
        if (!Verify(signedData)) {
            ISOException.throwIt(SW_BAD_SIGNATURE);
        }
        byte[] encryptedData = new byte[dataLen - 32];
        System.arraycopy(signedData, 0, encryptedData, 0, (short)(dataLen - 32));
        byte[] decryptedData = Decrypt(encryptedData);
        byte[] withoutNonce = verifyNonce(decryptedData);
        
        byte[] returnedData = process(withoutNonce);
        if (returnedData == null) {
            return;
        }
        short len = (short) returnedData.length;
        byte[] returnedWithNonce = addNonce(returnedData);
        len += 32;
        
        encryptedData = Encrypt(returnedWithNonce);
        signedData = Sign(encryptedData);
        Util.arrayCopyNonAtomic(signedData, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short) (signedData.length));
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (signedData.length));
    }
    
    void clearSessionData() {
        // E.g., fill sesssion data in RAM with zeroes
        //TODO FILL SHIT UP
        Util.arrayFillNonAtomic(m_ramArray, (short) 0, (short) m_ramArray.length, (byte) 0);
        // Or better fill with random data
        m_secureRandom.nextBytes(m_ramArray, (short) 0, (short) m_ramArray.length);
    }

    byte[] verifyNonce(byte[] data){
        short dataLen = (short) (data.length - 32); 
        short good = Util.arrayCompare(data, dataLen, nonce, (short) 0, (short) 32);
        if (good != 0){
            ISOException.throwIt(SW_BAD_NONCE);
            
        }
        // UPDATE NONCE
        m_sign.sign(nonce, (short) 0, (short) 32, nonce, (short) 0);
        
        // GET DATA
        byte[] withoutNonce = new byte[dataLen];
        Util.arrayCopy(data, (short) 0, withoutNonce, (short) 0, dataLen);
        return withoutNonce;
    }
    
    byte[] addNonce(byte[] data){
        short dataLen = (short) data.length;
        byte[] withNonce = new byte[(short) (dataLen + 32)];
        Util.arrayCopy(data, (short) 0, withNonce, (short) 0, dataLen);
        // ADD NONCE
        Util.arrayCopy(nonce, (short) 0, withNonce, dataLen, (short) 32);
        return withNonce;
    }
    
    void sessionMacKey(APDU apdu){
        // GET DERIVATION DATA FOR ENC KEY
        byte[] derivData = derivationData(apdu);
        
        // DERIVE STATIC ENC KEY (TODO: MOVE IT ELSEWHERE, NOT FOR EVERY SESSION)
        byte[] macKeyHash = new byte[16];
        md5_hash = MessageDigest.getInstance(MessageDigest.ALG_MD5, false);
        int len = md5_hash.doFinal(m_ramArray, (short) 0, (short) 20, macKeyHash, (short) 0);
        
         // DERIVE SESSION ENC KEY
        m_staticEncKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, (short) 128, true);
        m_staticEncKey.setKey(macKeyHash, (short) 0);
        m_staticEncCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        m_staticEncCipher.init(m_staticEncKey, Cipher.MODE_ENCRYPT);
        
        byte[] sessKey = new byte[16];
        m_staticEncCipher.doFinal(derivData, (short) 0, (short) 16, sessKey, (short) 0);
        m_sessionMacKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, KeyBuilder.LENGTH_HMAC_SHA_512_BLOCK_128, true);
        m_sessionMacKey.setKey(sessKey, (short) 0, (short) 16);
        m_sign.init(m_sessionMacKey, Signature.MODE_SIGN);
        m_verify.init(m_sessionMacKey, Signature.MODE_VERIFY);
        
        // DERIVE FIRST NONCE
        m_sign.sign(derivData, (short) 0, (short) 16, nonce, (short) 0);
        
        m_protocolState = EXPECTING_TRAFFIC;
    }
    
    void sessionEncKey(APDU apdu){
        // GET DERIVATION DATA FOR ENC KEY
        byte[] derivData = derivationData(apdu);
        
        // DERIVE STATIC ENC KEY (TODO: MOVE IT ELSEWHERE, NOT FOR EVERY SESSION)
        byte[] encKeyHash = new byte[16];
        
        // USE MD5 TO CREATE 16B STATIC ENC KEY (TODO: USE SOMETHING ELSE THAN MD5)
        md5_hash = MessageDigest.getInstance(MessageDigest.ALG_MD5, false);
        int len = md5_hash.doFinal(m_ramArray, (short) 0, (short) 20, encKeyHash, (short) 0);
        
        // DERIVE SESSION ENC KEY
        m_staticEncKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, (short) 128, true);
        m_staticEncKey.setKey(encKeyHash, (short) 0);
        m_staticEncCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        m_staticEncCipher.init(m_staticEncKey, Cipher.MODE_ENCRYPT);
        
        byte[] sessKey = new byte[16];
        m_staticEncCipher.doFinal(derivData, (short) 0, (short) 16, sessKey, (short) 0);
        m_sessionEncKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, true);
        m_sessionEncKey.setKey(sessKey, (short) 0);
        
        m_protocolState = EXPECTING_MAC_KEY;
    }
    
    // Exchange challenges and derive session keys from them, using DH secret
    byte[] derivationData(APDU apdu){
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        byte[] derivData = new byte[16];

        // CHECK EXPECTED LENGTH == 8
        if ((dataLen % 8) != 0) {
            ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        }
        
        // COPY HOST CHALLENGE TO DERIVATION DATA (2nd and 4th)
        Util.arrayCopy(apdubuf, ISO7816.OFFSET_CDATA, derivData, (short) 4, (short) 4);
        Util.arrayCopy(apdubuf, (short) (ISO7816.OFFSET_CDATA + 4), derivData, (short) 12, (short) 4);
        
        // GENERATE CARD CHALLENGE
        byte[] cardChal = new byte[8];
        m_secureRandom.nextBytes(cardChal, (short) 0, (short) 8);
        
        // COPY CARD CHALLENGE TO DERIVATION DATA (1st and 3rd)
        Util.arrayCopy(cardChal, (short) 0, derivData, (short) 0, (short) 4);
        Util.arrayCopy(cardChal, (short) 4, derivData, (short) 8, (short) 4);
        
        // COPY CARD CHALLENGE INTO RESPONSE APDU
        Util.arrayCopyNonAtomic(cardChal, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short) 8);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 8);
        
        return derivData;
        
        
    }

    void exchangePubKeys(APDU apdu) {
        try {
            byte[] apdubuf = apdu.getBuffer();
            short dataLen = apdu.setIncomingAndReceive();
            
            m_hostPubW = new byte[dataLen];
            Util.arrayCopy(apdubuf, ISO7816.OFFSET_CDATA, m_hostPubW, (short) 0, dataLen);
            
            kp = new KeyPair(KeyPair.ALG_EC_FP, //TODO, generate on exchange?
                    KeyBuilder.LENGTH_EC_FP_128);
            kp.genKeyPair();
            m_privKey = (ECPrivateKey) kp.getPrivate();
            m_pubKey = (ECPublicKey) kp.getPublic();

            
            m_tempKeyPair = new KeyPair(KeyPair.ALG_EC_FP,
                    KeyBuilder.LENGTH_EC_FP_128);
            m_tempKeyPair.genKeyPair();
            m_tempPrivKey = (ECPrivateKey) m_tempKeyPair.getPrivate();
            m_tempPubKey = (ECPublicKey) m_tempKeyPair.getPublic();


                
            short len = m_pubKey.getW(apdubuf, ISO7816.OFFSET_CDATA);
            m_protocolState = EXPECTING_TEMPORARY_KEY;
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
            
        } catch (Exception e) {
            ISOException.throwIt((short) 0xFFD1);
        }
    }

    byte[] generateHashChallenge() {

        m_tempSessionHMACKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
        
        m_tempSessionHMACKey.setKey(m_ramArray, (short) 0, (short) 16);
        m_hmac_sha256.init(m_tempSessionHMACKey, Signature.MODE_SIGN);

        //Copy pubkey to ram
        short pubWLen = m_pubKey.getW(m_ramArray, (short) 0);
        //copy host pub W to ram
        Util.arrayCopy(m_hostPubW, (short) 0, m_ramArray, (short) (pubWLen), (short) m_hostPubW.length);
        //copy temp pub W to ram;
        short tempPubWLen = m_tempPubKey.getW(m_ramArray, (short) (pubWLen + m_hostPubW.length));

        short totalLength = (short) (m_hostPubW.length + pubWLen + tempPubWLen);
        //hash it next and return
        
        byte[] result = new byte[32];
        short resultLen = m_hmac_sha256.sign(m_ramArray,(short) 0, totalLength, result, (short) 0); 
        
        return result;
    }

    void GetEncryptedTempPub(APDU apdu) {

        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        if ((dataLen % 16) != 0) {
            ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        }

        m_decryptCipher.init(pin, Cipher.MODE_DECRYPT);
        short messageLen = m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);

        m_tempHostPubW = new byte[33];
        Util.arrayCopy(m_ramArray, (short) 0, m_tempHostPubW, (short) 0, (short)  33);
        m_secureRandom.nextBytes(m_ramArray, (short) 0, messageLen);

        keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        keyAgreement.init(m_tempPrivKey);
        
        try {
            short secretLen = keyAgreement.generateSecret(m_tempHostPubW, (short) 0, (short) m_tempHostPubW.length, m_ramArray, (short) 0);
        } catch (Exception ex) {
            abort();
        }
        
        //KBA IS IN RAM

        //forget host temporary pub key
        m_secureRandom.nextBytes(m_tempHostPubW, (short) 0, (short) m_tempHostPubW.length);
        m_tempHostPubW = null;

        short pubKeyWLen = m_tempPubKey.getW(apdubuf, ISO7816.OFFSET_CDATA);
        //add hash with key Kba(Public of card, public of host,temp of card)
        byte[] challenge = generateHashChallenge();

        //clean temp keys
        m_tempPubKey.clearKey();
        m_tempPrivKey.clearKey();

        Util.arrayCopy(challenge, (short) 0, apdubuf, (short) (ISO7816.OFFSET_CDATA + pubKeyWLen), (short) challenge.length);
        m_protocolState = EXPECTING_CHALLENGE_ECDH;
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (pubKeyWLen + (short) challenge.length));        

    }
    
    boolean VerifyHostChallenge(byte[] challenge){
        
        //Copy host pub W to ram
        Util.arrayCopy(m_hostPubW, (short) 0, m_ramArray, (short) 0, (short) m_hostPubW.length); 
        
        //copy card pub W to ram
        short pubWLen = m_pubKey.getW(m_ramArray, (short) m_hostPubW.length);
        //add a 0
        m_ramArray[m_hostPubW.length + pubWLen] = 0x0;

        short totalLength = (short) (m_hostPubW.length + pubWLen + 1);
                
        byte[] result = new byte[32];
        short resultLen = m_hmac_sha256.sign(m_ramArray,(short) 0, totalLength, result, (short) 0); 
        
        return Util.arrayCompare(result, (short) 0, challenge, (short) 0, (short) challenge.length) == 0x0;
    }
    
    void GetHostChallenge(APDU apdu){
        try {
            byte[] apdubuf = apdu.getBuffer();
            short dataLen = apdu.setIncomingAndReceive();
            
            byte[] hostChallenge = new byte[dataLen];
            Util.arrayCopy(apdubuf, ISO7816.OFFSET_CDATA, hostChallenge, (short) 0, dataLen);
            
            boolean hostChallengeOK = VerifyHostChallenge(hostChallenge);

            if (!hostChallengeOK){
                //If challenge is not correct
                abort();
            }
            
            keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
            keyAgreement.init(m_privKey);
            short secretLen = keyAgreement.generateSecret(m_hostPubW, (short) 0, (short) m_hostPubW.length, m_ramArray, (short) 0);
            //FROM HERE ON OUT, THE DERIVED SECRET FROM PUB KEYS IS IN RAM
            
            
            //DELET THIS 
            Util.arrayCopy(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, secretLen);
            m_protocolState = EXPECTING_ENC_KEY;
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) secretLen);
            //DELET THAT ^
                     
            
        } catch (Exception e) {
            ISOException.throwIt((short) 0xFFD4);
        }
    }

    // ENCRYPT INCOMING BUFFER
    byte[] Encrypt(byte[] data) {
        short dataLen = (short) data.length;
        short paddLen = (short) (16 - (dataLen % 16));
        
        byte[] paddedData = new byte[dataLen + paddLen];
        java.util.Arrays.fill(paddedData, (byte)paddLen);
        Util.arrayCopy(data, (short) 0, paddedData, (short) (0), dataLen);
        
        dataLen += paddLen;
        byte[] encryptedData = new byte[dataLen];
        
        // CHECK EXPECTED LENGTH (MULTIPLY OF AES BLOCK LENGTH)
        if ((dataLen % 16) != 0) {
            ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        }

        m_encryptCipher.init(m_sessionEncKey, Cipher.MODE_ENCRYPT);
        // ENCRYPT INCOMING BUFFER
        m_encryptCipher.doFinal(paddedData, (short)0, dataLen, m_ramArray, (short) 0);
        
        // NOTE: In-place encryption directly with apdubuf as output can be performed. m_ramArray used to demonstrate Util.arrayCopyNonAtomic

        // COPY ENCRYPTED DATA
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, encryptedData, (short) 0, dataLen);
        return encryptedData;
    }

    // DECRYPT INCOMING BUFFER
    byte[] Decrypt(byte[] data) {
        short dataLen = (short) data.length;
        byte[] decryptedData = new byte[dataLen];

        // CHECK EXPECTED LENGTH (MULTIPLY OF AES BLOCK LENGTH)
        if ((dataLen % 16) != 0) {
            ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        }
        
        m_decryptCipher.init(m_sessionEncKey, Cipher.MODE_DECRYPT);
        // ENCRYPT INCOMING BUFFER
        m_decryptCipher.doFinal(data, (short)0, dataLen, m_ramArray, (short) 0);
        
        // COPY ENCRYPTED DATA INTO BUFFER
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, decryptedData, (short) 0, dataLen);
        
        // REMOVE PADDING
        short paddLen = decryptedData[dataLen - 1];
        byte[] unpaddedData = new byte[dataLen - paddLen];
        Util.arrayCopy(decryptedData, (short) 0, unpaddedData, (short) (0), (short) (dataLen - paddLen));

        return unpaddedData;
    }

    // HASH INCOMING BUFFER
    void Hash(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        if (m_hash != null) {
            m_hash.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);
        } else {
            ISOException.throwIt(SW_OBJECT_NOT_AVAILABLE);
        }

        // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, m_hash.getLength());

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, m_hash.getLength());
    }

    // GENERATE RANDOM DATA
    void Random(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();

        // GENERATE DATA
        short randomDataLen = apdubuf[ISO7816.OFFSET_P1];
        m_secureRandom.generateData(apdubuf, ISO7816.OFFSET_CDATA, randomDataLen);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, randomDataLen);
    }

    // VERIFY PIN
    void VerifyPIN(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // VERIFY PIN
        if (m_pin.check(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen) == false) {
            ISOException.throwIt(SW_BAD_PIN);
        }
    }

    // SET PIN 
    // Be aware - this method will allow attacker to set own PIN - need to protected. 
    // E.g., by additional Admin PIN or all secret data of previous user needs to be reased 
    void SetPIN(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // SET NEW PIN
        m_pin.update(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen);
    }

    // RETURN INPUT DATA UNCHANGED
    byte[] ReturnData(byte[] apdubuf) {
        byte[] returnData = new byte[apdubuf.length - ISO7816.OFFSET_CDATA + 1];
        Util.arrayCopy(apdubuf, (short) (ISO7816.OFFSET_CDATA - 1), returnData, (short) 0, (short) (apdubuf.length - ISO7816.OFFSET_CDATA + 1));
        return returnData;
    }

    byte[] Sign(byte[] data) {
        short dataLen = (short) data.length;
        byte[] signedData = new byte[(short) 32 + dataLen];
        
        // COPY ORIGINAL DATA FIRST
        Util.arrayCopy(data, (short) 0, signedData, (short) 0, dataLen);
        short signLen = 0;

        // SIGN INCOMING BUFFER
        signLen = m_sign.sign(data, (short) 0, (byte) dataLen, m_ramArray, (byte) 0);
        
        // COPY SIGNATURE AFTER ORIGINAL DATA
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, signedData, dataLen, signLen);
        return signedData;
    }
    
    boolean Verify(byte[] signedData){
        short dataLen = (short) (signedData.length - 32);
        return m_verify.verify(signedData, (short) 0, dataLen, signedData, (short)dataLen, (short) 32);
    }
}
