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
    final static byte SESH_KEYS = (byte) 0x5d;

    final static short ARRAY_LENGTH = (short) 0xff;
    final static byte AES_BLOCK_LENGTH = (short) 0x16;

    final static short SW_BAD_TEST_DATA_LEN = (short) 0x6680;
    final static short SW_KEY_LENGTH_BAD = (short) 0x6715;
    final static short SW_CIPHER_DATA_LENGTH_BAD = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE = (short) 0x6711;
    final static short SW_BAD_PIN = (short) 0x6900;

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
    private KeyPair kp2;
    private ECPrivateKey m_privKey;
    private ECPublicKey m_pubKey;
    private ECPrivateKey m_tempPrivKey;
    private ECPublicKey m_tempPubKey;
    private byte[] m_tempHostPubW;
    private byte[] m_hostPubW;
    private MessageDigest md5_hash = null;
    private Signature  m_hmac_sha256 = null;
    private HMACKey m_tempSessionHMACKey = null;
    private short m_maxNumberOfTries = 3;
    

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

            pin = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, (short) 128, true);

            md5_hash.doFinal(buffer, dataOffset, buffer[dataOffset - 1], m_ramArray, (short) 0);
            pin.setKey(m_ramArray, (short) 0);
            m_decryptCipher.init(pin, Cipher.MODE_DECRYPT);
            m_secureRandom.nextBytes(m_ramArray, (short) 0, (short) 16);

            // update flag
            isOP2 = true;

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
                switch (apduBuffer[ISO7816.OFFSET_INS]) {
                    case INS_ENCRYPT:
                        Encrypt(apdu);
                        break;
                    case INS_DECRYPT:
                        Decrypt(apdu);
                        break;
                    case INS_HASH:
                        Hash(apdu);
                        break;
                    case INS_RANDOM:
                        Random(apdu);
                        break;
                    case INS_VERIFYPIN:
                        VerifyPIN(apdu);
                        break;
                    case INS_SETPIN:
                        SetPIN(apdu);
                        break;
                    case INS_RETURNDATA:
                        ReturnData(apdu);
                        break;
                    case INS_SIGNDATA:
                        Sign(apdu);
                        break;
                    case INS_KEYPAIR:
                        GenerateKeyPair(apdu);
                        break;
                    case INS_EXCHANGE_PUBS:
                        ExchangePubKeys(apdu);
                        break;
                    case INS_GET_HOST_TMP_PUB:
                        GetEncryptedTempPub(apdu);
                        break;
                    case INS_GET_HOST_CHALLENGE:
                        GetHostChallenge(apdu);
                        break;
                    case SESH_KEYS:
                        SessionKeys(apdu);
                        break;
                    default:
                        // The INS code is not supported by the dispatcher
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                        break;
                }
            } else {
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
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

    void clearSessionData() {
        // E.g., fill sesssion data in RAM with zeroes
        Util.arrayFillNonAtomic(m_ramArray, (short) 0, (short) m_ramArray.length, (byte) 0);
        // Or better fill with random data
        m_secureRandom.generateData(m_ramArray, (short) 0, (short) m_ramArray.length);
    }

    void GenerateKeyPair(APDU apdu) {
        try {

        } catch (Exception e) {
            ISOException.throwIt((short) 0xFFD1);
        }
    }
    
    // Exchange challenges and derive session keys from them, using DH secret
    void SessionKeys(APDU apdu){
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        byte[] derivData = new byte[16];

        // CHECK EXPECTED LENGTH == 8
        if ((dataLen % 8) != 0) {
            ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        }
        Util.arrayCopy(apdubuf, ISO7816.OFFSET_CDATA, derivData, (short) 4, (short) 4);
        Util.arrayCopy(apdubuf, ISO7816.OFFSET_CDATA, derivData, (short) 12, (short) 4);
        
        // GENERATE CARD CHALLENGE
        
        
        // SEND CARD CHALLENGE IN RESPONSE APDU
        
        
        // GET SESSION KEYS FROM DERIVATION DATA (CHALLENGES COMBINED)
        
    }

    void ExchangePubKeys(APDU apdu) {
        try {
            byte[] apdubuf = apdu.getBuffer();
            short dataLen = apdu.setIncomingAndReceive();
            
            m_hostPubW = new byte[dataLen];
            Util.arrayCopy(apdubuf, ISO7816.OFFSET_CDATA, m_hostPubW, (short) 0, dataLen);

            kp = new KeyPair(KeyPair.ALG_EC_FP,
                    KeyBuilder.LENGTH_EC_FP_128);
            kp.genKeyPair();
            m_privKey = (ECPrivateKey) kp.getPrivate();
            m_pubKey = (ECPublicKey) kp.getPublic();

            //keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
            //keyAgreement.init(m_privKey);   
            //short secretLen = keyAgreement.generateSecret(apdubuf, (short) ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short)0);
            
            kp2 = new KeyPair(KeyPair.ALG_EC_FP,
                    KeyBuilder.LENGTH_EC_FP_128);
            kp2.genKeyPair();
            m_tempPrivKey = (ECPrivateKey) kp2.getPrivate();
            m_tempPubKey = (ECPublicKey) kp2.getPublic();


            short len = m_pubKey.getW(apdubuf, ISO7816.OFFSET_CDATA);
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);

            
        } catch (Exception e) {
            ISOException.throwIt((short) 0xFFD1);
        }
    }

    byte[] GenerateHashChallenge(short secretLength) {

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
        try {
            byte[] apdubuf = apdu.getBuffer();
            short dataLen = apdu.setIncomingAndReceive();

            if ((dataLen % 16) != 0) {
                ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
            }
            
            short hostWLen = m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);

            m_tempHostPubW = new byte[33];
            for (int i = 0; i < 33; i++) {
                m_tempHostPubW[i] = m_ramArray[i]; //change to arrayCopy
            }
            //TODO clear

            keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
            keyAgreement.init(m_tempPrivKey);
            short secretLen = keyAgreement.generateSecret(m_tempHostPubW, (short) 0, (short) m_tempHostPubW.length, m_ramArray, (short) 0);
            //KBA V RAM

            short len = m_tempPubKey.getW(apdubuf, ISO7816.OFFSET_CDATA);
            //add hash(Public of card, public of host, KBA, temp of card
            byte[] challenge = GenerateHashChallenge(secretLen);
            
            Util.arrayCopy(challenge, (short) 0, apdubuf, (short) (ISO7816.OFFSET_CDATA + len), (short) challenge.length);

            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (len + (short) challenge.length));
            
            
        } catch (Exception e) {
            ISOException.throwIt((short) 0xFFD3);
        }
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
                m_maxNumberOfTries--;
                ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
            }
            
            keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
            keyAgreement.init(m_privKey);
            short secretLen = keyAgreement.generateSecret(m_hostPubW, (short) 0, (short) m_hostPubW.length, m_ramArray, (short) 0);
            //FROM HERE ON OUT, THE DERIVED SECRET FROM PUB KEYS IS IN RAM
            
            
            //DELET THIS 
            //Util.arrayCopy(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, secretLen);
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) secretLen);
            //DELET THAT ^
                     
            
        } catch (Exception e) {
            ISOException.throwIt((short) 0xFFD4);
        }
    }

    // ENCRYPT INCOMING BUFFER
    void Encrypt(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // CHECK EXPECTED LENGTH (MULTIPLY OF AES BLOCK LENGTH)
        if ((dataLen % 16) != 0) {
            ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        }

        // ENCRYPT INCOMING BUFFER
        m_encryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);
        // NOTE: In-place encryption directly with apdubuf as output can be performed. m_ramArray used to demonstrate Util.arrayCopyNonAtomic

        // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }

    // DECRYPT INCOMING BUFFER
    void Decrypt(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // CHECK EXPECTED LENGTH (MULTIPLY OF AES BLOCK LENGTH)
        if ((dataLen % 16) != 0) {
            ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        }

        // ENCRYPT INCOMING BUFFER
        m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);

        // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
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

    // RETURN INPU DATA UNCHANGED
    void ReturnData(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }

    void Sign(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        short signLen = 0;

        // SIGN INCOMING BUFFER
        // COPY SIGNED DATA INTO OUTGOING BUFFER
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, signLen);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, signLen);
    }
}
