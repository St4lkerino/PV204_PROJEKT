/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package simpleapdu;

import java.util.Arrays;

/**
 *
 * @author St4lker
 */
public class Main {
    
    
    public static void main(String[] args){
        try {
            SecureCardChannel card = new SecureCardChannel();
            
            if (!card.initSession()){
                return;
            }
            
            // get random data over protected channel
            byte[] data = card.getRandom((short)10);
            
            // send back the data over protected channel
            byte[] data2 = card.returnData(data);
            card.endSession();

            // try new session
            if (!card.initSession()){
                return;
            }
            // get random data over protected channel
            data = card.getRandom((short)10);

            // send back the data over protected channel
            data2 = card.returnData(data);
            
            card.endSession();
        } catch (Exception ex){
            System.out.println("Exception : " + ex);
        }               
    }
}
