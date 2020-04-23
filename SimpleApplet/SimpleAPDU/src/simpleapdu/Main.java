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
            card.initSession();
            
            // get random data over protected channel
            byte[] data = card.getRandom((short)10);
            System.out.println(Arrays.toString(data));
            
            // send back the data over protected channel
            byte[] data2 = card.returnData(data);
            System.out.println(Arrays.toString(data2));
            
            card.endSession();

            // try new session
            card.initSession();
            
            // get random data over protected channel
            data = card.getRandom((short)10);
            System.out.println(Arrays.toString(data));
            
            // send back the data over protected channel
            data2 = card.returnData(data);
            System.out.println(Arrays.toString(data2));
            
            card.endSession();
        } catch (Exception ex){
            System.out.println("Exception : " + ex);
        }               
    }
}
