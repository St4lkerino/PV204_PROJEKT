/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package simpleapdu;

/**
 *
 * @author St4lker
 */
public class Main {
    
    
    public static void main(String[] args){
        try {
            SecureCardChannel card = new SecureCardChannel();
            card.initSession();
            card.transmit();
        } catch (Exception ex){
            System.out.println("Exception : " + ex);
        }               
    }
}
