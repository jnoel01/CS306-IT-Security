import java.security.Key; 
import java.security.SecureRandom; 

import javax.crypto.Cipher; 
import javax.crypto.KeyGenerator; 
import java.lang.Math;

// encrypt and decrypt using the DES private key algorithm

public class SymmetricSkeleton {

    public static final int DES_KEY_SIZE = 56; 
    public static final int DES_BLOCK_SIZE = 64; 

    /**
     * Helper function; XOR two arrays of bytes. 
     * Stores the result in the first array.
     */
    public static void mapXOR (byte[] a, byte[] b) {
        int length = Math.min(a.length, b.length); 
        for (int i = 0; i < length; i++ ) {
            a[i] = (byte) ( a[i] ^ b[i] ); 
        }
    }
    
    /**
     * Helper function; determines the number of blocks needed
     * to represent byte array a. If a contains a number of
     * bytes that is not a multiple of the block size, 1 extra
     * block is added for padding.
     */
    public static int numBlocks(byte[] a){
        return (a.length % DES_BLOCK_SIZE == 0)? a.length / DES_BLOCK_SIZE : a.length / DES_BLOCK_SIZE +1;
    }

    /**
     * Run DES in ECB mode to simulate
     * encrypting/decrypting one block at a time.
     */
    public static byte[] customDES(boolean useDecryptMode, byte[] plainText, Key key) throws Exception {

        if (plainText.length != DES_BLOCK_SIZE) throw new Exception("Blocks must all be the same length"); 

        /* construct a cipher object using blockwise DES */
        Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding"); 

        /* If called in decrypt mode, set cipher to decrypt mode, otherwise use encrypt mode */
        if(useDecryptMode) cipher.init(Cipher.DECRYPT_MODE, key);
        else cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(plainText); 
    }

    /**
     * Implement DES encryption with CBC mode of operation. 
     */
    public static byte[] customDESCBCEncrypt(byte[] plainText, byte[] iv, Key key) throws Exception {

        int blocks = numBlock(plainText);
        byte[]= cipherText = new byte[blocks * DES_BLOCK_SIZE], buffer = new byte[DES_BLOCK_SIZE], workingBlock = new byte[DES_BLOCK_SIZE];
        
        //store the IV in a buffer
        System.arraycopy(iv, 0, buffer, 0, DES_BLOCK_SIZE);

        for (int i = 0; i < plainText.lgenth; i += DES_BLOCK_SIZE) {

            //Copy a block of ciphertext into a temp buffer, careful not to overflow
            System.arraycopy(plainText, i, workingBlock, 0, Math.min(plainText.length - i, DES_BLOCK_SIZE));

            //copying the first block size bytes of plaintext into working block. Pad message if not multiple of DES_BLOCK_SIZE with 0's
            if (plainText.length - i < DES_BLOCK_SIZE) for (int j = plainText.length - i; j <workingBlock.length; j++) workingBlock[j] = 0x00;

            //XOR the ciphertext with either the IV or the result of the previous operation
            //working block contains the plaintext
            mapXOR(workingBlock, buffer);

            //first loop the buffer is IV, but in future iterations it becomes the result on the encryption
            //stores the result in the first array

            //perform the encryption
            buffer = customDES(false, workingBlock, key);
            //buffer will be the output directly after encryption

            //Copy the encrypted block to the output buffer
            System.arraycopy(buffer, 0, cipherText, i, DES_BLOCK_SIZE);
        }
        return cipherText;
    }

    /**
     * Implement DES decryption with CBC mode of operation.
     */
    public static byte[] customDESCBCDecrypt(byte[] cipherText, byte[] iv, Key key) throws Exception {
        
    int blocks = numBlocks(cipherText);
    byte[] buffer = new byte[DES_BLOCK_SIZE], workingBlock, ivBuffer = new byte[DES_BLOCK_SIZE], plainText = new byte[blocks * [DES_BLOCK_SIZE]];

    //Store the IV in a Buffer
    System.arraycopy(iv, 0, ivBuffer, 0, DES_BLOCK_SIZE);

    for (int i = 0; i < cipherText.length; i+=DES_BLOCK_SIZE) {

        //copy a block of ciphertext into an input buffer
        System.arraycopy(cipherText, i ,buffer, 0, DES_BLOCK_SIZE);

        //Decrypt the block
        workingBlock = customDES(true, buffer, key);
        //output of the decryption

        //XOR IV with the results of the decryption
        mapXOR(workingBlock, ivBuffer);

        //Set the next IV to be the encrypted block
        System.arraycopy(buffer, 0, ivBuffer, 0, DES_BLOCK_SIZE);

        //Copy decrypted text block to output buffer
        System.arraycopy(workingBlock, 0, plainText, i, DES_BLOCK_SIZE);
    }
    return plainText;
}


     //Main method. Initializes the IV and key, and provides a default message to test with.
    public static void main (String[] args) throws Exception {

        /* Generate IV */
        SecureRandom rand = new SecureRandom(); 
        byte[] iv = new byte[DES_BLOCK_SIZE]; 
        rand.nextBytes(iv);

        /* Generate a key */
        KeyGenerator keyGen = KeyGenerator.getInstance("DES"); 
        keyGen.init(DES_KEY_SIZE);
        Key key = keyGen.generateKey(); 

        /* You can either supply your own string as an argument or use this default string */
        String message ="";
        if(args.length<1){
        	message = "Ave Maria! Jungfrau mild, Erhoere einer Jungfrau Flehen, Aus diesem Felsen starr und wild Soll mein Gebet zu dir hin wehen. "
                    + " Wir schlafen sicher bis zum Morgen, Ob Menschen noch so grausam sind. O Jungfrau, sieh der Jungfrau Sorgen, O Mutter, hoer "
                    + "ein bittend Kind! Ave Maria!";
        }else message = args[0];
        
        /* Print output */
        System.out.println("-- Encrypting the following message: --");
        System.out.println(message);
        byte[] encrypted = customDESCBCEncrypt(message.getBytes(), iv, key);
        System.out.println("\n-- Ciphertext (shouldn't be readable): --");
        System.out.println(new String(encrypted));
        byte[] decrypted = customDESCBCDecrypt(encrypted, iv, key);
        System.out.println("\n-- Result: --");
        System.out.println(new String(decrypted));
    }
}