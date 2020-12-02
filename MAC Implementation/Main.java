package stevens.cs306.mac;

import java.security.Key;
import javax.xml.bind.DatatypeConverter;

public class Main {

    public static void main(String[] args) {
        boolean verify = false;
        String message = "This is a test message.  There are many like it but"
            + " this one is mine.";
        String secret = "CS-306_Test_Key";
        byte[] tag = null;

        switch (args.length) {
            case 3:
                verify = true;
                tag = toByteArray(args[2]);
            case 2:
                secret = args[1];
            case 1:
                message = args[0];
                break;
            case 0:
                break;
            default:
                System.err.println("Unexpected number of params");
                usage();
                System.exit(1);
                break;
        }

        Mac mac = new Mac();
        Key key = mac.generate(secret.getBytes());

        System.err.println("## Key ##\n" + secret + "\n");
        System.err.println("## Message ##\n" + message + "\n");
        if (!verify) {
            tag = mac.mac(message.getBytes(), key);
        }
        System.err.println("## Tag ##\n" + toHexString(tag) + "\n");

        if (mac.verify(message.getBytes(), tag, key)) {
            System.err.println("Success, tag was verified.");
        } else {
            System.err.println("Error, tag was not verified.");
        }
    }

    public static String toHexString(byte[] array) {
        return DatatypeConverter.printHexBinary(array);
    }

    public static byte[] toByteArray(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }

    public static void usage() {
        System.err.println("usage: java stevens.cs306.mac.Main [message [key [tag]]]");
    }

}

