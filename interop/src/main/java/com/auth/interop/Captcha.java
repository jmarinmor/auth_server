package com.auth.interop;

import java.util.Random;

public class Captcha extends Inquiry {

    public String image;

    public static Captcha newInstance(boolean debugMode) {
        Captcha ret = new Captcha();
        String key = generateCaptcha(5);
        String value = generateCaptcha(5);

        ret.inquiry = key;
        if (debugMode)
            ret.desiredResult = value;
        return ret;
    }

    public static Captcha newInstance(boolean debugMode, String key, String value) {
        Captcha ret = new Captcha();
        ret.inquiry = key;
        if (debugMode)
            ret.desiredResult = value;
        ret.reason = Reason.HUMAN_VERIFICATION;
        return ret;
    }

    protected static String generateCaptcha(int size) {

//        char data[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
//                'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
//                'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
//                'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
//                'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6',
//                '7', '8', '9' };
        char data[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
                'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
                'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
                'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U',
                'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6',
                '7', '8', '9' };
        char index[] = new char[size];

        int i = 0;

        synchronized (getRandom()) {
            for (i = 0; i < index.length; i++) {
                int ran = getRandom().nextInt(data.length);
                index[i] = data[ran];
            }
        }
        return new String(index);
    }

}
