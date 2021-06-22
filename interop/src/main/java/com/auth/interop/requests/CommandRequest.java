package com.auth.interop.requests;

import com.auth.interop.contents.ContentEncrypter;
import com.google.gson.Gson;
import com.jcore.crypto.Crypter;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import java.nio.charset.StandardCharsets;

public class CommandRequest<T> {

    public T command;
    public String commandEncoded;
    public String signature;

    public CommandRequest() {
    }

    public CommandRequest(String commandEncoded) {
        this.commandEncoded = commandEncoded;
    }

    public CommandRequest(T command, String signature) {
        this.command = command;
        this.signature = signature;
    }

    public T getCommand(Class<T> aClass, byte[] publicKey, Gson serializer) {
        T ret = null;
        if (publicKey == null) {
            try {
                if (commandEncoded != null)
                    ret = ContentEncrypter.decryptContent(aClass, commandEncoded, serializer);
                else
                    ret = command;
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            try {
                if (commandEncoded == null && signature == null)
                    return null;
                Crypter.Decrypter decrypter = Crypter.Decrypter.newFromRSAPublicKey(publicKey);
                if (commandEncoded != null) {
                    ret = ContentEncrypter.decryptContent(aClass, commandEncoded, decrypter, serializer);
                } else {
                    String json = serializer.toJson(command);
                    String sha256hex = DigestUtils.sha256Hex(json.getBytes(StandardCharsets.UTF_8));
                    String decrypted = decrypter.cryptToString(signature.getBytes(StandardCharsets.UTF_8));
                    if (StringUtils.equals(decrypted, sha256hex))
                        ret = command;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return ret;
    }
}
