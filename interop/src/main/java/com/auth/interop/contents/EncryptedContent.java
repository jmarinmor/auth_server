package com.auth.interop.contents;

import com.google.gson.Gson;

import javax.crypto.Cipher;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class EncryptedContent<T> {

    private static Class<?> mPersistentClass;
    // Base64
    public String content;

    public EncryptedContent() {
        if (mPersistentClass == null) {
            Type c = ((ParameterizedType)getClass().getGenericSuperclass()).getActualTypeArguments()[0];
            mPersistentClass = (Class<T>)c;
        }
    }

    public EncryptedContent<T> setContent(T content, Cipher cipher1, Cipher cipher2, Gson serializer) throws Exception {
        this.content = ContentEncrypter.encryptContent(content, cipher1, cipher2, serializer);
        return this;
    }

    public T getContent(Cipher cipher1, Cipher cipher2, Gson serializer) throws Exception {
        return ContentEncrypter.decryptContent((Class<T>)mPersistentClass, content, cipher1, cipher2, serializer);
    }

    public EncryptedContent<T> setContent(T content, Cipher cipher, Gson serializer) throws Exception {
        this.content = ContentEncrypter.encryptContent(content, cipher, serializer);
        return this;
    }

    public T getContent(Cipher cipher, Gson serializer) throws Exception {
        return ContentEncrypter.decryptContent((Class<T>)mPersistentClass, content, serializer);
    }

    public EncryptedContent<T> setContent(T content, Gson serializer) throws Exception {
        this.content = ContentEncrypter.encryptContent(content, serializer);
        return this;
    }

    public T getContent(Gson serializer) throws Exception {
        return ContentEncrypter.decryptContent((Class<T>)mPersistentClass, content, serializer);
    }


}
