package com.servers.interop.contents;

import com.google.gson.Gson;
import com.jcore.crypto.Crypter;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;

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

    public EncryptedContent<T> setContent(T content, Crypter cipher1, Crypter cipher2, Gson serializer) throws Exception {
        this.content = ContentEncrypter.encryptContent(content, cipher1, cipher2, serializer);
        return this;
    }

    public T getContent(Crypter cipher1, Crypter cipher2, Gson serializer) throws Exception {
        return ContentEncrypter.decryptContent((Class<T>)mPersistentClass, content, cipher1, cipher2, serializer);
    }

    public EncryptedContent<T> setContent(T content, Crypter cipher, Gson serializer) throws Exception {
        this.content = ContentEncrypter.encryptContent(content, cipher, serializer);
        return this;
    }

    public T getContent(Crypter cipher, Gson serializer) throws Exception {
        return ContentEncrypter.decryptContent((Class<T>)mPersistentClass, content, cipher, serializer);
    }

    public EncryptedContent<T> setContent(T content, Gson serializer) throws Exception {
        this.content = ContentEncrypter.encryptContent(content, serializer);
        return this;
    }

    public T getContent(Gson serializer) throws Exception {
        return ContentEncrypter.decryptContent((Class<T>)mPersistentClass, content, serializer);
    }


}
