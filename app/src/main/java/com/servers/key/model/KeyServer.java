package com.servers.key.model;

import com.servers.interop.ErrorCode;
import com.servers.interop.NamedPublicKey;
import com.servers.interop.commands.*;
import com.servers.interop.requests.CommandRequest;
import com.servers.interop.requests.CommandResponse;
import com.google.gson.Gson;
import com.jcore.crypto.Crypter;

public class KeyServer {
    private KeyDatabase mDatabase;
    private Gson mGson = new Gson();

    public KeyServer(KeyDatabase database) {
        this.mDatabase = database;
    }

    public KeyDatabase getDatabase () {
        return mDatabase;
    }

    public CommandResponse<Integer> setAdminPublicKey(CommandRequest<SetPublicKey> command) {
        if (command == null)
            return new CommandResponse<Integer>(ErrorCode.INVALID_PARAMS);
        if (!command.containsCommand())
            return new CommandResponse<Integer>(ErrorCode.INVALID_PARAMS);

        SetPublicKey cmd = command.getCommand(SetPublicKey.class, mDatabase.getAdminPublicKey(), mGson);
        if (cmd == null)
            return new CommandResponse<Integer>(ErrorCode.INVALID_PARAMS);

        byte[] key_bytes = Crypter.base64StringToBytes(cmd.publicKey);
        ErrorCode ret = mDatabase.setAdminPublicKey(key_bytes);
        return new CommandResponse<Integer>(ret);
    }

    public CommandResponse<String> getServicePublicKey(CommandRequest<GetPublicKey> command) {
        if (command == null)
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);
        if (!command.containsCommand())
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);

        GetPublicKey cmd = command.getCommand(GetPublicKey.class, mDatabase.getAdminPublicKey(), mGson);
        if (cmd == null)
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);

        byte[] key = mDatabase.getServicePublicKey();
        if (key == null)
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);

        String ret = Crypter.bytesToBase64String(key);
        return new CommandResponse<String>(ErrorCode.SUCCEDED, "", ret);
    }

    public CommandResponse<Integer> setServiceKeyPair(CommandRequest<SetKeyPair> command) {
        if (command == null)
            return new CommandResponse<Integer>(ErrorCode.INVALID_PARAMS);
        if (!command.containsCommand())
            return new CommandResponse<Integer>(ErrorCode.INVALID_PARAMS);

        SetKeyPair cmd = command.getCommand(SetKeyPair.class, mDatabase.getAdminPublicKey(), mGson);
        if (cmd == null || cmd.publicKey == null)
            return new CommandResponse<Integer>(ErrorCode.INVALID_PARAMS);

        byte[] publicKey = Crypter.base64StringToBytes(cmd.publicKey);
        if (publicKey == null)
            return new CommandResponse<Integer>(ErrorCode.INVALID_PARAMS);

        byte[] privateKey = Crypter.base64StringToBytes(cmd.privateKey);
        if (privateKey == null)
            return new CommandResponse<Integer>(ErrorCode.INVALID_PARAMS);

        ErrorCode ret = mDatabase.setServiceKeyPair(publicKey, privateKey);
        return new CommandResponse<Integer>(ret);
    }

    public CommandResponse<Integer> panic(CommandRequest<Panic> command) {
        if (command == null)
            return new CommandResponse<Integer>(ErrorCode.INVALID_PARAMS);
        if (!command.containsCommand())
            return new CommandResponse<Integer>(ErrorCode.INVALID_PARAMS);

        Panic cmd = command.getCommand(Panic.class, mDatabase.getServicePrivateKey(), mGson);
        if (cmd == null)
            return new CommandResponse<Integer>(ErrorCode.INVALID_PARAMS);
        mDatabase.panic();
        return new CommandResponse<Integer>(ErrorCode.SUCCEDED);
    }

    public CommandResponse<String> getRandomPublicKeyName(CommandRequest<GetRandomPublicKeyName> command) {
        if (command == null)
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);
        if (!command.containsCommand())
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);

        GetRandomPublicKeyName cmd = command.getCommand(GetRandomPublicKeyName.class, mDatabase.getServicePrivateKey(), mGson);
        if (cmd == null)
            return null;
        String ret = mDatabase.getRandomPublicKeyName(cmd.encoding);
        return new CommandResponse<String>(ErrorCode.SUCCEDED, "", ret);
    }

    public CommandResponse<NamedPublicKey> getServerPublicKey(CommandRequest<GetServerPublicKey> command) {
        if (command == null)
            return new CommandResponse<NamedPublicKey>(ErrorCode.INVALID_PARAMS);
        if (!command.containsCommand())
            return new CommandResponse<NamedPublicKey>(ErrorCode.INVALID_PARAMS);

        GetServerPublicKey cmd = command.getCommand(GetServerPublicKey.class, mDatabase.getServicePrivateKey(), mGson);
        if (cmd == null)
            return null;
        NamedPublicKey ret = mDatabase.getServerPublicKey(cmd.keyName);
        return new CommandResponse<NamedPublicKey>(ErrorCode.SUCCEDED, "", ret);
    }

    public CommandResponse<String> encrypt(CommandRequest<EncryptCommand> command) {
        if (command == null)
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);
        if (!command.containsCommand())
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);

        EncryptCommand cmd = command.getCommand(EncryptCommand.class, mDatabase.getServicePrivateKey(), mGson);
        if (cmd == null || cmd.content == null || cmd.keyName == null)
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);
        byte[] source = Crypter.base64StringToBytes(cmd.content);
        if (source == null)
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);
        byte[] encrypted = mDatabase.encrypt(source, cmd.keyName);
        String ret = Crypter.bytesToBase64String(encrypted);
        return new CommandResponse<String>(ErrorCode.SUCCEDED, "", ret);
    }

    public CommandResponse<String> decrypt(CommandRequest<DecryptCommand> command) {
        if (command == null)
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);
        if (!command.containsCommand())
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);

        DecryptCommand cmd = command.getCommand(DecryptCommand.class, mDatabase.getServicePrivateKey(), mGson);
        if (cmd == null || cmd.content == null || cmd.keyName == null)
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);
        byte[] source = Crypter.base64StringToBytes(cmd.content);
        if (source == null)
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);
        byte[] encrypted = mDatabase.decrypt(source, cmd.keyName);
        String ret = Crypter.bytesToBase64String(encrypted);
        return new CommandResponse<String>(ErrorCode.SUCCEDED, "", ret);
    }

}
