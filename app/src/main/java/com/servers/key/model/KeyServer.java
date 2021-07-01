package com.servers.key.model;

import com.servers.interop.ErrorCode;
import com.servers.interop.NamedPublicKey;
import com.servers.interop.commands.*;
import com.servers.interop.requests.CommandRequest;
import com.servers.interop.requests.CommandResponse;
import com.google.gson.Gson;
import com.jcore.crypto.Crypter;
import com.servers.interop.requests.PanicCommandRequest;

public class KeyServer {
    private KeyDatabase mDatabase;
    private Gson mGson = new Gson();

    public KeyServer(KeyDatabase database) {
        this.mDatabase = database;
    }

    public KeyDatabase getDatabase () {
        return mDatabase;
    }

    /**
     * This function sets the admin public key. From here, the following requests for admin functionality
     * must be encoded by the admin private key in order to be attended
     * <p>
     * Note: This is an admin function
     * </p>
     * @param command
     * @return
     */
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

    public static class GetServicesRequest extends CommandRequest<GetServices> {
    }

    /**
     *
     * <p>
     * Note: This is an admin function
     * </p>
     * @param command
     * @return
     */
    public CommandResponse<String[]> getServices(GetServicesRequest command) {
        if (command == null)
            return new CommandResponse<String[]>(ErrorCode.INVALID_PARAMS);
        if (!command.containsCommand())
            return new CommandResponse<String[]>(ErrorCode.INVALID_PARAMS);

        GetServices cmd = command.getCommand(GetServices.class, mDatabase.getAdminPublicKey(), mGson);
        if (cmd == null)
            return new CommandResponse<String[]>(ErrorCode.INVALID_PARAMS);

        String[] ret = mDatabase.getServices();
        if (ret == null)
            ret = new String[0];
        return new CommandResponse<String[]>(ErrorCode.SUCCEDED, "", ret);
    }

    public static class GetServiceRequest extends CommandRequest<GetService> {
    }

    /**
     *
     * <p>
     * Note: This is an admin function
     * </p>
     * @param command
     * @return
     */
    public CommandResponse<KeyDatabase.Service> getService(GetServiceRequest command) {
        if (command == null)
            return new CommandResponse<KeyDatabase.Service>(ErrorCode.INVALID_PARAMS);
        if (!command.containsCommand())
            return new CommandResponse<KeyDatabase.Service>(ErrorCode.INVALID_PARAMS);

        GetService cmd = command.getCommand(GetService.class, mDatabase.getAdminPublicKey(), mGson);
        if (cmd == null)
            return new CommandResponse<KeyDatabase.Service>(ErrorCode.INVALID_PARAMS);

        KeyDatabase.Service ret = mDatabase.getService(cmd.code);
        if (ret == null)
            return new CommandResponse<KeyDatabase.Service>(ErrorCode.INVALID_PARAMS);
        return new CommandResponse<KeyDatabase.Service>(ErrorCode.SUCCEDED, "", ret);
    }

    public static class GetServicePrivateKeyRequest extends CommandRequest<GetKey> {
        public String serviceCode;
    }

    public CommandResponse<String> getServicePrivateKey(GetServicePrivateKeyRequest command) {
        if (command == null)
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);
        if (!command.containsCommand())
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);

        GetKey cmd = command.getCommand(GetKey.class, mDatabase.getServicePrivateKey(command.serviceCode), mGson);
        if (cmd == null)
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);

        byte[] key = mDatabase.getServicePrivateKey(command.serviceCode);
        if (key == null)
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);

        String ret = Crypter.bytesToBase64String(key);
        return new CommandResponse<String>(ErrorCode.SUCCEDED, "", ret);
    }

    /**
     * This function can be called from the admin, or from ona of the services. It depends on the
     * command.serviceCode value. If is null, then is an admin command.
     * @param command
     * @return
     */
    public CommandResponse<Integer> panic(PanicCommandRequest command) {
        if (command == null)
            return new CommandResponse<Integer>(ErrorCode.INVALID_PARAMS);
        if (!command.containsCommand())
            return new CommandResponse<Integer>(ErrorCode.INVALID_PARAMS);

        if (command.serviceCode == null) {
            Panic cmd = command.getCommand(Panic.class, mDatabase.getAdminPublicKey(), mGson);
            if (cmd == null)
                return new CommandResponse<Integer>(ErrorCode.INVALID_PARAMS);
            mDatabase.panic(null);
            return new CommandResponse<Integer>(ErrorCode.SUCCEDED);
        } else {
            Panic cmd = command.getCommand(Panic.class, mDatabase.getServicePrivateKey(command.serviceCode), mGson);
            if (cmd == null)
                return new CommandResponse<Integer>(ErrorCode.INVALID_PARAMS);
            mDatabase.panic(command.serviceCode);
            return new CommandResponse<Integer>(ErrorCode.SUCCEDED);
        }
    }

    public static class GetRandomPublicKeyNameRequest extends CommandRequest<GetRandomPublicKeyName> {
        public String serviceCode;
    }

    public CommandResponse<String> getRandomPublicKeyName(GetRandomPublicKeyNameRequest command) {
        if (command == null)
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);
        if (!command.containsCommand())
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);

        GetRandomPublicKeyName cmd = command.getCommand(GetRandomPublicKeyName.class, mDatabase.getServicePrivateKey(command.serviceCode), mGson);
        if (cmd == null)
            return null;
        String ret = mDatabase.getRandomPublicKeyName(cmd.encoding);
        return new CommandResponse<String>(ErrorCode.SUCCEDED, "", ret);
    }

    public static class GetPublicKeyRequest extends CommandRequest<GetKey> {
        public String serviceCode;
    }

    public CommandResponse<NamedPublicKey> getPublicKey(GetPublicKeyRequest command) {
        if (command == null)
            return new CommandResponse<NamedPublicKey>(ErrorCode.INVALID_PARAMS);
        if (!command.containsCommand())
            return new CommandResponse<NamedPublicKey>(ErrorCode.INVALID_PARAMS);

        GetKey cmd = command.getCommand(GetKey.class, mDatabase.getServicePrivateKey(command.serviceCode), mGson);
        if (cmd == null)
            return null;
        NamedPublicKey ret = mDatabase.getPublicKey(cmd.keyName);
        return new CommandResponse<NamedPublicKey>(ErrorCode.SUCCEDED, "", ret);
    }

    public static class EncryptCommandRequest extends CommandRequest<EncryptCommand> {
        public String serviceCode;
    }

    public CommandResponse<String> encrypt(EncryptCommandRequest command) {
        if (command == null)
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);
        if (!command.containsCommand())
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);

        EncryptCommand cmd = command.getCommand(EncryptCommand.class, mDatabase.getServicePrivateKey(command.serviceCode), mGson);
        if (cmd == null || cmd.content == null || cmd.keyName == null)
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);
        byte[] source = Crypter.base64StringToBytes(cmd.content);
        if (source == null)
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);
        byte[] encrypted = mDatabase.encrypt(source, cmd.keyName);
        String ret = Crypter.bytesToBase64String(encrypted);
        return new CommandResponse<String>(ErrorCode.SUCCEDED, "", ret);
    }

    public static class DecryptCommandRequest extends CommandRequest<DecryptCommand> {
        public String serviceCode;
    }

    public CommandResponse<String> decrypt(DecryptCommandRequest command) {
        if (command == null)
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);
        if (!command.containsCommand())
            return new CommandResponse<String>(ErrorCode.INVALID_PARAMS);

        DecryptCommand cmd = command.getCommand(DecryptCommand.class, mDatabase.getServicePrivateKey(command.serviceCode), mGson);
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
