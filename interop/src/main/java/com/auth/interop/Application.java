package com.auth.interop;

import java.util.UUID;

public class Application {
    public enum RegistryMode {
        OWNER_VERIFICATION,
        USER_INVITATION,
        USER_VERIFICATION
    }
    public UUID owner;
    public UUID gid;
    public String name;
    public RegistryMode registryMode;
    public String appPublicKey;
}
