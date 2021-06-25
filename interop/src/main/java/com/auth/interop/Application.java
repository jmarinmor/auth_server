package com.auth.interop;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

public class Application {
    public UUID userId;
    public String appCode;
    public Set<String> appFields;
    public Map<String, String> publicKeys;
    public Map<Integer, String> uiServersURLs;
}
