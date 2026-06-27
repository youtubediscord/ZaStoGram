package org.telegram.messenger;

import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

public final class ProxyEndpointKey {

    private ProxyEndpointKey() {
    }

    public static String exact(SharedConfig.ProxyInfo proxyInfo) {
        if (proxyInfo == null) {
            return null;
        }
        StringBuilder builder = new StringBuilder();
        appendKeyPart(builder, normalizeKeyPart(proxyInfo.address, true));
        appendKeyPart(builder, String.valueOf(proxyInfo.port));
        appendKeyPart(builder, normalizeKeyPart(proxyInfo.username, false));
        appendKeyPart(builder, normalizeKeyPart(proxyInfo.password, false));
        appendKeyPart(builder, normalizeKeyPart(proxyInfo.secret, false));
        return builder.toString();
    }

    public static String network(SharedConfig.ProxyInfo proxyInfo) {
        if (proxyInfo == null) {
            return null;
        }
        StringBuilder builder = new StringBuilder();
        appendKeyPart(builder, normalizeKeyPart(proxyInfo.address, true));
        appendKeyPart(builder, String.valueOf(proxyInfo.port));
        return builder.toString();
    }

    public static String forPhase(SharedConfig.ProxyInfo proxyInfo, String phase) {
        switch (ProxyPhasePolicy.keyScope(phase)) {
            case NETWORK:
                return network(proxyInfo);
            case EXACT:
                return exact(proxyInfo);
            case NONE:
            default:
                return null;
        }
    }

    public static boolean matchesLiveStage(SharedConfig.ProxyInfo proxyInfo, String endpointKey) {
        if (proxyInfo == null || endpointKey == null || endpointKey.length() == 0) {
            return false;
        }
        return liveStage(proxyInfo).equals(endpointKey);
    }

    public static boolean matchesTelemetryEndpointKey(SharedConfig.ProxyInfo proxyInfo, String endpointKey) {
        if (proxyInfo == null || endpointKey == null || endpointKey.length() == 0) {
            return false;
        }
        return sameTelemetryEndpointKey(liveStage(proxyInfo), endpointKey)
                || sameTelemetryEndpointKey(networkLiveStage(proxyInfo), endpointKey);
    }

    public static boolean sameTelemetryEndpointKey(String left, String right) {
        if (left == null || right == null || left.length() == 0 || right.length() == 0) {
            return false;
        }
        return left.equals(right) || left.startsWith(right + ":") || right.startsWith(left + ":");
    }

    public static String liveStage(SharedConfig.ProxyInfo proxyInfo) {
        if (proxyInfo == null) {
            return "";
        }
        byte[] secret = decodedSecretForLiveStage(proxyInfo.secret);
        String kind = secretKindForLiveStage(secret);
        if ("none".equals(kind)) {
            return networkLiveStage(proxyInfo);
        }
        StringBuilder builder = new StringBuilder();
        builder.append(normalizeKeyPart(proxyInfo.address, false)).append(":").append(proxyInfo.port).append(":").append(kind);
        if ("ee".equals(kind)) {
            String domain = secretDomainForLiveStage(secret);
            if (domain.length() > 0) {
                builder.append(":").append(domain);
            }
        }
        return builder.toString();
    }

    public static String networkLiveStage(SharedConfig.ProxyInfo proxyInfo) {
        if (proxyInfo == null) {
            return "";
        }
        return normalizeKeyPart(proxyInfo.address, true) + ":" + proxyInfo.port;
    }

    public static String endpoint(SharedConfig.ProxyInfo proxyInfo) {
        if (proxyInfo == null) {
            return "null";
        }
        return proxyInfo.address + ":" + proxyInfo.port;
    }

    static byte[] decodedSecretForLiveStage(String secret) {
        if (secret == null || secret.length() == 0) {
            return new byte[0];
        }
        boolean allHex = true;
        for (int i = 0, count = secret.length(); i < count; i++) {
            char c = secret.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                allHex = false;
                break;
            }
        }
        if (allHex) {
            int size = secret.length() / 2;
            byte[] result = new byte[size];
            for (int i = 0; i < size; i++) {
                int high = Character.digit(secret.charAt(i * 2), 16);
                int low = Character.digit(secret.charAt(i * 2 + 1), 16);
                result[i] = (byte) (high * 16 + low);
            }
            return result;
        }
        int remainder = secret.length() & 3;
        if (remainder == 1) {
            return new byte[0];
        }
        String padded = secret;
        if (remainder != 0) {
            padded += remainder == 2 ? "==" : "=";
        }
        try {
            return Base64.decode(padded, Base64.URL_SAFE | Base64.NO_WRAP);
        } catch (IllegalArgumentException e) {
            return new byte[0];
        }
    }

    static String secretKindForLiveStage(byte[] secret) {
        if (secret == null || secret.length == 0) {
            return "none";
        }
        int first = secret[0] & 0xff;
        if (secret.length >= 17 && first == 0xdd) {
            return "dd";
        }
        if (secret.length > 17 && first == 0xee) {
            return "ee";
        }
        return "legacy";
    }

    static String secretDomainForLiveStage(byte[] secret) {
        if (secret == null || secret.length <= 17 || (secret[0] & 0xff) != 0xee) {
            return "";
        }
        return new String(secret, 17, secret.length - 17, StandardCharsets.UTF_8);
    }

    static String normalizeKeyPart(String value, boolean lowerCase) {
        if (value == null) {
            return "";
        }
        return lowerCase ? value.toLowerCase(Locale.US) : value;
    }

    private static void appendKeyPart(StringBuilder builder, String value) {
        builder.append(value.length()).append(':').append(value);
    }
}
