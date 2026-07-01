package org.telegram.messenger;

import android.util.Base64;

import java.net.IDN;
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
        } else {
            String hash = secretHashForLiveStage(secret);
            if (hash.length() > 0) {
                builder.append(":secret_hash=").append(hash);
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

    public static String networkFromLiveStage(String endpointKey) {
        if (endpointKey == null || endpointKey.length() == 0) {
            return "";
        }
        int kindIndex = liveStageKindIndex(endpointKey);
        if (kindIndex > 0) {
            return endpointKey.substring(0, kindIndex);
        }
        return endpointKey;
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
        return sanitizeSecretDomainForLiveStage(new String(secret, 17, secret.length - 17, StandardCharsets.UTF_8));
    }

    static String secretHashForLiveStage(byte[] secret) {
        if (secret == null || secret.length == 0) {
            return "";
        }
        byte[] digest = Utilities.computeSHA256(secret, 0, secret.length);
        if (digest == null || digest.length < 8) {
            return "";
        }
        byte[] shortDigest = new byte[8];
        System.arraycopy(digest, 0, shortDigest, 0, shortDigest.length);
        return Utilities.bytesToHex(shortDigest).toLowerCase(Locale.US);
    }

    static String sanitizeSecretDomainForLiveStage(String domain) {
        if (domain == null || domain.length() == 0) {
            return "";
        }
        StringBuilder stripped = new StringBuilder(domain.length());
        for (int i = 0, count = domain.length(); i < count; i++) {
            char c = domain.charAt(i);
            if (!Character.isISOControl(c)) {
                stripped.append(c);
            }
        }
        String trimmed = stripped.toString().trim();
        if (trimmed.length() == 0) {
            return "";
        }
        try {
            String ascii = IDN.toASCII(trimmed, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.US);
            return isValidAsciiHostname(ascii) ? ascii : "";
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    private static boolean isValidAsciiHostname(String domain) {
        if (domain == null || domain.length() == 0 || domain.length() > 253 || domain.startsWith(".") || domain.endsWith(".")) {
            return false;
        }
        String[] labels = domain.split("\\.", -1);
        for (String label : labels) {
            if (label.length() == 0 || label.length() > 63 || label.startsWith("-") || label.endsWith("-")) {
                return false;
            }
            for (int i = 0, count = label.length(); i < count; i++) {
                char c = label.charAt(i);
                boolean valid = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
                if (!valid) {
                    return false;
                }
            }
        }
        return true;
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

    private static int liveStageKindIndex(String endpointKey) {
        int result = endpointKey.indexOf(":ee:");
        if (result > 0) {
            return result;
        }
        result = endpointKey.indexOf(":dd:");
        if (result > 0) {
            return result;
        }
        result = endpointKey.indexOf(":legacy");
        return result > 0 ? result : -1;
    }
}
