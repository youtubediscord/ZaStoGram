package org.telegram.messenger;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * ZaStoGram privacy/retention overrides.
 *
 * Runtime toggles (default ON) backed by a SharedPreferences file. Feature code reads the static
 * fields directly (e.g. {@code if (ZaStoPrivacy.KEEP_DELETED)}); the settings screen flips them via
 * {@link #set}. Call {@link #load} once at app startup so saved values are applied. Fields stay
 * {@code true} (current behaviour) until/unless the user turns something off.
 */
public final class ZaStoPrivacy {

    private static final String PREFS = "zasto_settings";

    public static final String KEY_KEEP_DELETED = "KEEP_DELETED";
    public static final String KEY_KEEP_EPHEMERAL = "KEEP_EPHEMERAL";
    public static final String KEY_KEEP_EDIT_HISTORY = "KEEP_EDIT_HISTORY";
    public static final String KEY_ALLOW_SAVE_PROTECTED = "ALLOW_SAVE_PROTECTED";
    public static final String KEY_ALLOW_SCREENSHOTS = "ALLOW_SCREENSHOTS";
    public static final String KEY_MUTE_SCREENSHOT_PING = "MUTE_SCREENSHOT_PING";
    public static final String KEY_DISABLE_ADS = "DISABLE_ADS";

    /** Keep messages that the remote side deletes (anti-delete), marked instead of removed. */
    public static boolean KEEP_DELETED = true;

    /** Keep self-destruct / TTL / view-once media; never run the local destruction. */
    public static boolean KEEP_EPHEMERAL = true;

    /** Keep previous versions of remotely-edited messages so the edit history can be viewed. */
    public static boolean KEEP_EDIT_HISTORY = true;

    /** Allow saving/forwarding of content-protected (noforwards) media and stories. */
    public static boolean ALLOW_SAVE_PROTECTED = true;

    /** Do not apply FLAG_SECURE on viewers of other people's content (allow screenshots). */
    public static boolean ALLOW_SCREENSHOTS = true;

    /** Do not send the "took a screenshot" service message to the other party. */
    public static boolean MUTE_SCREENSHOT_PING = true;

    /** Disable Telegram/client sponsored messages, sponsored peers, video ads, and promo dialogs. */
    public static boolean DISABLE_ADS = true;

    private static SharedPreferences prefs() {
        return ApplicationLoader.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    /** Apply saved values (default ON). Safe to call early; on any error fields keep their defaults. */
    public static void load() {
        try {
            SharedPreferences p = prefs();
            KEEP_DELETED = p.getBoolean(KEY_KEEP_DELETED, true);
            KEEP_EPHEMERAL = p.getBoolean(KEY_KEEP_EPHEMERAL, true);
            KEEP_EDIT_HISTORY = p.getBoolean(KEY_KEEP_EDIT_HISTORY, true);
            ALLOW_SAVE_PROTECTED = p.getBoolean(KEY_ALLOW_SAVE_PROTECTED, true);
            ALLOW_SCREENSHOTS = p.getBoolean(KEY_ALLOW_SCREENSHOTS, true);
            MUTE_SCREENSHOT_PING = p.getBoolean(KEY_MUTE_SCREENSHOT_PING, true);
            DISABLE_ADS = p.getBoolean(KEY_DISABLE_ADS, true);
        } catch (Exception ignore) {
        }
    }

    public static boolean get(String key) {
        switch (key) {
            case KEY_KEEP_DELETED: return KEEP_DELETED;
            case KEY_KEEP_EPHEMERAL: return KEEP_EPHEMERAL;
            case KEY_KEEP_EDIT_HISTORY: return KEEP_EDIT_HISTORY;
            case KEY_ALLOW_SAVE_PROTECTED: return ALLOW_SAVE_PROTECTED;
            case KEY_ALLOW_SCREENSHOTS: return ALLOW_SCREENSHOTS;
            case KEY_MUTE_SCREENSHOT_PING: return MUTE_SCREENSHOT_PING;
            case KEY_DISABLE_ADS: return DISABLE_ADS;
        }
        return false;
    }

    public static void set(String key, boolean value) {
        switch (key) {
            case KEY_KEEP_DELETED: KEEP_DELETED = value; break;
            case KEY_KEEP_EPHEMERAL: KEEP_EPHEMERAL = value; break;
            case KEY_KEEP_EDIT_HISTORY: KEEP_EDIT_HISTORY = value; break;
            case KEY_ALLOW_SAVE_PROTECTED: ALLOW_SAVE_PROTECTED = value; break;
            case KEY_ALLOW_SCREENSHOTS: ALLOW_SCREENSHOTS = value; break;
            case KEY_MUTE_SCREENSHOT_PING: MUTE_SCREENSHOT_PING = value; break;
            case KEY_DISABLE_ADS: DISABLE_ADS = value; break;
            default: return;
        }
        try {
            prefs().edit().putBoolean(key, value).apply();
        } catch (Exception ignore) {
        }
    }

    private ZaStoPrivacy() {
    }
}
