package org.telegram.messenger;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;
import org.telegram.tgnet.SerializedData;
import org.telegram.tgnet.TLRPC;

import java.util.ArrayList;
import java.util.List;

/**
 * Persists previous versions of remotely-edited messages (ZaSto edit history).
 *
 * Per-account SharedPreferences, keyed by the real (dialogId + mid). Each version is a JSON object
 * {@code {"d": <unix seconds>, "t": <previous text/caption>, "m": <base64 of the previous TLRPC.Message>}}.
 * The {@code "m"} blob is present only when the media actually changed (photo/document replaced); it is
 * tiny (ids + file_reference + thumb descriptors — the real pixels stay on disk, kept by the
 * KEEP_EDIT_HISTORY file-preservation guard in MessagesStorage). Mirrors {@link ZaStoDeletedStore} —
 * no DB schema change, revert by flipping {@link ZaStoPrivacy#KEEP_EDIT_HISTORY}.
 */
public final class ZaStoEditHistoryStore {

    private static final int MAX_VERSIONS = 50;

    private static SharedPreferences prefs(int account) {
        return ApplicationLoader.applicationContext.getSharedPreferences("zasto_edits_" + account, Context.MODE_PRIVATE);
    }

    private static String key(long dialogId, int mid) {
        return "h" + dialogId + "_" + mid;
    }

    private static boolean hasDisplayableMedia(TLRPC.Message m) {
        return m != null && m.media != null && (
            (m.media instanceof TLRPC.TL_messageMediaPhoto && m.media.photo instanceof TLRPC.TL_photo) ||
            (m.media instanceof TLRPC.TL_messageMediaDocument && m.media.document instanceof TLRPC.TL_document));
    }

    /**
     * Record the previous version of an edited message. {@code mediaChanged} is the storage-layer
     * "old media is being replaced/lost" signal; when set (and the old media is real) the whole old
     * message is serialized so the old photo/document can be shown later.
     */
    public static synchronized void recordEdit(int account, long dialogId, TLRPC.Message oldMessage, TLRPC.Message newMessage, boolean mediaChanged) {
        if (oldMessage == null || newMessage == null) {
            return;
        }
        String prev = oldMessage.message == null ? "" : oldMessage.message;
        String next = newMessage.message == null ? "" : newMessage.message;
        boolean textChanged = !prev.equals(next);
        boolean keepMedia = mediaChanged && hasDisplayableMedia(oldMessage);
        if (!textChanged && !keepMedia) {
            return; // pure reaction / markup edit — nothing worth keeping
        }
        String mediaB64 = null;
        if (keepMedia) {
            try {
                SerializedData sd = new SerializedData(oldMessage.getObjectSize());
                oldMessage.serializeToStream(sd);
                mediaB64 = Base64.encodeToString(sd.toByteArray(), Base64.NO_WRAP);
                sd.cleanup();
            } catch (Exception ignore) {
            }
        }
        try {
            SharedPreferences p = prefs(account);
            String k = key(dialogId, newMessage.id);
            String existing = p.getString(k, null);
            JSONArray array = existing != null ? new JSONArray(existing) : new JSONArray();
            if (mediaB64 == null && array.length() > 0) {
                JSONObject last = array.optJSONObject(array.length() - 1);
                if (last != null && prev.equals(last.optString("t")) && !last.has("m")) {
                    return; // dedupe a re-delivered identical text-only edit
                }
            }
            int d = oldMessage.edit_date != 0 ? oldMessage.edit_date : oldMessage.date;
            JSONObject e = new JSONObject().put("d", d).put("t", prev);
            if (mediaB64 != null) {
                e.put("m", mediaB64);
            }
            array.put(e);
            while (array.length() > MAX_VERSIONS) {
                array.remove(0);
            }
            p.edit().putString(k, array.toString()).apply();
        } catch (Exception ignore) {
        }
    }

    public static boolean has(int account, long dialogId, int mid) {
        return prefs(account).contains(key(dialogId, mid));
    }

    /** Prior versions, oldest first (empty if none). {@code Version.message} holds the old media when kept. */
    public static List<Version> get(int account, long dialogId, int mid) {
        List<Version> out = new ArrayList<>();
        try {
            String s = prefs(account).getString(key(dialogId, mid), null);
            if (s != null) {
                JSONArray array = new JSONArray(s);
                for (int i = 0; i < array.length(); i++) {
                    JSONObject o = array.optJSONObject(i);
                    if (o == null) {
                        continue;
                    }
                    TLRPC.Message om = null;
                    String m = o.optString("m", null);
                    if (m != null && !m.isEmpty()) {
                        try {
                            byte[] bytes = Base64.decode(m, Base64.NO_WRAP);
                            SerializedData sd = new SerializedData(bytes);
                            om = TLRPC.Message.TLdeserialize(sd, sd.readInt32(false), false);
                            if (om != null) {
                                om.readAttachPath(sd, UserConfig.getInstance(account).getClientUserId());
                            }
                            sd.cleanup();
                        } catch (Exception ignore) {
                        }
                    }
                    out.add(new Version(o.optInt("d"), o.optString("t"), om));
                }
            }
        } catch (Exception ignore) {
        }
        return out;
    }

    public static final class Version {
        public final int date;
        public final String text;
        public final TLRPC.Message message; // old version's message (carries replaced media); null for text-only

        public Version(int date, String text) {
            this(date, text, null);
        }

        public Version(int date, String text, TLRPC.Message message) {
            this.date = date;
            this.text = text;
            this.message = message;
        }
    }

    private ZaStoEditHistoryStore() {
    }
}
