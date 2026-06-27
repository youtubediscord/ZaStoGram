/*
 * This is the source code of Telegram for Android v. 5.x.x.
 * It is licensed under GNU GPL v. 2 or later.
 * You should have received a copy of the license in this archive (see LICENSE).
 */

package org.telegram.messenger;

import android.os.SystemClock;

import org.telegram.tgnet.ConnectionsManager;

import java.util.ArrayList;
import java.util.List;

public class ProxyCheckScheduler {

    private static final long PROXY_CHECK_SPACING_MS = 700L;

    private static final ArrayList<Request> queue = new ArrayList<>();
    private static final Runnable startNextRunnable = ProxyCheckScheduler::startNext;
    private static Request activeRequest;

    public interface Callback {
        void onProxyChecked(SharedConfig.ProxyInfo proxyInfo, long time, String diagnostic);
        void onProxyCheckQueueFinished();
    }

    public static boolean enqueueNow(int currentAccount, SharedConfig.ProxyInfo proxyInfo, Object owner, Callback callback) {
        if (proxyInfo == null || owner == null) {
            log("enqueue_now_rejected endpoint=" + endpoint(proxyInfo));
            return false;
        }
        if (attachPending(proxyInfo, owner, callback, true)) {
            return true;
        }
        clearDetachedCheckState(proxyInfo, "enqueue_now");
        if (proxyInfo.checking) {
            log("enqueue_now_rejected endpoint=" + endpoint(proxyInfo));
            return false;
        }
        queue.add(0, new Request(currentAccount, proxyInfo, owner, callback, true));
        log("enqueue_now endpoint=" + endpoint(proxyInfo) + " queued=" + queue.size());
        AndroidUtilities.runOnUIThread(startNextRunnable);
        return true;
    }

    public static int enqueueStale(int currentAccount, List<SharedConfig.ProxyInfo> proxyList, Object owner, Callback callback) {
        if (proxyList == null || owner == null) {
            log("enqueue_rejected owner=" + owner);
            return 0;
        }
        int added = 0;
        for (int i = 0, count = proxyList.size(); i < count; i++) {
            SharedConfig.ProxyInfo proxyInfo = proxyList.get(i);
            if (attachPending(proxyInfo, owner, callback, false)) {
                added++;
                continue;
            }
            clearDetachedCheckState(proxyInfo, "enqueue");
            if (!shouldCheck(proxyInfo, false)) {
                continue;
            }
            queue.add(new Request(currentAccount, proxyInfo, owner, callback));
            added++;
            log("enqueue endpoint=" + endpoint(proxyInfo) + " queued=" + queue.size());
        }
        if (added > 0) {
            AndroidUtilities.runOnUIThread(startNextRunnable);
        }
        return added;
    }

    public static void clearDetachedCheckStates(List<SharedConfig.ProxyInfo> proxyList, String reason) {
        if (proxyList == null) {
            return;
        }
        for (int i = 0, count = proxyList.size(); i < count; i++) {
            clearDetachedCheckState(proxyList.get(i), reason);
        }
    }

    public static void cancelOwner(Object owner) {
        if (owner == null) {
            return;
        }
        for (int i = queue.size() - 1; i >= 0; i--) {
            Request request = queue.get(i);
            if (request.cancelOwner(owner)) {
                log("cancel_owner endpoint=" + endpoint(request.proxyInfo) + " queued=" + queue.size() + " listeners=" + request.activeListenerCount());
                if (!request.hasActiveListeners()) {
                    request.cancelled = true;
                    queue.remove(i);
                    log("cancel_owner request_removed endpoint=" + endpoint(request.proxyInfo) + " queued=" + queue.size());
                }
            }
        }
        if (activeRequest != null && activeRequest.cancelOwner(owner)) {
            Request request = activeRequest;
            if (!request.hasActiveListeners()) {
                request.cancelled = true;
                SharedConfig.ProxyInfo proxyInfo = request.proxyInfo;
                ConnectionsManager.getInstance(request.currentAccount).cancelProxyCheck(request.nativePingId);
                ProxyRuntimeStateStore.clearTransientState(proxyInfo);
                activeRequest = null;
                log("cancel_owner active endpoint=" + endpoint(proxyInfo));
                AndroidUtilities.runOnUIThread(startNextRunnable, PROXY_CHECK_SPACING_MS);
            } else {
                log("cancel_owner active_listener endpoint=" + endpoint(request.proxyInfo) + " listeners=" + request.activeListenerCount());
            }
        }
    }

    public static boolean hasOwnerPending(Object owner) {
        if (owner == null) {
            return false;
        }
        if (activeRequest != null && activeRequest.hasOwner(owner)) {
            return true;
        }
        for (int i = 0, count = queue.size(); i < count; i++) {
            Request request = queue.get(i);
            if (request.hasOwner(owner)) {
                return true;
            }
        }
        return false;
    }

    public static int cancelEndpointAttempts(String endpointKey) {
        if (endpointKey == null || endpointKey.length() == 0) {
            return 0;
        }
        int cancelled = 0;
        for (int i = queue.size() - 1; i >= 0; i--) {
            Request request = queue.get(i);
            if (!request.matchesEndpointKey(endpointKey)) {
                continue;
            }
            request.cancelAll();
            queue.remove(i);
            cancelled++;
            log("cancel_endpoint queued endpoint=" + endpoint(request.proxyInfo) + " target=" + endpointKey + " queued=" + queue.size());
        }
        if (activeRequest != null && activeRequest.matchesEndpointKey(endpointKey)) {
            Request request = activeRequest;
            request.cancelAll();
            ConnectionsManager.getInstance(request.currentAccount).cancelProxyCheck(request.nativePingId);
            activeRequest = null;
            cancelled++;
            log("cancel_endpoint active endpoint=" + endpoint(request.proxyInfo) + " target=" + endpointKey);
            AndroidUtilities.runOnUIThread(startNextRunnable, PROXY_CHECK_SPACING_MS);
        }
        return cancelled;
    }

    private static boolean shouldCheck(SharedConfig.ProxyInfo proxyInfo, boolean force) {
        if (proxyInfo == null || proxyInfo.checking) {
            return false;
        }
        if (force) {
            return true;
        }
        long now = SystemClock.elapsedRealtime();
        long nextAllowedTime = ProxyRuntimeStateStore.nextAllowedCheckTime(proxyInfo);
        if (nextAllowedTime > now) {
            ProxyRuntimeStateStore.markEndpointCooldown(proxyInfo, now);
            log("skip_backoff endpoint=" + endpoint(proxyInfo) + " wait_ms=" + (nextAllowedTime - now) + " phase=" + ProxyRuntimeStateStore.lastEndpointDiagnostic(proxyInfo));
            return false;
        }
        if (isFresh(proxyInfo)) {
            return false;
        }
        return true;
    }

    public static boolean isFresh(SharedConfig.ProxyInfo proxyInfo) {
        return ProxyRuntimeStateStore.isFresh(proxyInfo);
    }

    public static boolean isEndpointBackedOff(SharedConfig.ProxyInfo proxyInfo) {
        return ProxyRuntimeStateStore.isEndpointBackedOff(proxyInfo);
    }

    public static void markConnected(SharedConfig.ProxyInfo proxyInfo) {
        ProxyRuntimeStateStore.markConnected(proxyInfo);
    }

    public static void markConnectionStarting(SharedConfig.ProxyInfo proxyInfo) {
        ProxyRuntimeStateStore.markConnectionStarting(proxyInfo);
    }

    public static void markConnectionUsable(SharedConfig.ProxyInfo proxyInfo, String diagnostic) {
        ProxyRuntimeStateStore.markConnectionUsable(proxyInfo, diagnostic);
    }

    public static void markEndpointFailure(SharedConfig.ProxyInfo proxyInfo, String diagnostic) {
        ProxyRuntimeStateStore.markEndpointFailure(proxyInfo, diagnostic);
    }

    public static boolean matchesEndpointStageKey(SharedConfig.ProxyInfo proxyInfo, String endpointKey) {
        return ProxyEndpointKey.matchesLiveStage(proxyInfo, endpointKey);
    }

    public static String endpointStageKeyForLiveStage(SharedConfig.ProxyInfo proxyInfo) {
        return ProxyEndpointKey.liveStage(proxyInfo);
    }

    public static String networkEndpointKeyForLiveStage(SharedConfig.ProxyInfo proxyInfo) {
        return ProxyEndpointKey.networkLiveStage(proxyInfo);
    }

    private static boolean hasPending(SharedConfig.ProxyInfo proxyInfo) {
        return findPending(proxyInfo) != null;
    }

    private static boolean attachPending(SharedConfig.ProxyInfo proxyInfo, Object owner, Callback callback, boolean force) {
        Request request = findPending(proxyInfo);
        if (request == null) {
            return false;
        }
        request.force = request.force || force;
        if (request.addListener(proxyInfo, owner, callback)) {
            ProxyRuntimeStateStore.copyTransientState(proxyInfo, request.proxyInfo);
            log("attach_pending endpoint=" + endpoint(proxyInfo) + " listeners=" + request.activeListenerCount() + " force=" + request.force);
        }
        return true;
    }

    private static Request findPending(SharedConfig.ProxyInfo proxyInfo) {
        String key = ProxyEndpointKey.exact(proxyInfo);
        if (key == null) {
            return null;
        }
        if (activeRequest != null && !activeRequest.cancelled && key.equals(ProxyEndpointKey.exact(activeRequest.proxyInfo))) {
            return activeRequest;
        }
        for (int i = 0, count = queue.size(); i < count; i++) {
            Request request = queue.get(i);
            if (!request.cancelled && key.equals(ProxyEndpointKey.exact(request.proxyInfo))) {
                return request;
            }
        }
        return null;
    }

    private static void startNext() {
        if (activeRequest != null) {
            return;
        }
        while (!queue.isEmpty()) {
            Request request = queue.remove(0);
            if (request.cancelled) {
                continue;
            }
            if (!shouldCheck(request.proxyInfo, request.force)) {
                log("skip_fresh endpoint=" + endpoint(request.proxyInfo) + " queued=" + queue.size());
                notifyRequestFinishedIfDrained(request);
                continue;
            }
            startRequest(request);
            return;
        }
    }

    private static void startRequest(Request request) {
        activeRequest = request;
        SharedConfig.ProxyInfo proxyInfo = request.proxyInfo;
        request.setChecking(true);
        log("start endpoint=" + endpoint(proxyInfo) + " queued=" + queue.size());
        long nativePingId = ConnectionsManager.getInstance(request.currentAccount).checkProxy(proxyInfo.address, proxyInfo.port, proxyInfo.username, proxyInfo.password, proxyInfo.secret, (time, diagnostic) -> AndroidUtilities.runOnUIThread(() -> finishRequest(request, time, diagnostic)));
        request.nativePingId = nativePingId;
        request.setProxyCheckPingId(nativePingId);
        if (nativePingId == 0) {
            log("start_failed endpoint=" + endpoint(proxyInfo) + " reason=native_refused");
            finishRequest(request, -1, ProxyCheckDiagnostics.START_FAILED);
        }
    }

    private static void finishRequest(Request request, long time, String diagnostic) {
        if (activeRequest != request) {
            log("finish_ignored endpoint=" + endpoint(request.proxyInfo) + " time=" + time + " diagnostic=" + ProxyCheckDiagnostics.normalize(diagnostic) + " active=" + (activeRequest == null ? "null" : endpoint(activeRequest.proxyInfo)));
            return;
        }
        activeRequest = null;
        String normalizedDiagnostic = normalizedDiagnosticForResult(time, diagnostic);
        String displayDiagnostic = ProxyRuntimeStateStore.displayDiagnosticForProxyCheck(request.proxyInfo, time, normalizedDiagnostic);
        long appliedTime = ProxyRuntimeStateStore.appliedTimeForProxyCheck(request.currentAccount, request.proxyInfo, time);
        long callbackTime = ProxyRuntimeStateStore.callbackTimeForProxyCheck(request.currentAccount, request.proxyInfo, time);
        log("finish result=" + (callbackTime == -1 ? "fail" : "ok") + " phase=" + normalizedDiagnostic + " diagnostic=" + displayDiagnostic + " time=" + callbackTime + " applied_time=" + appliedTime + " raw_time=" + time + " endpoint=" + endpoint(request.proxyInfo) + " queued=" + queue.size() + " cancelled=" + request.cancelled + " listeners=" + request.activeListenerCount());
        ProxyRuntimeStateStore.rememberProxyCheckResult(request.currentAccount, request.proxyInfo, time, displayDiagnostic);
        for (int i = 0, count = request.listeners.size(); i < count; i++) {
            Listener listener = request.listeners.get(i);
            if (listener.cancelled) {
                continue;
            }
            String appliedDiagnostic = ProxyRuntimeStateStore.appliedDiagnosticForProxyCheck(request.currentAccount, listener.proxyInfo, time, displayDiagnostic);
            ProxyRuntimeStateStore.applyMeasuredProxyCheckResult(listener.proxyInfo, appliedTime, appliedDiagnostic);
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxyCheckDone, listener.proxyInfo);
            if (listener.callback != null) {
                listener.callback.onProxyChecked(listener.proxyInfo, callbackTime, displayDiagnostic);
            }
        }
        notifyRequestFinishedIfDrained(request);
        AndroidUtilities.runOnUIThread(startNextRunnable, PROXY_CHECK_SPACING_MS);
    }

    private static String normalizedDiagnosticForResult(long time, String diagnostic) {
        if (time >= 0) {
            return ProxyCheckDiagnostics.OK;
        }
        return ProxyCheckDiagnostics.normalize(diagnostic);
    }

    private static void notifyRequestFinishedIfDrained(Request request) {
        ArrayList<Object> notifiedOwners = new ArrayList<>();
        for (int i = 0, count = request.listeners.size(); i < count; i++) {
            notifyListenerFinishedIfDrained(request.listeners.get(i), notifiedOwners);
        }
    }

    private static void notifyListenerFinishedIfDrained(Listener listener, ArrayList<Object> notifiedOwners) {
        if (listener.cancelled || listener.callback == null || hasOwnerPending(listener.owner) || alreadyNotifiedOwner(listener.owner, notifiedOwners)) {
            return;
        }
        if (listener.owner != null) {
            notifiedOwners.add(listener.owner);
        }
        log("drained owner=" + listener.owner);
        listener.callback.onProxyCheckQueueFinished();
    }

    private static boolean alreadyNotifiedOwner(Object owner, ArrayList<Object> notifiedOwners) {
        return owner != null && notifiedOwners.contains(owner);
    }

    private static void clearDetachedCheckState(SharedConfig.ProxyInfo proxyInfo, String reason) {
        if (proxyInfo != null && proxyInfo.checking && !hasPending(proxyInfo)) {
            ProxyRuntimeStateStore.clearTransientState(proxyInfo);
            log("clear_detached endpoint=" + endpoint(proxyInfo) + " reason=" + reason);
        }
    }

    private static void log(String message) {
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("proxy_check_scheduler " + message);
        }
    }

    private static String endpoint(SharedConfig.ProxyInfo proxyInfo) {
        return ProxyEndpointKey.endpoint(proxyInfo);
    }

    private static class Request {
        final int currentAccount;
        final SharedConfig.ProxyInfo proxyInfo;
        final ArrayList<Listener> listeners = new ArrayList<>();
        long nativePingId;
        boolean force;
        boolean cancelled;

        Request(int currentAccount, SharedConfig.ProxyInfo proxyInfo, Object owner, Callback callback) {
            this(currentAccount, proxyInfo, owner, callback, false);
        }

        Request(int currentAccount, SharedConfig.ProxyInfo proxyInfo, Object owner, Callback callback, boolean force) {
            this.currentAccount = currentAccount;
            this.proxyInfo = proxyInfo;
            this.force = force;
            addListener(proxyInfo, owner, callback);
        }

        boolean addListener(SharedConfig.ProxyInfo proxyInfo, Object owner, Callback callback) {
            for (int i = 0, count = listeners.size(); i < count; i++) {
                Listener listener = listeners.get(i);
                if (!listener.cancelled && listener.owner == owner && listener.proxyInfo == proxyInfo) {
                    return false;
                }
            }
            listeners.add(new Listener(proxyInfo, owner, callback));
            return true;
        }

        boolean cancelOwner(Object owner) {
            boolean changed = false;
            for (int i = 0, count = listeners.size(); i < count; i++) {
                Listener listener = listeners.get(i);
                if (!listener.cancelled && listener.owner == owner) {
                    listener.cancelled = true;
                    listener.callback = null;
                    changed = true;
                }
            }
            if (changed) {
                clearCancelledListenerState();
            }
            return changed;
        }

        void clearCancelledListenerState() {
            for (int i = 0, count = listeners.size(); i < count; i++) {
                Listener listener = listeners.get(i);
                if (listener.cancelled && !hasActiveListenerForProxyInfo(listener.proxyInfo)) {
                    ProxyRuntimeStateStore.clearTransientState(listener.proxyInfo);
                }
            }
        }

        boolean hasActiveListenerForProxyInfo(SharedConfig.ProxyInfo proxyInfo) {
            for (int i = 0, count = listeners.size(); i < count; i++) {
                Listener listener = listeners.get(i);
                if (!listener.cancelled && listener.proxyInfo == proxyInfo) {
                    return true;
                }
            }
            return false;
        }

        boolean hasOwner(Object owner) {
            for (int i = 0, count = listeners.size(); i < count; i++) {
                Listener listener = listeners.get(i);
                if (!listener.cancelled && listener.owner == owner) {
                    return true;
                }
            }
            return false;
        }

        boolean hasActiveListeners() {
            return activeListenerCount() > 0;
        }

        boolean matchesEndpointKey(String endpointKey) {
            return ProxyEndpointKey.matchesTelemetryEndpointKey(proxyInfo, endpointKey);
        }

        void cancelAll() {
            cancelled = true;
            ProxyRuntimeStateStore.clearTransientState(proxyInfo);
            for (int i = 0, count = listeners.size(); i < count; i++) {
                Listener listener = listeners.get(i);
                listener.cancelled = true;
                listener.callback = null;
                ProxyRuntimeStateStore.clearTransientState(listener.proxyInfo);
            }
        }

        int activeListenerCount() {
            int count = 0;
            for (int i = 0, listenersCount = listeners.size(); i < listenersCount; i++) {
                if (!listeners.get(i).cancelled) {
                    count++;
                }
            }
            return count;
        }

        void setChecking(boolean checking) {
            ProxyRuntimeStateStore.setChecking(proxyInfo, checking);
            for (int i = 0, count = listeners.size(); i < count; i++) {
                Listener listener = listeners.get(i);
                if (!listener.cancelled) {
                    ProxyRuntimeStateStore.setChecking(listener.proxyInfo, checking);
                }
            }
        }

        void setProxyCheckPingId(long pingId) {
            ProxyRuntimeStateStore.setProxyCheckPingId(proxyInfo, pingId);
            for (int i = 0, count = listeners.size(); i < count; i++) {
                Listener listener = listeners.get(i);
                if (!listener.cancelled) {
                    ProxyRuntimeStateStore.setProxyCheckPingId(listener.proxyInfo, pingId);
                }
            }
        }
    }

    private static class Listener {
        final SharedConfig.ProxyInfo proxyInfo;
        final Object owner;
        Callback callback;
        boolean cancelled;

        Listener(SharedConfig.ProxyInfo proxyInfo, Object owner, Callback callback) {
            this.proxyInfo = proxyInfo;
            this.owner = owner;
            this.callback = callback;
        }
    }
}
