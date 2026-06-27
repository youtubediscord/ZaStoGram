package org.telegram.tgnet;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.InstallSourceInfo;
import android.content.pm.PackageInfo;
import android.net.DnsResolver;
import android.os.AsyncTask;
import android.os.Build;
import android.os.CancellationSignal;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.Base64;

import androidx.annotation.Keep;

import com.google.android.exoplayer2.upstream.DefaultBandwidthMeter;
import com.google.android.gms.tasks.Task;
import com.google.android.play.core.integrity.IntegrityManager;
import com.google.android.play.core.integrity.IntegrityManagerFactory;
import com.google.android.play.core.integrity.IntegrityTokenRequest;
import com.google.android.play.core.integrity.IntegrityTokenResponse;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;

import org.json.JSONArray;
import org.json.JSONObject;
import org.telegram.messenger.AccountInstance;
import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.BaseController;
import org.telegram.messenger.BuildVars;
import org.telegram.messenger.CaptchaController;
import org.telegram.messenger.EmuDetector;
import org.telegram.messenger.FileLoadOperation;
import org.telegram.messenger.FileLoader;
import org.telegram.messenger.FileLog;
import org.telegram.messenger.FileUploadOperation;
import org.telegram.messenger.KeepAliveJob;
import org.telegram.messenger.LocaleController;
import org.telegram.messenger.MessagesController;
import org.telegram.messenger.NotificationCenter;
import org.telegram.messenger.ProxyConnectionEvent;
import org.telegram.messenger.ProxyRuntimeStateStore;
import org.telegram.messenger.PushListenerController;
import org.telegram.messenger.SharedConfig;
import org.telegram.messenger.StatsController;
import org.telegram.messenger.UserConfig;
import org.telegram.messenger.Utilities;
import org.telegram.ui.Components.VideoPlayer;
import org.telegram.ui.LoginActivity;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.TimeZone;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLException;

public class ConnectionsManager extends BaseController {

    public final static int ConnectionTypeGeneric = 1;
    public final static int ConnectionTypeDownload = 2;
    public final static int ConnectionTypeUpload = 4;
    public final static int ConnectionTypePush = 8;
    public final static int ConnectionTypeDownload2 = ConnectionTypeDownload | (1 << 16);

    public final static int FileTypePhoto = 0x01000000;
    public final static int FileTypeVideo = 0x02000000;
    public final static int FileTypeAudio = 0x03000000;
    public final static int FileTypeFile = 0x04000000;

    public final static int RequestFlagEnableUnauthorized = 1;
    public final static int RequestFlagFailOnServerErrors = 2;
    public final static int RequestFlagCanCompress = 4;
    public final static int RequestFlagWithoutLogin = 8;
    public final static int RequestFlagTryDifferentDc = 16;
    public final static int RequestFlagForceDownload = 32;
    public final static int RequestFlagInvokeAfter = 64;
    public final static int RequestFlagNeedQuickAck = 128;
    public final static int RequestFlagDoNotWaitFloodWait = 1024;
    public final static int RequestFlagListenAfterCancel = 2048;
    public final static int RequestFlagFailOnServerErrorsExceptFloodWait = 65536;

    public final static int ConnectionStateConnecting = 1;
    public final static int ConnectionStateWaitingForNetwork = 2;
    public final static int ConnectionStateConnected = 3;
    public final static int ConnectionStateConnectingToProxy = 4;
    public final static int ConnectionStateUpdating = 5;

    public final static byte USE_IPV4_ONLY = 0;
    public final static byte USE_IPV6_ONLY = 1;
    public final static byte USE_IPV4_IPV6_RANDOM = 2;

    public final static int MT_PROXY_TLS_PROFILE_AUTO = 0;
    public final static int MT_PROXY_TLS_PROFILE_FIREFOX = 1;
    public final static int MT_PROXY_TLS_PROFILE_ANDROID_CHROME = 2;
    public final static int MT_PROXY_TLS_PROFILE_YANDEX = 3;
    public final static int MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID = 4;
    public final static int MT_PROXY_TLS_PROFILE_ANDROID_OKHTTP = 5;
    public final static int MT_PROXY_TLS_PROFILE_AUTO_ROTATE = 6;
    public final static int MT_PROXY_TLS_PROFILE_CHROME_MODERN = 7;
    public final static int MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF = 0;
    public final static int MT_PROXY_CLIENT_HELLO_FRAGMENTATION_SOFT = 1;
    public final static int MT_PROXY_RECORD_SIZING_OFF = 0;
    public final static int MT_PROXY_RECORD_SIZING_CONSERVATIVE = 1;
    public final static int MT_PROXY_RECORD_SIZING_VARIED = 2;
    public final static int MT_PROXY_TIMING_OFF = 0;
    public final static int MT_PROXY_TIMING_GENTLE = 1;
    public final static int MT_PROXY_TIMING_BALANCED = 2;
    public final static int MT_PROXY_STARTUP_COVER_OFF = 0;
    public final static int MT_PROXY_STARTUP_COVER_SOFT = 1;
    public final static int MT_PROXY_STARTUP_COVER_STRICT = 2;
    public final static int MT_PROXY_CONNECTION_PATTERN_OFF = 0;
    public final static int MT_PROXY_CONNECTION_PATTERN_SOFT = 1;
    public final static int MT_PROXY_CONNECTION_PATTERN_QUIET = 2;
    public final static int MT_PROXY_CONNECTION_PATTERN_STRICT = 3;
    public final static int MT_PROXY_CONNECTION_PATTERN_BROWSER = 4;
    public final static int WSS_TRANSPORT_OFF = SharedConfig.TRANSPORT_LEGACY_PROXY;
    public final static int WSS_TRANSPORT_OFFICIAL = SharedConfig.TRANSPORT_WSS_OFFICIAL;
    public final static int WSS_TRANSPORT_CUSTOM = SharedConfig.TRANSPORT_WSS_CUSTOM;
    public final static int WSS_TRANSPORT_SOCKS5 = SharedConfig.TRANSPORT_WSS_SOCKS5;
    public static final String BACKGROUND_NETWORK_ALWAYS_ON = "backgroundNetworkAlwaysOn";

    private static final int MT_PROXY_TLS_PROFILE_RANDOM_COUNT = 2;
    private static final String MT_PROXY_TLS_PROFILE_PREFS = "mtproxy_tls_profile";
    private static final String MT_PROXY_TLS_PROFILE_SALT = "profile_salt_v1";
    private static final String MT_PROXY_TLS_PROFILE_OVERRIDE = "profile_override";
    private static final String DOH_USER_AGENT = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36";
    private static final String DOH_GOOGLE_QUERY_ENDPOINT = "https://dns.google/resolve";
    private static final String DOH_CLOUDFLARE_QUERY_ENDPOINT = "https://cloudflare-dns.com/dns-query";
    private static final int HOST_RESOLVER_SYSTEM_TIMEOUT_MS = 1500;
    private static final int HOST_RESOLVER_DOH_CONNECT_TIMEOUT_MS = 1000;
    private static final int HOST_RESOLVER_DOH_READ_TIMEOUT_MS = 1500;
    private static final int HOST_RESOLVER_TOTAL_TIMEOUT_MS = 3000;
    private static final long HOST_RESOLVER_MAX_FRESH_TTL_MS = 30 * 60 * 1000L;
    private static final long HOST_RESOLVER_STALE_TTL_MS = 60 * 60 * 1000L;

    private static long lastDnsRequestTime;

    public final static int DEFAULT_DATACENTER_ID = Integer.MAX_VALUE;

    private long lastPauseTime = System.currentTimeMillis();
    private boolean appPaused = true;
    private boolean isUpdating;
    private int connectionState;
    private AtomicInteger lastRequestToken = new AtomicInteger(1);
    private int appResumeCount;

    private static AsyncTask currentTask;

    private static HashMap<String, ResolveHostByNameTask> resolvingHostnameTasks = new HashMap<>();

    public static final Executor DNS_THREAD_POOL_EXECUTOR;
    private static final Executor DNS_DIRECT_EXECUTOR = Runnable::run;
    public static final int CPU_COUNT = Runtime.getRuntime().availableProcessors();
    private static final int CORE_POOL_SIZE = Math.max(2, Math.min(CPU_COUNT - 1, 4));
    private static final int MAXIMUM_POOL_SIZE = CPU_COUNT * 2 + 1;
    private static final int KEEP_ALIVE_SECONDS = 30;
    private static final BlockingQueue<Runnable> sPoolWorkQueue = new LinkedBlockingQueue<>(128);
    private static final ThreadFactory sThreadFactory = new ThreadFactory() {
        private final AtomicInteger mCount = new AtomicInteger(1);

        public Thread newThread(Runnable r) {
            return new Thread(r, "DnsAsyncTask #" + mCount.getAndIncrement());
        }
    };

    private boolean forceTryIpV6;

    static {
        ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(CORE_POOL_SIZE, MAXIMUM_POOL_SIZE, KEEP_ALIVE_SECONDS, TimeUnit.SECONDS, sPoolWorkQueue, sThreadFactory);
        threadPoolExecutor.allowCoreThreadTimeOut(true);
        DNS_THREAD_POOL_EXECUTOR = threadPoolExecutor;
    }

    public void setForceTryIpV6(boolean forceTryIpV6) {
        if (this.forceTryIpV6 != forceTryIpV6) {
            this.forceTryIpV6 = forceTryIpV6;
            checkConnection();
        }
    }

    public void discardConnection(int dcId, int connectionType) {
        Utilities.stageQueue.postRunnable(() -> {
            native_discardConnection(currentAccount, dcId, connectionType);
        });
    }

    public void failNotRunningRequest(int requestToken) {
        Utilities.stageQueue.postRunnable(() -> {
            native_failNotRunningRequest(currentAccount, requestToken);
        });
    }

    private static class ResolvedDomain {

        public final List<String> ipv4;
        public final List<String> ipv6;
        final long expiresAtMs;
        final long staleExpiresAtMs;
        final String source;

        public ResolvedDomain(List<String> ipv4Addresses, List<String> ipv6Addresses, long expiresAtMs, long staleExpiresAtMs, String source) {
            ipv4 = ipv4Addresses != null ? ipv4Addresses : new ArrayList<>();
            ipv6 = ipv6Addresses != null ? ipv6Addresses : new ArrayList<>();
            this.expiresAtMs = expiresAtMs;
            this.staleExpiresAtMs = staleExpiresAtMs;
            this.source = source;
        }

        public boolean isFresh(long now) {
            return now <= expiresAtMs && hasAddresses();
        }

        public boolean isStale(long now) {
            return now <= staleExpiresAtMs && hasAddresses();
        }

        public boolean hasAddresses() {
            return !ipv4.isEmpty() || !ipv6.isEmpty();
        }

        public String getAddress() {
            List<String> addresses = !ipv4.isEmpty() ? ipv4 : ipv6;
            return addresses.get(Utilities.random.nextInt(addresses.size()));
        }
    }

    private static HashMap<String, ResolvedDomain> dnsCache = new HashMap<>();

    private static int lastClassGuid = 1;

    private static final ConnectionsManager[] Instance = new ConnectionsManager[UserConfig.MAX_ACCOUNT_COUNT];
    public static ConnectionsManager getInstance(int num) {
        ConnectionsManager localInstance = Instance[num];
        if (localInstance == null) {
            synchronized (ConnectionsManager.class) {
                localInstance = Instance[num];
                if (localInstance == null) {
                    Instance[num] = localInstance = new ConnectionsManager(num);
                }
            }
        }
        return localInstance;
    }

    public ConnectionsManager(int instance) {
        super(instance);
        connectionState = native_getConnectionState(currentAccount);
        String deviceModel;
        String systemLangCode;
        String langCode;
        String appVersion;
        String systemVersion;
        File config = ApplicationLoader.getFilesDirFixed();
        if (instance != 0) {
            config = new File(config, "account" + instance);
            config.mkdirs();
        }
        String configPath = config.toString();
        boolean enablePushConnection = isPushConnectionEnabled();
        try {
            systemLangCode = LocaleController.getSystemLocaleStringIso639().toLowerCase();
            langCode = LocaleController.getLocaleStringIso639().toLowerCase();
            deviceModel = Build.MANUFACTURER + Build.MODEL;
            PackageInfo pInfo = ApplicationLoader.applicationContext.getPackageManager().getPackageInfo(ApplicationLoader.applicationContext.getPackageName(), 0);
            appVersion = pInfo.versionName + " (" + pInfo.versionCode + ")";
            if (BuildVars.DEBUG_PRIVATE_VERSION) {
                appVersion += " pbeta";
            } else if (BuildVars.DEBUG_VERSION) {
                appVersion += " beta";
            }
            systemVersion = "SDK " + Build.VERSION.SDK_INT;
        } catch (Exception e) {
            systemLangCode = "en";
            langCode = "";
            deviceModel = "Android unknown";
            appVersion = "App version unknown";
            systemVersion = "SDK " + Build.VERSION.SDK_INT;
        }
        if (systemLangCode.trim().length() == 0) {
            systemLangCode = "en";
        }
        if (deviceModel.trim().length() == 0) {
            deviceModel = "Android unknown";
        }
        if (appVersion.trim().length() == 0) {
            appVersion = "App version unknown";
        }
        if (systemVersion.trim().length() == 0) {
            systemVersion = "SDK Unknown";
        }
        getUserConfig().loadConfig();
        String pushString = getRegId();
        String fingerprint = AndroidUtilities.getCertificateSHA256Fingerprint();

        int timezoneOffset = (TimeZone.getDefault().getRawOffset() + TimeZone.getDefault().getDSTSavings()) / 1000;
        SharedPreferences mainPreferences;
        if (currentAccount == 0) {
            mainPreferences = ApplicationLoader.applicationContext.getSharedPreferences("mainconfig", Activity.MODE_PRIVATE);
        } else {
            mainPreferences = ApplicationLoader.applicationContext.getSharedPreferences("mainconfig" + currentAccount, Activity.MODE_PRIVATE);
        }
        forceTryIpV6 = mainPreferences.getBoolean("forceTryIpV6", false);
        boolean userPremium = false;
        if (getUserConfig().getCurrentUser() != null) {
            userPremium = getUserConfig().getCurrentUser().premium;
        }
        init(SharedConfig.buildVersion(), TLRPC.LAYER, BuildVars.APP_ID, deviceModel, systemVersion, appVersion, langCode, systemLangCode, configPath, FileLog.getNetworkLogPath(), pushString, fingerprint, timezoneOffset, getUserConfig().getClientUserId(), userPremium, enablePushConnection);
    }

    private String getRegId() {
        String pushString = SharedConfig.pushString;
        if (!TextUtils.isEmpty(pushString) && SharedConfig.pushType == PushListenerController.PUSH_TYPE_HUAWEI) {
            pushString = "huawei://" + pushString;
        }
        if (TextUtils.isEmpty(pushString) && !TextUtils.isEmpty(SharedConfig.pushStringStatus)) {
            pushString = SharedConfig.pushStringStatus;
        }
        if (TextUtils.isEmpty(pushString)) {
            String tag = SharedConfig.pushType == PushListenerController.PUSH_TYPE_FIREBASE ? "FIREBASE" : "HUAWEI";
            pushString = SharedConfig.pushStringStatus = "__" + tag + "_GENERATING_SINCE_" + getCurrentTime() + "__";
        }
        return pushString;
    }

    public boolean isPushConnectionEnabled() {
        SharedPreferences preferences = MessagesController.getGlobalNotificationsSettings();
        if (preferences.contains("pushConnection")) {
            return preferences.getBoolean("pushConnection", true);
        } else {
            return MessagesController.getMainSettings(UserConfig.selectedAccount).getBoolean("backgroundConnection", false);
        }
    }

    public static boolean isBackgroundNetworkAlwaysOn() {
        SharedPreferences preferences = MessagesController.getGlobalNotificationsSettings();
        return preferences.getBoolean(BACKGROUND_NETWORK_ALWAYS_ON, false);
    }

    public long getCurrentTimeMillis() {
        return native_getCurrentTimeMillis(currentAccount);
    }

    public int getCurrentTime() {
        return native_getCurrentTime(currentAccount);
    }

    public int getCurrentDatacenterId() {
        return native_getCurrentDatacenterId(currentAccount);
    }

    public long getCurrentAuthKeyId() {
        return native_getCurrentAuthKeyId(currentAccount);
    }

    public int getTimeDifference() {
        return native_getTimeDifference(currentAccount);
    }

    public <T extends TLObject> int sendRequestTyped(TLMethod<T> method, Utilities.Callback2<T, TLRPC.TL_error> completionBlock) {
        return sendRequestTyped(method, null, completionBlock);
    }
    public <T extends TLObject> int sendRequestTyped(TLMethod<T> method, Executor executor, Utilities.Callback2<T, TLRPC.TL_error> completionBlock) {
        return sendRequestTyped(method, executor, completionBlock, DEFAULT_DATACENTER_ID, 0);
    }
    public <T extends TLObject> int sendRequestTyped(TLMethod<T> method, Executor executor, Utilities.Callback2<T, TLRPC.TL_error> completionBlock, int requestFlags) {
        return sendRequestTyped(method, executor, completionBlock, DEFAULT_DATACENTER_ID, requestFlags);
    }
    public <T extends TLObject> int sendRequestTyped(TLMethod<T> method, Executor executor, Utilities.Callback2<T, TLRPC.TL_error> completionBlock, int dcId, int requestFlags) {
        return sendRequest(method, (res, err) -> {
            //noinspection unchecked
            T result = (T) res;
            if (executor != null) {
                executor.execute(() -> completionBlock.run(result, err));
            } else {
                completionBlock.run(result, err);
            }
        }, null, null, null, requestFlags, dcId, ConnectionTypeGeneric, true);
    }

    public int sendRequest(TLObject object, RequestDelegate completionBlock) {
        return sendRequest(object, completionBlock, null, 0);
    }

    public int sendRequest(TLObject object, RequestDelegate completionBlock, int flags) {
        return sendRequest(object, completionBlock, null, null, null, flags, DEFAULT_DATACENTER_ID, ConnectionTypeGeneric, true);
    }

    public int sendRequest(TLObject object, RequestDelegate completionBlock, int flags, int connectionType) {
        return sendRequest(object, completionBlock, null, null, null, flags, DEFAULT_DATACENTER_ID, connectionType, true);
    }

    public int sendRequest(TLObject object, RequestDelegateTimestamp completionBlock, int flags, int connectionType, int datacenterId) {
        return sendRequest(object, null, completionBlock, null, null, flags, datacenterId, connectionType, true);
    }

    public int sendRequest(TLObject object, RequestDelegate completionBlock, QuickAckDelegate quickAckBlock, int flags) {
        return sendRequest(object, completionBlock, null, quickAckBlock, null, flags, DEFAULT_DATACENTER_ID, ConnectionTypeGeneric, true);
    }

    public int sendRequest(final TLObject object, final RequestDelegate onComplete, final QuickAckDelegate onQuickAck, final WriteToSocketDelegate onWriteToSocket, final int flags, final int datacenterId, final int connectionType, final boolean immediate) {
        return sendRequest(object, onComplete, null, onQuickAck, onWriteToSocket, flags, datacenterId, connectionType, immediate);
    }

    public int sendRequestSync(final TLObject object, final RequestDelegate onComplete, final QuickAckDelegate onQuickAck, final WriteToSocketDelegate onWriteToSocket, final int flags, final int datacenterId, final int connectionType, final boolean immediate) {
        final int requestToken = lastRequestToken.getAndIncrement();
        sendRequestInternal(object, onComplete, null, onQuickAck, onWriteToSocket, flags, datacenterId, connectionType, immediate, requestToken);
        return requestToken;
    }

    public int sendRequest(final TLObject object, final RequestDelegate onComplete, final RequestDelegateTimestamp onCompleteTimestamp, final QuickAckDelegate onQuickAck, final WriteToSocketDelegate onWriteToSocket, final int flags, final int datacenterId, final int connectionType, final boolean immediate) {
        final int requestToken = lastRequestToken.getAndIncrement();
        Utilities.stageQueue.postRunnable(() -> {
            sendRequestInternal(object, onComplete, onCompleteTimestamp, onQuickAck, onWriteToSocket, flags, datacenterId, connectionType, immediate, requestToken);
        });
        return requestToken;
    }

    private void sendRequestInternal(TLObject object, RequestDelegate onComplete, RequestDelegateTimestamp onCompleteTimestamp, QuickAckDelegate onQuickAck, WriteToSocketDelegate onWriteToSocket, int flags, int datacenterId, int connectionType, boolean immediate, int requestToken) {
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("send request " + object + " with token = " + requestToken);
        }
        try {
            NativeByteBuffer buffer = new NativeByteBuffer(object.getObjectSize());
            object.serializeToStream(buffer);
            object.freeResources();

            long startRequestTime = 0;
            if (BuildVars.DEBUG_PRIVATE_VERSION && BuildVars.LOGS_ENABLED || (connectionType & ConnectionTypeDownload) != 0) {
                startRequestTime = System.currentTimeMillis();
            }
            long finalStartRequestTime = startRequestTime;
            listen(requestToken, (response, errorCode, errorText, networkType, timestamp, requestMsgId, dcId) -> {
                try {
                    TLObject resp = null;
                    TLRPC.TL_error error = null;
                    int responseSize = 0;
                    if (response != 0) {
                        NativeByteBuffer buff = NativeByteBuffer.wrap(response);
                        buff.setDataSourceType(TLDataSourceType.NETWORK);
                        buff.reused = true;
                        responseSize = buff.limit();
                        int magic = buff.readInt32(true);
                        try {
                            resp = object.deserializeResponse(buff, magic, true);
                        } catch (Exception e2) {
                            if (BuildVars.DEBUG_PRIVATE_VERSION) {
                                throw e2;
                            }
                            FileLog.fatal(e2);
                            return;
                        }
                    } else if (errorText != null) {
                        error = new TLRPC.TL_error();
                        error.code = errorCode;
                        error.text = errorText;
                        if (BuildVars.LOGS_ENABLED && error.code != -2000) {
                            FileLog.e(object + " got error " + error.code + " " + error.text);
                        }
                    }
                    if ((connectionType & ConnectionTypeDownload) != 0 && VideoPlayer.activePlayers.isEmpty()) {
                        long ping_time = native_getCurrentPingTime(currentAccount);
                        final long size = responseSize;
                        final long delta = Math.max(0, (System.currentTimeMillis() - finalStartRequestTime) - ping_time);
                        DefaultBandwidthMeter.getSingletonInstance(ApplicationLoader.applicationContext).onTransfer(size, delta);
                    }
                    if (BuildVars.DEBUG_PRIVATE_VERSION && !getUserConfig().isClientActivated() && error != null && error.code == 400 && Objects.equals(error.text, "CONNECTION_NOT_INITED")) {
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.d("Cleanup keys for " + currentAccount + " because of CONNECTION_NOT_INITED");
                        }
                        cleanup(true);
                        sendRequest(object, onComplete, onCompleteTimestamp, onQuickAck, onWriteToSocket, flags, datacenterId, connectionType, immediate);
                        return;
                    }
                    if (resp != null) {
                        resp.networkType = networkType;
                    }
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d("java received " + resp + (error != null ? " error = " + error : "") + " messageId = 0x" + Long.toHexString(requestMsgId));
                        FileLog.dumpResponseAndRequest(currentAccount, object, resp, error, requestMsgId, finalStartRequestTime, requestToken);
                    }
                    final TLObject finalResponse = resp;
                    final TLRPC.TL_error finalError = error;
                    Utilities.stageQueue.postRunnable(() -> {
                        if (onComplete != null) {
                            onComplete.run(finalResponse, finalError);
                        } else if (onCompleteTimestamp != null) {
                            onCompleteTimestamp.run(finalResponse, finalError, timestamp);
                        } else if (finalResponse instanceof TLRPC.Updates) {
                            KeepAliveJob.finishJob();
                            AccountInstance.getInstance(currentAccount).getMessagesController().processUpdates((TLRPC.Updates) finalResponse, false);
                        }
                        if (finalResponse != null) {
                            finalResponse.freeResources();
                        }
                    });
                } catch (Exception e) {
                    FileLog.e(e);
                }
            }, onQuickAck, onWriteToSocket);
            native_sendRequest(currentAccount, buffer.address, flags, datacenterId, connectionType, immediate, requestToken);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private final ConcurrentHashMap<Integer, RequestCallbacks> requestCallbacks = new ConcurrentHashMap<>();
    private static class RequestCallbacks {
        public RequestDelegateInternal onComplete;
        public QuickAckDelegate onQuickAck;
        public WriteToSocketDelegate onWriteToSocket;
        public Runnable onCancelled;
        public RequestCallbacks(RequestDelegateInternal onComplete, QuickAckDelegate onQuickAck, WriteToSocketDelegate onWriteToSocket) {
            this.onComplete = onComplete;
            this.onQuickAck = onQuickAck;
            this.onWriteToSocket = onWriteToSocket;
        }
    }

    private void listen(int requestToken, RequestDelegateInternal onComplete, QuickAckDelegate onQuickAck, WriteToSocketDelegate onWriteToSocket) {
        requestCallbacks.put(requestToken, new RequestCallbacks(onComplete, onQuickAck, onWriteToSocket));
//        FileLog.d("{rc} listen(" + currentAccount + ", " + requestToken + "): " + requestCallbacks.size() + " requests' callbacks");
    }

    private void listenCancel(int requestToken, Runnable onCancelled) {
        RequestCallbacks callbacks = requestCallbacks.get(requestToken);
        if (callbacks != null) {
            callbacks.onCancelled = onCancelled;
//            FileLog.d("{rc} listenCancel(" + currentAccount + ", " + requestToken + "): " + requestCallbacks.size() + " requests' callbacks");
        } else {
//            FileLog.d("{rc} listenCancel(" + currentAccount + ", " + requestToken + "): callback not found, " + requestCallbacks.size() + " requests' callbacks");
        }
    }

    public static void onRequestClear(int currentAccount, int requestToken, boolean cancelled) {
        ConnectionsManager connectionsManager = getInstance(currentAccount);
        if (connectionsManager == null) return;
        RequestCallbacks callbacks = connectionsManager.requestCallbacks.get(requestToken);
        if (cancelled) {
            if (callbacks != null) {
                if (callbacks.onCancelled != null) {
                    callbacks.onCancelled.run();
                }
                connectionsManager.requestCallbacks.remove(requestToken);
//                FileLog.d("{rc} onRequestClear(" + currentAccount + ", " + requestToken + ", " + cancelled + "): request to cancel is found " + connectionsManager.requestCallbacks.size() + " requests' callbacks");
            } else {
//                FileLog.d("{rc} onRequestClear(" + currentAccount + ", " + requestToken + ", " + cancelled + "): request to cancel is not found " + connectionsManager.requestCallbacks.size() + " requests' callbacks");
            }
        } else if (callbacks != null) {
            connectionsManager.requestCallbacks.remove(requestToken);
//            FileLog.d("{rc} onRequestClear(" + currentAccount + ", " + requestToken + ", " + cancelled + "): " + connectionsManager.requestCallbacks.size() + " requests' callbacks");
        }
    }

    public static void onRequestComplete(int currentAccount, int requestToken, long response, int errorCode, String errorText, int networkType, long timestamp, long requestMsgId, int dcId) {
        ConnectionsManager connectionsManager = getInstance(currentAccount);
        if (connectionsManager == null) return;
        RequestCallbacks callbacks = connectionsManager.requestCallbacks.get(requestToken);
        connectionsManager.requestCallbacks.remove(requestToken);
        if (callbacks != null) {
            if (callbacks.onComplete != null) {
                callbacks.onComplete.run(response, errorCode, errorText, networkType, timestamp, requestMsgId, dcId);
            }
//            FileLog.d("{rc} onRequestComplete(" + currentAccount + ", " + requestToken + "): found request " + requestToken + ", " + connectionsManager.requestCallbacks.size() + " requests' callbacks");
        } else {
//            FileLog.d("{rc} onRequestComplete(" + currentAccount + ", " + requestToken + "): not found request " + requestToken + "! " + connectionsManager.requestCallbacks.size() + " requests' callbacks");
        }
    }

    public static void onRequestQuickAck(int currentAccount, int requestToken) {
        ConnectionsManager connectionsManager = getInstance(currentAccount);
        if (connectionsManager == null) return;
        RequestCallbacks callbacks = connectionsManager.requestCallbacks.get(requestToken);
        if (callbacks != null) {
            if (callbacks.onQuickAck != null) {
                callbacks.onQuickAck.run();
            }
//            FileLog.d("{rc} onRequestQuickAck(" + currentAccount + ", " + requestToken + "): found request " + requestToken + ", " + connectionsManager.requestCallbacks.size() + " requests' callbacks");
        } else {
//            FileLog.d("{rc} onRequestQuickAck(" + currentAccount + ", " + requestToken + "): not found request " + requestToken + "! " + connectionsManager.requestCallbacks.size() + " requests' callbacks");
        }
    }

    public static void onRequestWriteToSocket(int currentAccount, int requestToken) {
        ConnectionsManager connectionsManager = getInstance(currentAccount);
        if (connectionsManager == null) return;
        RequestCallbacks callbacks = connectionsManager.requestCallbacks.get(requestToken);
        if (callbacks != null) {
            if (callbacks.onWriteToSocket != null) {
                callbacks.onWriteToSocket.run();
            }
//            FileLog.d("{rc} onRequestWriteToSocket(" + currentAccount + ", " + requestToken + "): found request " + requestToken + ", " + connectionsManager.requestCallbacks.size() + " requests' callbacks");
        } else {
//            FileLog.d("{rc} onRequestWriteToSocket(" + currentAccount + ", " + requestToken + "): not found request " + requestToken + "! " + connectionsManager.requestCallbacks.size() + " requests' callbacks");
        }
    }

    public void cancelRequest(int token, boolean notifyServer) {
        cancelRequest(token, notifyServer, null);
    }

    public void cancelRequest(int token, boolean notifyServer, Runnable onCancelled) {
        Utilities.stageQueue.postRunnable(() -> {
            if (onCancelled != null) {
                listenCancel(token, () -> {
                    Utilities.stageQueue.postRunnable(onCancelled);
                });
            }
            native_cancelRequest(currentAccount, token, notifyServer);
        });
    }

    public void cleanup(boolean resetKeys) {
        native_cleanUp(currentAccount, resetKeys);
    }

    public void cancelRequestsForGuid(int guid) {
        Utilities.stageQueue.postRunnable(() -> {
            native_cancelRequestsForGuid(currentAccount, guid);
        });
    }

    public void bindRequestToGuid(int requestToken, int guid) {
        if (guid == 0) {
            return;
        }
        native_bindRequestToGuid(currentAccount, requestToken, guid);
    }

    public void applyDatacenterAddress(int datacenterId, String ipAddress, int port) {
        native_applyDatacenterAddress(currentAccount, datacenterId, ipAddress, port);
    }

    public int getConnectionState() {
        if (connectionState == ConnectionStateConnected && isUpdating) {
            return ConnectionStateUpdating;
        }
        return connectionState;
    }

    public void setUserId(long id) {
        native_setUserId(currentAccount, id);
    }

    public void checkConnection() {
        byte selectedStrategy = getIpStrategy();
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("selected ip strategy " + selectedStrategy);
        }
        native_setIpStrategy(currentAccount, selectedStrategy);
        native_setNetworkAvailable(currentAccount, ApplicationLoader.isNetworkOnline(), ApplicationLoader.getCurrentNetworkType(), ApplicationLoader.isConnectionSlow());
    }

    public void setPushConnectionEnabled(boolean value) {
        native_setPushConnectionEnabled(currentAccount, value);
    }

    public void init(int version, int layer, int apiId, String deviceModel, String systemVersion, String appVersion, String langCode, String systemLangCode, String configPath, String logPath, String regId, String cFingerprint, int timezoneOffset, long userId, boolean userPremium, boolean enablePushConnection) {
        SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("mainconfig", Activity.MODE_PRIVATE);
        String proxyAddress = preferences.getString("proxy_ip", "");
        String proxyUsername = preferences.getString("proxy_user", "");
        String proxyPassword = preferences.getString("proxy_pass", "");
        String proxySecret = preferences.getString("proxy_secret", "");
        int proxyPort = preferences.getInt("proxy_port", 1080);

        if (preferences.getBoolean("proxy_enabled", false) && !TextUtils.isEmpty(proxyAddress)) {
            native_setProxySettings(currentAccount, proxyAddress, proxyPort, proxyUsername, proxyPassword, proxySecret, MtProxyOptions.resolve(proxyAddress, proxyPort, proxySecret));
        }
        setWssTransportSettings();
        String installer = "";
        try {
            Context context = ApplicationLoader.applicationContext;
            if (Build.VERSION.SDK_INT >= 30) {
                InstallSourceInfo installSourceInfo = context.getPackageManager().getInstallSourceInfo(context.getPackageName());
                if (installSourceInfo != null) {
                    installer = installSourceInfo.getInitiatingPackageName();
                    if (installer == null) {
                        installer = installSourceInfo.getInstallingPackageName();
                    }
                }
            } else {
                installer = context.getPackageManager().getInstallerPackageName(context.getPackageName());
            }
        } catch (Throwable ignore) {

        }
        if (installer == null) {
            installer = "";
        }
        String packageId = "";
        try {
            packageId = ApplicationLoader.applicationContext.getPackageName();
        } catch (Throwable ignore) {

        }
        if (packageId == null) {
            packageId = "";
        }

        native_init(currentAccount, version, layer, apiId, deviceModel, systemVersion, appVersion, langCode, systemLangCode, configPath, logPath, regId, cFingerprint, installer, packageId, timezoneOffset, userId, userPremium, enablePushConnection, ApplicationLoader.isNetworkOnline(), ApplicationLoader.getCurrentNetworkType(), SharedConfig.measureDevicePerformanceClass());
        checkConnection();
    }

    public static void setLangCode(String langCode) {
        langCode = langCode.replace('_', '-').toLowerCase();
        for (int a = 0; a < UserConfig.MAX_ACCOUNT_COUNT; a++) {
            native_setLangCode(a, langCode);
        }
    }

    public static void setRegId(String regId, @PushListenerController.PushType int type, String status) {
        String pushString = regId;
        if (!TextUtils.isEmpty(pushString) && type == PushListenerController.PUSH_TYPE_HUAWEI) {
            pushString = "huawei://" + pushString;
        }
        if (TextUtils.isEmpty(pushString) && !TextUtils.isEmpty(status)) {
            pushString = status;
        }
        if (TextUtils.isEmpty(pushString)) {
            String tag = type == PushListenerController.PUSH_TYPE_FIREBASE ? "FIREBASE" : "HUAWEI";
            pushString = SharedConfig.pushStringStatus = "__" + tag + "_GENERATING_SINCE_" + getInstance(0).getCurrentTime() + "__";
        }
        for (int a = 0; a < UserConfig.MAX_ACCOUNT_COUNT; a++) {
            native_setRegId(a, pushString);
        }
    }

    private static boolean isMtProxySoftMuxEnabled() {
        if (!SharedConfig.mtProxySoftMux) {
            return false;
        }
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        return preferences.getBoolean("proxy_enabled", false)
                && !TextUtils.isEmpty(preferences.getString("proxy_ip", ""))
                && !TextUtils.isEmpty(preferences.getString("proxy_secret", ""));
    }

    public static int getMtProxySoftMuxDownloadConnectionType(int requestIndex) {
        if (isMtProxySoftMuxEnabled()) {
            return ConnectionTypeDownload;
        }
        return (requestIndex & 1) == 0 ? ConnectionTypeDownload : ConnectionTypeDownload2;
    }

    public static int getMtProxySoftMuxUploadConnectionType(int requestIndex) {
        if (isMtProxySoftMuxEnabled()) {
            return ConnectionTypeUpload;
        }
        return ConnectionTypeUpload | ((requestIndex % 4) << 16);
    }

    public static void setSystemLangCode(String langCode) {
        langCode = langCode.replace('_', '-').toLowerCase();
        for (int a = 0; a < UserConfig.MAX_ACCOUNT_COUNT; a++) {
            native_setSystemLangCode(a, langCode);
        }
    }

    public void switchBackend(boolean restart) {
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        preferences.edit().remove("language_showed2").commit();
        native_switchBackend(currentAccount, restart);
    }

    public boolean isTestBackend() {
        return native_isTestBackend(currentAccount) != 0;
    }

    public void resumeNetworkMaybe() {
        native_resumeNetwork(currentAccount, true);
    }

    public void updateDcSettings() {
        native_updateDcSettings(currentAccount);
    }

    public void setDefaultDatacenterId(int dcId) {
        native_moveDatacenter(currentAccount, dcId);
    }

    public long getPauseTime() {
        return lastPauseTime;
    }

    public long checkProxy(String address, int port, String username, String password, String secret, RequestTimeDelegate requestTimeDelegate) {
        if (TextUtils.isEmpty(address)) {
            return 0;
        }
        if (address == null) {
            address = "";
        }
        if (username == null) {
            username = "";
        }
        if (password == null) {
            password = "";
        }
        if (secret == null) {
            secret = "";
        }
        return native_checkProxy(currentAccount, address, port, username, password, secret, MtProxyOptions.resolve(address, port, secret), requestTimeDelegate);
    }

    public void cancelProxyCheck(long pingId) {
        if (pingId != 0) {
            native_cancelProxyCheck(currentAccount, pingId);
        }
    }

    public void setAppPaused(final boolean value, final boolean byScreenState) {
        if (!byScreenState) {
            appPaused = value;
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("app paused = " + value);
            }
            if (value) {
                appResumeCount--;
            } else {
                appResumeCount++;
            }
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("app resume count " + appResumeCount);
            }
            if (appResumeCount < 0) {
                appResumeCount = 0;
            }
        }
        if (appResumeCount == 0) {
            applyBackgroundNetworkPolicy();
        } else {
            if (appPaused) {
                return;
            }
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("reset app pause time");
            }
            if (lastPauseTime != 0 && System.currentTimeMillis() - lastPauseTime > 5000) {
                getContactsController().checkContacts();
            }
            lastPauseTime = 0;
            native_resumeNetwork(currentAccount, false);
        }
    }

    public void applyBackgroundNetworkPolicy() {
        if (appResumeCount != 0) {
            return;
        }
        if (isBackgroundNetworkAlwaysOn()) {
            lastPauseTime = 0;
            native_resumeNetwork(currentAccount, false);
            return;
        }
        if (lastPauseTime == 0) {
            lastPauseTime = System.currentTimeMillis();
        }
        native_pauseNetwork(currentAccount);
    }

    public static void applyBackgroundNetworkPolicyForAllAccounts() {
        for (int a = 0; a < UserConfig.MAX_ACCOUNT_COUNT; a++) {
            if (UserConfig.getInstance(a).isClientActivated()) {
                getInstance(a).applyBackgroundNetworkPolicy();
            }
        }
    }

    public static void onUnparsedMessageReceived(long address, final int currentAccount, long messageId) {
        try {
            NativeByteBuffer buff = NativeByteBuffer.wrap(address);
            buff.setDataSourceType(TLDataSourceType.NETWORK);
            buff.reused = true;
            int constructor = buff.readInt32(true);
            final TLObject message = TLClassStore.Instance().TLdeserialize(buff, constructor, true);
            FileLog.dumpUnparsedMessage(message, messageId, currentAccount);
            if (message instanceof TLRPC.Updates) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("java received " + message);
                }
                KeepAliveJob.finishJob();
                Utilities.stageQueue.postRunnable(() -> AccountInstance.getInstance(currentAccount).getMessagesController().processUpdates((TLRPC.Updates) message, false));
            } else {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d(String.format("java_debug_parser_unmapped constructor=0x%x", constructor));
                }
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static void onUpdate(final int currentAccount) {
        Utilities.stageQueue.postRunnable(() -> AccountInstance.getInstance(currentAccount).getMessagesController().updateTimerProc());
    }

    public static void onSessionCreated(final int currentAccount) {
        Utilities.stageQueue.postRunnable(() -> AccountInstance.getInstance(currentAccount).getMessagesController().getDifference());
    }

    public static void onConnectionStateChanged(final int state, final int currentAccount) {
        AndroidUtilities.runOnUIThread(() -> {
            getInstance(currentAccount).connectionState = state;
            AccountInstance.getInstance(currentAccount).getNotificationCenter().postNotificationName(NotificationCenter.didUpdateConnectionState);
        });
    }

    public static void onProxyConnectionStageChanged(final int currentAccount, final String diagnostic, final String endpointKey) {
        AndroidUtilities.runOnUIThread(() -> {
            ProxyConnectionEvent event = ProxyConnectionEvent.nativeStage(currentAccount, diagnostic, endpointKey);
            ProxyRuntimeStateStore.onNativeStage(event);
            String normalizedDiagnostic = event.phase;
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("proxy_connection_stage account=" + currentAccount + " phase=" + normalizedDiagnostic + " endpoint=" + endpointKey);
            }
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxyConnectionStageChanged, normalizedDiagnostic, endpointKey);
            AccountInstance.getInstance(currentAccount).getNotificationCenter().postNotificationName(NotificationCenter.proxyConnectionStageChanged, normalizedDiagnostic, endpointKey);
        });
    }

    public static void onLogout(final int currentAccount) {
        AndroidUtilities.runOnUIThread(() -> {
            AccountInstance accountInstance = AccountInstance.getInstance(currentAccount);
            if (accountInstance.getUserConfig().getClientUserId() != 0) {
                accountInstance.getUserConfig().clearConfig();
                accountInstance.getMessagesController().performLogout(0);
            }
        });
    }

    public static int getInitFlags() {
        int flags = 0;
        EmuDetector detector = EmuDetector.with(ApplicationLoader.applicationContext);
        if (detector.detect()) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("detected emu");
            }
            flags |= 1024;
        }
        return flags;
    }

    public static void onBytesSent(int amount, int networkType, final int currentAccount) {
        try {
            AccountInstance.getInstance(currentAccount).getStatsController().incrementSentBytesCount(networkType, StatsController.TYPE_TOTAL, amount);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static void onRequestNewServerIpAndPort(final int second, final int currentAccount) {
        Utilities.globalQueue.postRunnable(() -> {
            boolean networkOnline = ApplicationLoader.isNetworkOnline();
            Utilities.stageQueue.postRunnable(() -> {
                FileLog.d("13. currentTask == " + currentTask);
                if (currentTask != null || second == 0 && Math.abs(lastDnsRequestTime - System.currentTimeMillis()) < 10000 || !networkOnline) {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d("don't start task, current task = " + currentTask + " next task = " + second + " time diff = " + Math.abs(lastDnsRequestTime - System.currentTimeMillis()) + " network = " + ApplicationLoader.isNetworkOnline());
                    }
                    return;
                }
                lastDnsRequestTime = System.currentTimeMillis();
                if (second == 2) {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d("start mozilla txt task");
                    }
                    MozillaDnsLoadTask task = new MozillaDnsLoadTask(currentAccount);
                    task.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, null, null, null);
                    FileLog.d("9. currentTask = mozilla");
                    currentTask = task;
                } else if (second == 1) {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d("start google txt task");
                    }
                    GoogleDnsLoadTask task = new GoogleDnsLoadTask(currentAccount);
                    task.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, null, null, null);
                    FileLog.d("11. currentTask = dnstxt");
                    currentTask = task;
                } else {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d("start firebase task");
                    }
                    FirebaseTask task = new FirebaseTask(currentAccount);
                    task.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, null, null, null);
                    FileLog.d("12. currentTask = firebase");
                    currentTask = task;
                }
            });
        });
    }

    public static void onProxyError() {
        AndroidUtilities.runOnUIThread(() -> NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.needShowAlert, 3));
    }

    public static void getHostByName(String hostName, long address) {
        AndroidUtilities.runOnUIThread(() -> {
            ResolvedDomain resolvedDomain = dnsCache.get(hostName);
            if (resolvedDomain != null && SystemClock.elapsedRealtime() - resolvedDomain.ttl < 5 * 60 * 1000) {
                native_onHostNameResolved(hostName, address, resolvedDomain.getAddress());
            } else {
                ResolveHostByNameTask task = resolvingHostnameTasks.get(hostName);
                if (task == null) {
                    task = new ResolveHostByNameTask(hostName);
                    task.addAddress(address);
                    resolvingHostnameTasks.put(hostName, task);
                    try {
                        task.executeOnExecutor(DNS_THREAD_POOL_EXECUTOR, null, null, null);
                    } catch (Throwable e) {
                        resolvingHostnameTasks.remove(hostName);
                        FileLog.e(e);
                        native_onHostNameResolved(hostName, address, "");
                        return;
                    }
                } else {
                    task.addAddress(address);
                }
            }
        });
    }

    public static void onBytesReceived(int amount, int networkType, final int currentAccount) {
        try {
            StatsController.getInstance(currentAccount).incrementReceivedBytesCount(networkType, StatsController.TYPE_TOTAL, amount);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static void onUpdateConfig(long address, final int currentAccount) {
        try {
            NativeByteBuffer buff = NativeByteBuffer.wrap(address);
            buff.reused = true;
            final TLRPC.TL_config message = TLRPC.TL_config.TLdeserialize(buff, buff.readInt32(true), true);
            if (message != null) {
                Utilities.stageQueue.postRunnable(() -> AccountInstance.getInstance(currentAccount).getMessagesController().updateConfig(message));
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static void onInternalPushReceived(final int currentAccount) {
        KeepAliveJob.startJob();
    }

    public static void setProxySettings(boolean enabled, String address, int port, String username, String password, String secret) {
        if (address == null) {
            address = "";
        }
        if (username == null) {
            username = "";
        }
        if (password == null) {
            password = "";
        }
        if (secret == null) {
            secret = "";
        }

        MtProxyOptions enabledOptions = enabled && !TextUtils.isEmpty(address) ? MtProxyOptions.resolve(address, port, secret) : MtProxyOptions.disabled();
        for (int a = 0; a < UserConfig.MAX_ACCOUNT_COUNT; a++) {
            if (enabled && !TextUtils.isEmpty(address)) {
                native_setProxySettings(a, address, port, username, password, secret, enabledOptions);
            } else {
                native_setProxySettings(a, "", 1080, "", "", "", MtProxyOptions.disabled());
            }
            AccountInstance accountInstance = AccountInstance.getInstance(a);
            if (accountInstance.getUserConfig().isClientActivated()) {
                accountInstance.getMessagesController().checkPromoInfo(true);
            }
        }
    }

    private static int resolveWssTransportMode() {
        int mode = SharedConfig.normalizeWssTransportMode(SharedConfig.wssTransportMode);
        if (mode == WSS_TRANSPORT_CUSTOM) {
            if (TextUtils.isEmpty(SharedConfig.wssHost)) {
                return WSS_TRANSPORT_OFF;
            }
        }
        return mode;
    }

    private static class WssSocksProxy {
        String host = "";
        int port = 1080;
        String username = "";
        String password = "";
        boolean enabled;
    }

    private static WssSocksProxy resolveWssSocksProxy(int mode) {
        WssSocksProxy proxy = new WssSocksProxy();
        SharedConfig.loadProxyList();
        SharedConfig.ProxyInfo selectedProxy = SharedConfig.currentWssSocksProxy;
        if (mode == WSS_TRANSPORT_OFF || selectedProxy == null) {
            return proxy;
        }
        if (!TextUtils.isEmpty(selectedProxy.secret) || TextUtils.isEmpty(selectedProxy.address)) {
            return proxy;
        }
        int port = selectedProxy.port;
        if (port <= 0 || port > 65535) {
            return proxy;
        }
        proxy.host = selectedProxy.address;
        proxy.port = port;
        proxy.username = selectedProxy.username != null ? selectedProxy.username : "";
        proxy.password = selectedProxy.password != null ? selectedProxy.password : "";
        proxy.enabled = true;
        return proxy;
    }

    public static void setWssTransportSettings() {
        int mode = resolveWssTransportMode();
        String host = SharedConfig.wssHost != null ? SharedConfig.wssHost : "";
        String path = SharedConfig.normalizeWssPath(SharedConfig.wssPath);
        int port = SharedConfig.wssPort > 0 && SharedConfig.wssPort <= 65535 ? SharedConfig.wssPort : 443;
        boolean enabled = mode != WSS_TRANSPORT_OFF;
        WssSocksProxy wssSocksProxy = resolveWssSocksProxy(mode);
        String wssSocksHost = wssSocksProxy.host;
        String wssSocksUsername = wssSocksProxy.username;
        String wssSocksPassword = wssSocksProxy.password;
        for (int a = 0; a < UserConfig.MAX_ACCOUNT_COUNT; a++) {
            native_setWssTransportSettings(a, mode, mode, host, port, path, SharedConfig.wssUseForMiniApps, wssSocksHost, wssSocksProxy.port, wssSocksUsername, wssSocksPassword, wssSocksProxy.enabled, enabled);
        }
    }

    static int resolveMtProxyClientHelloFragmentationMode() {
        return SharedConfig.mtProxyClientHelloFragmentation
                ? MT_PROXY_CLIENT_HELLO_FRAGMENTATION_SOFT
                : MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF;
    }

    static int resolveMtProxyConnectionPatternMode() {
        int mode = SharedConfig.mtProxyConnectionPatternMode;
        if (mode >= MT_PROXY_CONNECTION_PATTERN_OFF && mode <= MT_PROXY_CONNECTION_PATTERN_BROWSER) {
            return mode;
        }
        return MT_PROXY_CONNECTION_PATTERN_OFF;
    }

    static int resolveMtProxyRecordSizingMode() {
        int mode = SharedConfig.mtProxyRecordSizingMode;
        if (mode >= MT_PROXY_RECORD_SIZING_OFF && mode <= MT_PROXY_RECORD_SIZING_VARIED) {
            return mode;
        }
        return MT_PROXY_RECORD_SIZING_OFF;
    }

    static int resolveMtProxyTimingMode() {
        int mode = SharedConfig.mtProxyTimingMode;
        if (mode >= MT_PROXY_TIMING_OFF && mode <= MT_PROXY_TIMING_BALANCED) {
            return mode;
        }
        return MT_PROXY_TIMING_OFF;
    }

    static int resolveMtProxyStartupCoverMode() {
        int mode = SharedConfig.mtProxyStartupCoverMode;
        if (mode >= MT_PROXY_STARTUP_COVER_OFF && mode <= MT_PROXY_STARTUP_COVER_STRICT) {
            return mode;
        }
        return MT_PROXY_STARTUP_COVER_OFF;
    }

    private static int normalizeMtProxyTlsProfileOverride(int profile) {
        if (profile == MT_PROXY_TLS_PROFILE_AUTO) {
            return MT_PROXY_TLS_PROFILE_AUTO;
        }
        if (profile == MT_PROXY_TLS_PROFILE_AUTO_ROTATE) {
            return MT_PROXY_TLS_PROFILE_AUTO_ROTATE;
        }
        if (profile >= MT_PROXY_TLS_PROFILE_FIREFOX && profile <= MT_PROXY_TLS_PROFILE_CHROME_MODERN) {
            return profile;
        }
        return MT_PROXY_TLS_PROFILE_AUTO;
    }

    public static int getMtProxyTlsProfileOverride() {
        SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences(MT_PROXY_TLS_PROFILE_PREFS, Context.MODE_PRIVATE);
        return normalizeMtProxyTlsProfileOverride(preferences.getInt(MT_PROXY_TLS_PROFILE_OVERRIDE, MT_PROXY_TLS_PROFILE_AUTO));
    }

    public static void setMtProxyTlsProfileOverride(int profile) {
        profile = normalizeMtProxyTlsProfileOverride(profile);
        SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences(MT_PROXY_TLS_PROFILE_PREFS, Context.MODE_PRIVATE);
        preferences.edit().putInt(MT_PROXY_TLS_PROFILE_OVERRIDE, profile).apply();
    }

    static int resolveMtProxyTlsProfile(String address, int port, String secret) {
        SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences(MT_PROXY_TLS_PROFILE_PREFS, Context.MODE_PRIVATE);
        int override = getMtProxyTlsProfileOverride();
        if (override != MT_PROXY_TLS_PROFILE_AUTO) {
            return override;
        }

        long salt = preferences.getLong(MT_PROXY_TLS_PROFILE_SALT, 0);
        if (salt == 0) {
            salt = Utilities.random.nextLong();
            if (salt == 0) {
                salt = 1;
            }
            preferences.edit().putLong(MT_PROXY_TLS_PROFILE_SALT, salt).apply();
        }

        long hash = 0xcbf29ce484222325L ^ salt;
        hash = stableMtProxyTlsHash(hash, address);
        hash = stableMtProxyTlsHash(hash, port);
        hash = stableMtProxyTlsHash(hash, secret);

        int bucket = Math.floorMod(hash, MT_PROXY_TLS_PROFILE_RANDOM_COUNT);
        if (bucket == 0) {
            return MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
        }
        return MT_PROXY_TLS_PROFILE_YANDEX;
    }

    private static long stableMtProxyTlsHash(long hash, int value) {
        for (int i = 0; i < 4; i++) {
            hash ^= (value >> (i * 8)) & 0xff;
            hash *= 0x100000001b3L;
        }
        return hash;
    }

    private static long stableMtProxyTlsHash(long hash, String value) {
        if (value == null) {
            return stableMtProxyTlsHash(hash, 0);
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                c = (char) (c + 32);
            }
            hash ^= c & 0xff;
            hash *= 0x100000001b3L;
            hash ^= (c >> 8) & 0xff;
            hash *= 0x100000001b3L;
        }
        return hash;
    }

    public static native void native_switchBackend(int currentAccount, boolean restart);
    public static native int native_isTestBackend(int currentAccount);
    public static native void native_pauseNetwork(int currentAccount);
    public static native void native_setIpStrategy(int currentAccount, byte value);
    public static native void native_updateDcSettings(int currentAccount);
    public static native void native_moveDatacenter(int currentAccount, int datacenterId);
    public static native void native_setNetworkAvailable(int currentAccount, boolean value, int networkType, boolean slow);
    public static native void native_resumeNetwork(int currentAccount, boolean partial);
    public static native long native_getCurrentTimeMillis(int currentAccount);
    public static native int native_getCurrentTime(int currentAccount);
    public static native int native_getCurrentPingTime(int currentAccount);
    public static native int native_getCurrentDatacenterId(int currentAccount);
    public static native long native_getCurrentAuthKeyId(int currentAccount);
    public static native int native_getTimeDifference(int currentAccount);
    public static native void native_sendRequest(int currentAccount, long object, int flags, int datacenterId, int connectionType, boolean immediate, int requestToken);
    public static native void native_cancelRequest(int currentAccount, int token, boolean notifyServer);
    public static native void native_cleanUp(int currentAccount, boolean resetKeys);
    public static native void native_cancelRequestsForGuid(int currentAccount, int guid);
    public static native void native_bindRequestToGuid(int currentAccount, int requestToken, int guid);
    public static native void native_applyDatacenterAddress(int currentAccount, int datacenterId, String ipAddress, int port);
    public static native int native_getConnectionState(int currentAccount);
    public static native void native_setUserId(int currentAccount, long id);
    public static native void native_init(int currentAccount, int version, int layer, int apiId, String deviceModel, String systemVersion, String appVersion, String langCode, String systemLangCode, String configPath, String logPath, String regId, String cFingerprint, String installer, String packageId, int timezoneOffset, long userId, boolean userPremium, boolean enablePushConnection, boolean hasNetwork, int networkType, int performanceClass);
    public static native void native_setProxySettings(int currentAccount, String address, int port, String username, String password, String secret, MtProxyOptions options);
    public static native void native_setWssTransportSettings(int currentAccount, int mode, int gatewayMode, String host, int port, String path, boolean miniApps, String socksHost, int socksPort, String socksUsername, String socksPassword, boolean socksEnabled, boolean enabled);
    public static native void native_setLangCode(int currentAccount, String langCode);
    public static native void native_setRegId(int currentAccount, String regId);
    public static native void native_setSystemLangCode(int currentAccount, String langCode);
    public static native void native_setJava(boolean useJavaByteBuffers);
    public static native void native_setPushConnectionEnabled(int currentAccount, boolean value);
    public static native void native_applyDnsConfig(int currentAccount, long address, String phone, int date);
    public static native long native_checkProxy(int currentAccount, String address, int port, String username, String password, String secret, MtProxyOptions options, RequestTimeDelegate requestTimeDelegate);
    public static native void native_cancelProxyCheck(int currentAccount, long pingId);
    public static native void native_onHostNameResolved(String host, long address, String ip);
    public static native void native_discardConnection(int currentAccount, int datacenterId, int connectionType);
    public static native void native_failNotRunningRequest(int currentAccount, int token);
    public static native void native_receivedIntegrityCheckClassic(int currentAccount, int requestToken, String nonce, String token);
    public static native void native_receivedCaptchaResult(int currentAccount, int[] requestTokens, String token);
    public static native boolean native_isGoodPrime(byte[] prime, int g);


    public static boolean testNativeTlScheme(NativeByteBuffer buffer, INativeTlTest test) {
        return test.test(buffer.address);
    }

    public static native boolean native_test_AuthAuthorization(long object);
    public interface INativeTlTest {
        boolean test(long address);
    }


    public static int generateClassGuid() {
        return lastClassGuid++;
    }

    public void setIsUpdating(final boolean value) {
        AndroidUtilities.runOnUIThread(() -> {
            if (isUpdating == value) {
                return;
            }
            isUpdating = value;
            if (connectionState == ConnectionStateConnected) {
                AccountInstance.getInstance(currentAccount).getNotificationCenter().postNotificationName(NotificationCenter.didUpdateConnectionState);
            }
        });
    }

    @SuppressLint("NewApi")
    protected byte getIpStrategy() {
        if (Build.VERSION.SDK_INT < 19) {
            return USE_IPV4_ONLY;
        }
        if (BuildVars.LOGS_ENABLED) {
            try {
                NetworkInterface networkInterface;
                Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
                while (networkInterfaces.hasMoreElements()) {
                    networkInterface = networkInterfaces.nextElement();
                    if (!networkInterface.isUp() || networkInterface.isLoopback() || networkInterface.getInterfaceAddresses().isEmpty()) {
                        continue;
                    }
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d("valid interface: " + networkInterface);
                    }
                    List<InterfaceAddress> interfaceAddresses = networkInterface.getInterfaceAddresses();
                    for (int a = 0; a < interfaceAddresses.size(); a++) {
                        InterfaceAddress address = interfaceAddresses.get(a);
                        InetAddress inetAddress = address.getAddress();
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.d("address: " + inetAddress.getHostAddress());
                        }
                        if (inetAddress.isLinkLocalAddress() || inetAddress.isLoopbackAddress() || inetAddress.isMulticastAddress()) {
                            continue;
                        }
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.d("address is good");
                        }
                    }
                }
            } catch (Throwable e) {
                FileLog.e(e);
            }
        }
        try {
            NetworkInterface networkInterface;
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            boolean hasIpv4 = false;
            boolean hasIpv6 = false;
            boolean hasStrangeIpv4 = false;
            while (networkInterfaces.hasMoreElements()) {
                networkInterface = networkInterfaces.nextElement();
                if (!networkInterface.isUp() || networkInterface.isLoopback()) {
                    continue;
                }
                List<InterfaceAddress> interfaceAddresses = networkInterface.getInterfaceAddresses();
                for (int a = 0; a < interfaceAddresses.size(); a++) {
                    InterfaceAddress address = interfaceAddresses.get(a);
                    InetAddress inetAddress = address.getAddress();
                    if (inetAddress.isLinkLocalAddress() || inetAddress.isLoopbackAddress() || inetAddress.isMulticastAddress()) {
                        continue;
                    }
                    if (inetAddress instanceof Inet6Address) {
                        hasIpv6 = true;
                    } else if (inetAddress instanceof Inet4Address) {
                        String addrr = inetAddress.getHostAddress();
                        if (!addrr.startsWith("192.0.0.")) {
                            hasIpv4 = true;
                        } else {
                            hasStrangeIpv4 = true;
                        }
                    }
                }
            }
            if (hasIpv6) {
                if (forceTryIpV6) {
                    return USE_IPV6_ONLY;
                }
                if (hasStrangeIpv4) {
                    return USE_IPV4_IPV6_RANDOM;
                }
                if (!hasIpv4) {
                    return USE_IPV6_ONLY;
                }
            }
        } catch (Throwable e) {
            FileLog.e(e);
        }

        return USE_IPV4_ONLY;
    }

    private static DohJsonResponse loadDohJson(String endpoint, String name, String type, String randomPadding, int connectTimeout, int readTimeout, AsyncTask<?, ?, ?> task) throws Exception {
        StringBuilder urlBuilder = new StringBuilder(endpoint);
        urlBuilder.append("?name=").append(name).append("&type=").append(type);
        if (!TextUtils.isEmpty(randomPadding)) {
            urlBuilder.append("&random_padding=").append(randomPadding);
        }
        URLConnection httpConnection = new URL(urlBuilder.toString()).openConnection();
        httpConnection.addRequestProperty("User-Agent", DOH_USER_AGENT);
        httpConnection.addRequestProperty("accept", "application/dns-json");
        httpConnection.setConnectTimeout(connectTimeout);
        httpConnection.setReadTimeout(readTimeout);
        httpConnection.connect();

        ByteArrayOutputStream outbuf = new ByteArrayOutputStream();
        InputStream httpConnectionStream = null;
        try {
            httpConnectionStream = httpConnection.getInputStream();
            byte[] data = new byte[1024 * 32];
            while (true) {
                if (task != null && task.isCancelled()) {
                    break;
                }
                int read = httpConnectionStream.read(data);
                if (read > 0) {
                    outbuf.write(data, 0, read);
                } else if (read == -1) {
                    break;
                } else {
                    break;
                }
            }
            return new DohJsonResponse(outbuf.toByteArray(), (int) (httpConnection.getDate() / 1000));
        } finally {
            try {
                if (httpConnectionStream != null) {
                    httpConnectionStream.close();
                }
            } catch (Throwable e) {
                FileLog.e(e, false);
            }
            try {
                outbuf.close();
            } catch (Exception ignore) {

            }
        }
    }

    private static void logDohExpectedFailure(String source, String host, String endpoint, Throwable e) {
        FileLog.d("dns doh failed source=" + source + " host=" + host + " endpoint=" + endpoint + " reason=" + e.getClass().getSimpleName());
    }

    private static void logHostResolverExpectedFailure(String provider, String host, String reason) {
        FileLog.d("dns host resolver fallback host=" + host + " provider=" + provider + " reason=" + reason);
    }

    private static ArrayList<String> filterIpv4Addresses(List<InetAddress> inetAddresses) {
        ArrayList<String> addresses = new ArrayList<>();
        if (inetAddresses == null) {
            return addresses;
        }
        for (int a = 0, N = inetAddresses.size(); a < N; a++) {
            InetAddress inetAddress = inetAddresses.get(a);
            if (inetAddress instanceof Inet4Address) {
                String hostAddress = inetAddress.getHostAddress();
                if (!TextUtils.isEmpty(hostAddress) && !addresses.contains(hostAddress)) {
                    addresses.add(hostAddress);
                }
            }
        }
        return addresses;
    }

    private static ResolvedDomain resolvedDomainFromIpv4Addresses(ArrayList<String> addresses) {
        if (addresses == null || addresses.isEmpty()) {
            return null;
        }
        return new ResolvedDomain(addresses, SystemClock.elapsedRealtime());
    }

    @SuppressLint("NewApi")
    private static ResolvedDomain tryAndroidDnsResolverA(String hostName) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return null;
        }
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<ArrayList<String>> result = new AtomicReference<>();
        AtomicReference<Throwable> error = new AtomicReference<>();
        CancellationSignal cancellationSignal = new CancellationSignal();
        try {
            DnsResolver.getInstance().query(null, hostName, DnsResolver.TYPE_A, DnsResolver.FLAG_EMPTY, DNS_DIRECT_EXECUTOR, cancellationSignal, new DnsResolver.Callback<List<InetAddress>>() {
                @Override
                public void onAnswer(List<InetAddress> answer, int rcode) {
                    result.set(filterIpv4Addresses(answer));
                    latch.countDown();
                }

                @Override
                public void onError(DnsResolver.DnsException e) {
                    error.set(e);
                    latch.countDown();
                }
            });
            if (!latch.await(HOST_RESOLVER_DNS_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                cancellationSignal.cancel();
                logHostResolverExpectedFailure("android", hostName, "timeout");
                return null;
            }
        } catch (InterruptedException e) {
            cancellationSignal.cancel();
            Thread.currentThread().interrupt();
            logHostResolverExpectedFailure("android", hostName, e.getClass().getSimpleName());
            return null;
        } catch (Throwable e) {
            cancellationSignal.cancel();
            logHostResolverExpectedFailure("android", hostName, e.getClass().getSimpleName());
            return null;
        }
        Throwable resolverError = error.get();
        if (resolverError != null) {
            logHostResolverExpectedFailure("android", hostName, resolverError.getClass().getSimpleName());
            return null;
        }
        ResolvedDomain resolvedDomain = resolvedDomainFromIpv4Addresses(result.get());
        if (resolvedDomain == null) {
            logHostResolverExpectedFailure("android", hostName, "no_ipv4_answer");
        }
        return resolvedDomain;
    }

    private static ResolvedDomain tryInetAddressA(String hostName) {
        try {
            InetAddress[] inetAddresses = InetAddress.getAllByName(hostName);
            ArrayList<String> addresses = new ArrayList<>(inetAddresses.length);
            for (int a = 0; a < inetAddresses.length; a++) {
                InetAddress inetAddress = inetAddresses[a];
                if (inetAddress instanceof Inet4Address) {
                    String hostAddress = inetAddress.getHostAddress();
                    if (!TextUtils.isEmpty(hostAddress) && !addresses.contains(hostAddress)) {
                        addresses.add(hostAddress);
                    }
                }
            }
            ResolvedDomain resolvedDomain = resolvedDomainFromIpv4Addresses(addresses);
            if (resolvedDomain == null) {
                logHostResolverExpectedFailure("inet", hostName, "no_ipv4_answer");
            }
            return resolvedDomain;
        } catch (UnknownHostException e) {
            FileLog.d("dns inet fallback failed host=" + hostName + " reason=" + e.getClass().getSimpleName());
        } catch (Exception e) {
            FileLog.e(e, false);
        }
        return null;
    }

    private static String randomDohPadding() {
        int len = Utilities.random.nextInt(116) + 13;
        final String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder padding = new StringBuilder(len);
        for (int a = 0; a < len; a++) {
            padding.append(characters.charAt(Utilities.random.nextInt(characters.length())));
        }
        return padding.toString();
    }

    private static String dnsConfigDomain(int currentAccount) {
        if (native_isTestBackend(currentAccount) != 0) {
            return "tapv3.stel.com";
        }
        return AccountInstance.getInstance(currentAccount).getMessagesController().dcDomainName;
    }

    private static NativeByteBuffer parseDnsTxtConfig(byte[] bytes) throws Exception {
        JSONObject jsonObject = new JSONObject(new String(bytes));
        JSONArray array = jsonObject.getJSONArray("Answer");
        int len = array.length();
        ArrayList<String> arrayList = new ArrayList<>(len);
        for (int a = 0; a < len; a++) {
            JSONObject object = array.getJSONObject(a);
            int type = object.getInt("type");
            if (type != 16) {
                continue;
            }
            arrayList.add(object.getString("data"));
        }
        Collections.sort(arrayList, (o1, o2) -> {
            int l1 = o1.length();
            int l2 = o2.length();
            if (l1 > l2) {
                return -1;
            } else if (l1 < l2) {
                return 1;
            }
            return 0;
        });
        StringBuilder builder = new StringBuilder();
        for (int a = 0; a < arrayList.size(); a++) {
            builder.append(arrayList.get(a).replace("\"", ""));
        }
        byte[] decodedBytes = Base64.decode(builder.toString(), Base64.DEFAULT);
        NativeByteBuffer buffer = new NativeByteBuffer(decodedBytes.length);
        buffer.writeBytes(decodedBytes);
        return buffer;
    }

    private static class DohJsonResponse {
        final byte[] bytes;
        final int responseDate;

        DohJsonResponse(byte[] bytes, int responseDate) {
            this.bytes = bytes;
            this.responseDate = responseDate;
        }
    }

    private static class ResolveHostByNameTask extends AsyncTask<Void, Void, ResolvedDomain> {

        private ArrayList<Long> addresses = new ArrayList<>();
        private String currentHostName;

        public ResolveHostByNameTask(String hostName) {
            super();
            currentHostName = hostName;
        }

        public void addAddress(long address) {
            if (addresses.contains(address)) {
                return;
            }
            addresses.add(address);
        }

        protected ResolvedDomain doInBackground(Void... voids) {
            ResolvedDomain android = tryAndroidDnsResolverA(currentHostName);
            if (android != null) {
                return android;
            }
            if (isCancelled()) {
                return null;
            }
            return tryInetAddressA(currentHostName);
        }

        @Override
        protected void onPostExecute(final ResolvedDomain result) {
            if (result != null) {
                dnsCache.put(currentHostName, result);
                for (int a = 0, N = addresses.size(); a < N; a++) {
                    native_onHostNameResolved(currentHostName, addresses.get(a), result.getAddress());
                }
            } else {
                for (int a = 0, N = addresses.size(); a < N; a++) {
                    native_onHostNameResolved(currentHostName, addresses.get(a), "");
                }
            }
            resolvingHostnameTasks.remove(currentHostName);
        }
    }

    private static class GoogleDnsLoadTask extends AsyncTask<Void, Void, NativeByteBuffer> {

        private int currentAccount;
        private int responseDate;

        public GoogleDnsLoadTask(int instance) {
            super();
            currentAccount = instance;
        }

        protected NativeByteBuffer doInBackground(Void... voids) {
            String domain = "";
            try {
                domain = dnsConfigDomain(currentAccount);
                DohJsonResponse response = loadDohJson(DOH_GOOGLE_QUERY_ENDPOINT, domain, "ANY", randomDohPadding(), 5000, 5000, this);
                responseDate = response.responseDate;
                return parseDnsTxtConfig(response.bytes);
            } catch (FileNotFoundException | UnknownHostException | SocketTimeoutException | SSLException e) {
                logDohExpectedFailure("google_txt", domain, DOH_GOOGLE_QUERY_ENDPOINT, e);
            } catch (Throwable e) {
                FileLog.e(e, false);
            }
            return null;
        }

        @Override
        protected void onPostExecute(final NativeByteBuffer result) {
            Utilities.stageQueue.postRunnable(() -> {
                FileLog.d("3. currentTask = null, result = " + result);
                currentTask = null;
                if (result != null) {
                    native_applyDnsConfig(currentAccount, result.address, AccountInstance.getInstance(currentAccount).getUserConfig().getClientPhone(), responseDate);
                } else {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d("failed to get google result");
                        FileLog.d("start mozilla task");
                    }
                    MozillaDnsLoadTask task = new MozillaDnsLoadTask(currentAccount);
                    task.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, null, null, null);
                    FileLog.d("4. currentTask = mozilla");
                    currentTask = task;
                }
            });
        }
    }

    private static class MozillaDnsLoadTask extends AsyncTask<Void, Void, NativeByteBuffer> {

        private int currentAccount;
        private int responseDate;

        public MozillaDnsLoadTask(int instance) {
            super();
            currentAccount = instance;
        }

        protected NativeByteBuffer doInBackground(Void... voids) {
            String domain = "";
            try {
                domain = dnsConfigDomain(currentAccount);
                DohJsonResponse response = loadDohJson(DOH_MOZILLA_CLOUDFLARE_QUERY_ENDPOINT, domain, "TXT", randomDohPadding(), 5000, 5000, this);
                responseDate = response.responseDate;
                return parseDnsTxtConfig(response.bytes);
            } catch (FileNotFoundException | UnknownHostException | SocketTimeoutException | SSLException e) {
                logDohExpectedFailure("mozilla_txt", domain, DOH_MOZILLA_CLOUDFLARE_QUERY_ENDPOINT, e);
            } catch (Throwable e) {
                FileLog.e(e, false);
            }
            return null;
        }

        @Override
        protected void onPostExecute(final NativeByteBuffer result) {
            Utilities.stageQueue.postRunnable(() -> {
                FileLog.d("5. currentTask = null");
                currentTask = null;
                if (result != null) {
                    native_applyDnsConfig(currentAccount, result.address, AccountInstance.getInstance(currentAccount).getUserConfig().getClientPhone(), responseDate);
                } else {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d("failed to get mozilla txt result");
                    }
                }
            });
        }
    }

    private static class FirebaseTask extends AsyncTask<Void, Void, NativeByteBuffer> {

        private int currentAccount;
        private FirebaseRemoteConfig firebaseRemoteConfig;

        public FirebaseTask(int instance) {
            super();
            currentAccount = instance;
        }

        protected NativeByteBuffer doInBackground(Void... voids) {
            try {
                if (native_isTestBackend(currentAccount) != 0) {
                    throw new Exception("test backend");
                }
                firebaseRemoteConfig = FirebaseRemoteConfig.getInstance();
                String currentValue = firebaseRemoteConfig.getString("ipconfigv3");
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("current firebase value = " + currentValue);
                }

                firebaseRemoteConfig.fetch(0).addOnCompleteListener(finishedTask -> {
                    final boolean success = finishedTask.isSuccessful();
                    Utilities.stageQueue.postRunnable(() -> {
                        if (success) {
                            firebaseRemoteConfig.activate().addOnCompleteListener(finishedTask2 -> {
                                FileLog.d("6. currentTask = null");
                                currentTask = null;
                                String config = firebaseRemoteConfig.getString("ipconfigv3");
                                if (!TextUtils.isEmpty(config)) {
                                    byte[] bytes = Base64.decode(config, Base64.DEFAULT);
                                    try {
                                        NativeByteBuffer buffer = new NativeByteBuffer(bytes.length);
                                        buffer.writeBytes(bytes);
                                        int date = (int) (firebaseRemoteConfig.getInfo().getFetchTimeMillis() / 1000);
                                        native_applyDnsConfig(currentAccount, buffer.address, AccountInstance.getInstance(currentAccount).getUserConfig().getClientPhone(), date);
                                    } catch (Exception e) {
                                        FileLog.e(e);
                                    }
                                } else {
                                    if (BuildVars.LOGS_ENABLED) {
                                        FileLog.d("failed to get firebase result");
                                        FileLog.d("start dns txt task");
                                    }
                                    GoogleDnsLoadTask task = new GoogleDnsLoadTask(currentAccount);
                                    task.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, null, null, null);
                                    FileLog.d("7. currentTask = GoogleDnsLoadTask");
                                    currentTask = task;
                                }
                            });
                        } else {
                            if (BuildVars.LOGS_ENABLED) {
                                FileLog.d("failed to get firebase result 2");
                                FileLog.d("start dns txt task");
                            }
                            GoogleDnsLoadTask task = new GoogleDnsLoadTask(currentAccount);
                            task.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, null, null, null);
                            FileLog.d("7. currentTask = GoogleDnsLoadTask");
                            currentTask = task;
                        }
                    });
                });
            } catch (Throwable e) {
                Utilities.stageQueue.postRunnable(() -> {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d("failed to get firebase result");
                        FileLog.d("start dns txt task");
                    }
                    GoogleDnsLoadTask task = new GoogleDnsLoadTask(currentAccount);
                    task.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, null, null, null);
                    FileLog.d("8. currentTask = GoogleDnsLoadTask");
                    currentTask = task;
                });
                FileLog.e(e, false);
            }
            return null;
        }

        @Override
        protected void onPostExecute(NativeByteBuffer result) {

        }
    }

    public static long lastPremiumFloodWaitShown = 0;
    @Keep
    public static void onPremiumFloodWait(final int currentAccount, final int requestToken, boolean isUpload) {
        AndroidUtilities.runOnUIThread(() -> {
            if (UserConfig.selectedAccount != currentAccount) {
                return;
            }
            AndroidUtilities.runOnUIThread(() -> {
                boolean updated = false;
                if (isUpload) {
                    FileUploadOperation operation = FileLoader.getInstance(currentAccount).findUploadOperationByRequestToken(requestToken);
                    if (operation != null) {
                        updated = !operation.caughtPremiumFloodWait;
                        operation.caughtPremiumFloodWait = true;
                    }
                } else {
                    FileLoadOperation operation = FileLoader.getInstance(currentAccount).findLoadOperationByRequestToken(requestToken);
                    if (operation != null) {
                        updated = !operation.caughtPremiumFloodWait;
                        operation.caughtPremiumFloodWait = true;
                    }
                }
                final boolean finalUpdated = updated;
                if (finalUpdated) {
                    NotificationCenter.getInstance(currentAccount).postNotificationName(NotificationCenter.premiumFloodWaitReceived);
                }
            });
        });
    }

    @Keep
    public static void onIntegrityCheckClassic(final int currentAccount, final int requestToken, final String project, final String nonce) {
        AndroidUtilities.runOnUIThread(() -> {
            long start = System.currentTimeMillis();
            FileLog.d("account"+currentAccount+": server requests integrity classic check with project = "+project+" nonce = " + nonce);
            IntegrityManager integrityManager = IntegrityManagerFactory.create(ApplicationLoader.applicationContext);
            final long project_id;
            try {
                project_id = Long.parseLong(project);
            } catch (Exception e) {
                FileLog.d("account"+currentAccount+": integrity check failes to parse project id");
                native_receivedIntegrityCheckClassic(currentAccount, requestToken, nonce, "PLAYINTEGRITY_FAILED_EXCEPTION_NOPROJECT");
                return;
            }
            Task<IntegrityTokenResponse> integrityTokenResponse = integrityManager.requestIntegrityToken(IntegrityTokenRequest.builder().setNonce(nonce).setCloudProjectNumber(project_id).build());
            integrityTokenResponse
                .addOnSuccessListener(r -> {
                    final String token = r.token();

                    if (token == null) {
                        FileLog.e("account"+currentAccount+": integrity check gave null token in " + (System.currentTimeMillis() - start) + "ms");
                        native_receivedIntegrityCheckClassic(currentAccount, requestToken, nonce, "PLAYINTEGRITY_FAILED_EXCEPTION_NULL");
                        return;
                    }

                    FileLog.d("account"+currentAccount+": integrity check successfully gave token: " + token + " in " + (System.currentTimeMillis() - start) + "ms");
                    try {
                        native_receivedIntegrityCheckClassic(currentAccount, requestToken, nonce, token);
                    } catch (Exception e) {
                        FileLog.e("receivedIntegrityCheckClassic failed", e);
                    }
                })
                .addOnFailureListener(e -> {
                    FileLog.e("account"+currentAccount+": integrity check failed to give a token in " + (System.currentTimeMillis() - start) + "ms", e);
                    native_receivedIntegrityCheckClassic(currentAccount, requestToken, nonce, "PLAYINTEGRITY_FAILED_EXCEPTION_" + LoginActivity.errorString(e));
                });
        });
    }

    @Keep
    public static void onCaptchaCheck(final int currentAccount, final int requestToken, final String action, final String key_id) {
        CaptchaController.request(currentAccount, requestToken, action, key_id);
    }
}
