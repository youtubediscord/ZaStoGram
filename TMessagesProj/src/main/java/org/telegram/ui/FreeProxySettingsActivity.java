package org.telegram.ui;

import android.content.Context;
import android.view.View;
import android.widget.FrameLayout;

import org.telegram.messenger.LocaleController;
import org.telegram.messenger.R;
import org.telegram.messenger.SharedConfig;
import org.telegram.messenger.browser.Browser;
import org.telegram.ui.ActionBar.ActionBar;
import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.ActionBar.Theme;
import org.telegram.ui.Components.IconBackgroundColors;
import org.telegram.ui.Components.LayoutHelper;
import org.telegram.ui.Components.UItem;
import org.telegram.ui.Components.UniversalAdapter;
import org.telegram.ui.Components.UniversalRecyclerView;

import java.util.ArrayList;

/**
 * ZaStoGram: the free-proxy catalog, moved out of the cluttered main Settings list into its own
 * screen (opened from a single "Бесплатные прокси" row), mirroring the ZaSto privacy screen.
 * Reuses {@link SettingsActivity.SettingCell} so the rows look exactly as before.
 */
public class FreeProxySettingsActivity extends BaseFragment {

    private UniversalRecyclerView listView;

    @Override
    public View createView(Context context) {
        actionBar.setBackButtonImage(R.drawable.ic_ab_back);
        actionBar.setAllowOverlayTitle(true);
        actionBar.setTitle(LocaleController.getString(R.string.FreeProxyChannels));
        actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() {
            @Override
            public void onItemClick(int id) {
                if (id == -1) {
                    finishFragment();
                }
            }
        });

        FrameLayout frameLayout = new FrameLayout(context);
        fragmentView = frameLayout;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));

        listView = new UniversalRecyclerView(this, this::fillItems, this::onClick, this::onLongClick);
        listView.adapter.setApplyBackground(false);
        listView.setSections();
        frameLayout.addView(listView, LayoutHelper.createFrame(LayoutHelper.MATCH_PARENT, LayoutHelper.MATCH_PARENT));

        return fragmentView;
    }

    private void fillItems(ArrayList<UItem> items, UniversalAdapter adapter) {
        // Quick access to the real proxy settings (toggle a dead proxy without leaving this screen).
        items.add(SettingsActivity.SettingCell.Factory.of(1002, IconBackgroundColors.BLUE.top, IconBackgroundColors.BLUE.bottom, R.drawable.settings_data, LocaleController.getString(R.string.ProxySettings), null));
        items.add(SettingsActivity.SettingCell.Factory.of(27, IconBackgroundColors.GREEN.top, IconBackgroundColors.GREEN.bottom, R.drawable.settings_privacy, LocaleController.getString(R.string.ZapretVpnSponsorSetting), null, LocaleController.getString(SharedConfig.showZapretVpnSponsor ? R.string.ZapretProxySponsorOn : R.string.ZapretProxySponsorOff)));
        items.add(UItem.asShadow(null));
        items.add(UItem.asHeader(LocaleController.getString(R.string.FreeProxyChannels)));
        items.add(SettingsActivity.SettingCell.Factory.of(28, IconBackgroundColors.BLUE.top, IconBackgroundColors.BLUE.bottom, R.drawable.settings_channel, LocaleController.getString(R.string.FreeProxyMtProxyEveryday)));
        items.add(SettingsActivity.SettingCell.Factory.of(29, IconBackgroundColors.BLUE_LIGHT.top, IconBackgroundColors.BLUE_LIGHT.bottom, R.drawable.settings_channel, LocaleController.getString(R.string.FreeProxyProxyMtProto)));
        items.add(SettingsActivity.SettingCell.Factory.of(30, IconBackgroundColors.CYAN.top, IconBackgroundColors.CYAN.bottom, R.drawable.settings_channel, LocaleController.getString(R.string.FreeProxyProxyFreeRu)));
        items.add(SettingsActivity.SettingCell.Factory.of(31, IconBackgroundColors.PURPLE.top, IconBackgroundColors.PURPLE.bottom, R.drawable.settings_channel, LocaleController.getString(R.string.FreeProxyTgMtProxyLol)));
        items.add(SettingsActivity.SettingCell.Factory.of(32, IconBackgroundColors.ORANGE.top, IconBackgroundColors.ORANGE.bottom, R.drawable.settings_channel, LocaleController.getString(R.string.FreeProxyMemtproxy)));
        items.add(SettingsActivity.SettingCell.Factory.of(33, IconBackgroundColors.ORANGE_DEEP.top, IconBackgroundColors.ORANGE_DEEP.bottom, R.drawable.settings_channel, LocaleController.getString(R.string.FreeProxyTProxyRu)));
        items.add(SettingsActivity.SettingCell.Factory.of(34, IconBackgroundColors.BLUE_ALT.top, IconBackgroundColors.BLUE_ALT.bottom, R.drawable.settings_channel, LocaleController.getString(R.string.FreeProxyProxyFreeMTProto)));
        items.add(SettingsActivity.SettingCell.Factory.of(35, IconBackgroundColors.GREEN.top, IconBackgroundColors.GREEN.bottom, R.drawable.settings_channel, LocaleController.getString(R.string.FreeProxyTelMTProto)));
        items.add(UItem.asShadow(null));
    }

    private void onClick(UItem item, View view, int position, float x, float y) {
        switch (item.id) {
            case 1002:
                presentFragment(new ProxyListActivity());
                break;
            case 27:
                SharedConfig.showZapretVpnSponsor = !SharedConfig.showZapretVpnSponsor;
                SharedConfig.saveConfig();
                listView.adapter.update(true);
                break;
            case 28:
                Browser.openUrl(getParentActivity(), "https://t.me/MTProxy_everyday");
                break;
            case 29:
                Browser.openUrl(getParentActivity(), "https://t.me/ProxyMTProto");
                break;
            case 30:
                Browser.openUrl(getParentActivity(), "https://t.me/ProxyFree_Ru");
                break;
            case 31:
                Browser.openUrl(getParentActivity(), "https://t.me/tgmtproxylol");
                break;
            case 32:
                Browser.openUrl(getParentActivity(), "https://t.me/memtproxy");
                break;
            case 33:
                Browser.openUrl(getParentActivity(), "https://t.me/TProxyRU");
                break;
            case 34:
                Browser.openUrl(getParentActivity(), "https://t.me/ProxyFreeMTProto");
                break;
            case 35:
                Browser.openUrl(getParentActivity(), "https://t.me/TelMTProto");
                break;
        }
    }

    private boolean onLongClick(UItem item, View view, int position, float x, float y) {
        return false;
    }
}
