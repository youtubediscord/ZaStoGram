package org.telegram.ui.Plugins;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;

import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.FileLog;
import org.telegram.messenger.NotificationCenter;
import org.telegram.messenger.R;
import org.telegram.messenger.Utilities;
import org.telegram.plugins.PluginInfo;
import org.telegram.plugins.PluginsController;
import org.telegram.ui.ActionBar.ActionBar;
import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.ActionBar.Theme;
import org.telegram.ui.Cells.HeaderCell;
import org.telegram.ui.Cells.TextCell;
import org.telegram.ui.Cells.TextInfoPrivacyCell;
import org.telegram.ui.Components.BulletinFactory;
import org.telegram.ui.Components.LayoutHelper;
import org.telegram.ui.Components.RecyclerListView;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Lists installed Python plugins. Tap a plugin to open its screen (enable toggle + settings +
 * delete); use the action-bar "+" to install a .plugin file from storage.
 */
public class PluginsActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {

    private static final int MENU_ADD = 1;
    private static final int REQUEST_PICK = 49321;

    private static final int VIEW_TYPE_HEADER = 0;
    private static final int VIEW_TYPE_PLUGIN = 1;
    private static final int VIEW_TYPE_INFO = 2;

    private RecyclerListView listView;
    private ListAdapter adapter;
    private List<PluginInfo> plugins = new ArrayList<>();

    private int headerRow;
    private int pluginsStartRow;
    private int pluginsEndRow;
    private int infoRow;
    private int rowCount;

    @Override
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.pluginsDidLoad);
        updateRows();
        return true;
    }

    @Override
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.pluginsDidLoad);
    }

    private void updateRows() {
        plugins = PluginsController.getInstance().getPlugins();
        rowCount = 0;
        headerRow = rowCount++;
        if (plugins.isEmpty()) {
            pluginsStartRow = pluginsEndRow = -1;
        } else {
            pluginsStartRow = rowCount;
            rowCount += plugins.size();
            pluginsEndRow = rowCount;
        }
        infoRow = rowCount++;
    }

    @Override
    public View createView(Context context) {
        actionBar.setBackButtonImage(R.drawable.ic_ab_back);
        actionBar.setAllowOverlayTitle(true);
        actionBar.setTitle("Плагины");
        actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() {
            @Override
            public void onItemClick(int id) {
                if (id == -1) {
                    finishFragment();
                } else if (id == MENU_ADD) {
                    pickPluginFile();
                }
            }
        });
        actionBar.createMenu().addItem(MENU_ADD, R.drawable.msg_add);

        FrameLayout frameLayout = new FrameLayout(context);
        fragmentView = frameLayout;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));

        listView = new RecyclerListView(context);
        listView.setVerticalScrollBarEnabled(false);
        listView.setLayoutManager(new LinearLayoutManager(context, LinearLayoutManager.VERTICAL, false));
        listView.setAdapter(adapter = new ListAdapter(context));
        frameLayout.addView(listView, LayoutHelper.createFrame(LayoutHelper.MATCH_PARENT, LayoutHelper.MATCH_PARENT));

        listView.setOnItemClickListener((view, position) -> {
            if (position >= pluginsStartRow && position < pluginsEndRow) {
                PluginInfo info = plugins.get(position - pluginsStartRow);
                presentFragment(new PluginSettingsActivity(info.id));
            }
        });

        return fragmentView;
    }

    private void pickPluginFile() {
        if (getParentActivity() == null) {
            return;
        }
        try {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("*/*");
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            getParentActivity().startActivityForResult(
                    Intent.createChooser(intent, "Выберите .plugin файл"), REQUEST_PICK);
        } catch (Throwable t) {
            FileLog.e(t);
            BulletinFactory.of(this).createErrorBulletin("Не удалось открыть выбор файла").show();
        }
    }

    @Override
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_PICK && resultCode == Activity.RESULT_OK
                && data != null && data.getData() != null) {
            importUri(data.getData());
        }
    }

    private void importUri(Uri uri) {
        Utilities.globalQueue.postRunnable(() -> {
            PluginInfo info = null;
            try (InputStream in = ApplicationLoader.applicationContext.getContentResolver().openInputStream(uri)) {
                if (in != null) {
                    info = PluginsController.getInstance().installFromStream(in);
                }
            } catch (Throwable t) {
                FileLog.e(t);
            }
            final PluginInfo result = info;
            AndroidUtilities.runOnUIThread(() -> {
                if (result == null) {
                    BulletinFactory.of(this).createErrorBulletin("Это не похоже на корректный .plugin файл").show();
                } else {
                    updateRows();
                    if (adapter != null) {
                        adapter.notifyDataSetChanged();
                    }
                    BulletinFactory.of(this).createSuccessBulletin("Плагин «" + result.displayName() + "» установлен").show();
                }
            });
        });
    }

    @Override
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.pluginsDidLoad) {
            updateRows();
            if (adapter != null) {
                adapter.notifyDataSetChanged();
            }
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {

        private final Context mContext;

        ListAdapter(Context context) {
            mContext = context;
        }

        @Override
        public int getItemCount() {
            return rowCount;
        }

        @Override
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getItemViewType() == VIEW_TYPE_PLUGIN;
        }

        @Override
        public int getItemViewType(int position) {
            if (position == headerRow) {
                return VIEW_TYPE_HEADER;
            } else if (position == infoRow) {
                return VIEW_TYPE_INFO;
            }
            return VIEW_TYPE_PLUGIN;
        }

        @Override
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == VIEW_TYPE_HEADER) {
                view = new HeaderCell(mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == VIEW_TYPE_INFO) {
                view = new TextInfoPrivacyCell(mContext);
            } else {
                view = new TextCell(mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            }
            view.setLayoutParams(new RecyclerView.LayoutParams(
                    RecyclerView.LayoutParams.MATCH_PARENT, RecyclerView.LayoutParams.WRAP_CONTENT));
            return new RecyclerListView.Holder(view);
        }

        @Override
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            switch (getItemViewType(position)) {
                case VIEW_TYPE_HEADER:
                    ((HeaderCell) holder.itemView).setText("Установленные плагины");
                    break;
                case VIEW_TYPE_INFO:
                    String hint = plugins.isEmpty()
                            ? "Плагинов пока нет. Нажмите + и выберите .plugin файл (Python, совместим с exteraGram)."
                            : "Нажмите на плагин, чтобы включить/выключить его, открыть настройки или удалить.";
                    ((TextInfoPrivacyCell) holder.itemView).setText(hint);
                    break;
                default:
                    TextCell cell = (TextCell) holder.itemView;
                    PluginInfo info = plugins.get(position - pluginsStartRow);
                    boolean dividerBelow = (position - pluginsStartRow) < plugins.size() - 1;
                    String status;
                    if (info.error != null) {
                        status = "ошибка";
                    } else if (!info.enabled) {
                        status = "выкл";
                    } else {
                        status = info.version != null ? "v" + info.version : "вкл";
                    }
                    cell.setTextAndValue(info.displayName(), status, dividerBelow);
                    int textKey = info.enabled
                            ? Theme.key_windowBackgroundWhiteBlackText
                            : Theme.key_windowBackgroundWhiteGrayText;
                    cell.setColors(Theme.key_windowBackgroundWhiteGrayIcon, textKey);
                    break;
            }
        }
    }
}
