#pragma once

#include <QtWidgets/QMainWindow>
#include <QSystemTrayIcon>
#include <QIcon>
#include <QSettings>
#include "ui_Drcom.h"
#include "DrcomClient.h"

class QCloseEvent;
class QEvent;
class QTimer;

// 吉林大学校园网 Dr.COM 认证客户端主窗口
class Drcom : public QMainWindow
{
    Q_OBJECT

public:
    Drcom(QWidget *parent = nullptr);
    ~Drcom() override;

protected:
    void closeEvent(QCloseEvent *event) override;
    void changeEvent(QEvent *event) override;

private slots:
    void onLoginClicked();
    void onLogoutClicked();
    void onSettingsClicked();
    void onRefreshMacClicked();
    void onNavClicked();
    void onWindowClicked();
    void onReconnectTick();
    void onAwakeTick();
    void onClientLoginStarted();
    void onClientLoginSucceeded(const QString &ip);
    void onClientLoginFailed(int code, const QString &message);
    void onClientLoggedOut();
    void onClientConnectionLost();
    void onTrayActivated(QSystemTrayIcon::ActivationReason reason);

private:
    enum UiState { StateOffline, StateLoggingIn, StateOnline };

    bool attemptLogin(bool silent, bool fromReconnect = false);
    void tryAutoConnect();
    void handleDropped();          // 意外掉线 -> 启动自动重连
    void scheduleReconnect();      // 按退避间隔安排一次重连
    void cancelReconnect();
    bool hasSavedCredentials() const;
    void loadSettings();
    void saveCredentials();
    void saveCheckStates();
    void detectMac();
    DrcomConfig buildConfig() const;
    void setUiState(UiState state);
    void setStatusDot(const QString &color);
    void setStatusText(const QString &text);
    void setIpText(const QString &ip);
    void showTrayMessage(const QString &title, const QString &msg,
                         QSystemTrayIcon::MessageIcon icon = QSystemTrayIcon::Information);
    void setKeepAwakeState();      // 应用/清除系统保持唤醒（三模式：无限/时长/直到）
    void updateAwakeModeControls();// 按模式显示/启用对应输入控件
    void updateAwakeHint();        // 刷新剩余时间/目标时刻提示
    void setAutoStart(bool on);    // 开机自启：计划任务（快）优先，失败回退 Run 键
    bool taskExists();             // 「登录时触发」计划任务是否已存在
    bool runKeyExists();           // HKCU\Run 启动项是否已存在
    bool createTask();             // 创建登录触发计划任务（XML 导入）
    static QString currentUserSid();// 当前用户 SID（写入任务 XML）
    void applyTheme();             // 按配置/系统主题加载浅色或深色样式表
    static bool isSystemDarkMode();// Windows 系统主题是否为深色
    static QIcon makeAppIcon();

    Ui::DrcomClass ui;
    QSettings m_settings;
    DrcomClient *m_client = nullptr;
    QSystemTrayIcon *m_tray = nullptr;
    QAction *m_actLogin = nullptr;
    QAction *m_actLogout = nullptr;
    UiState m_state = StateOffline;
    QString m_onlineIp;
    bool m_closing = false;

    // ---- 自动重连（心跳掉线后触发） ----
    QTimer *m_reconnectTimer = nullptr;    // 自动重连定时器（退避）
    bool m_reconnectArmed = false;         // 是否处于自动重连流程
    int m_reconnectDelay = 5;              // 当前重连退避间隔（秒）

    // ---- 保持唤醒（Awake 式三模式） ----
    QTimer *m_awakeTimer = nullptr;        // 1 秒倒计时（时长/直到模式）
    QDateTime m_awakeEnd;                  // 结束时刻（时长/直到模式）

    // ---- 托盘唤醒控制 ----
    QAction *m_actAwakeToggle = nullptr;   // 托盘「保持唤醒」开关
    QAction *m_actAwakeMode[3] = {};       // 托盘「唤醒模式」三个选项
};
