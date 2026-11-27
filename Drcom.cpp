#include "Drcom.h"
#include "NavDialog.h"

#include <QMessageBox>
#include <QCloseEvent>
#include <QEvent>
#include <QMenu>
#include <QActionGroup>
#include <QTimer>
#include <QDialog>
#include <QFormLayout>
#include <QDialogButtonBox>
#include <QSpinBox>
#include <QNetworkInterface>
#include <QPainter>
#include <QPainterPath>
#include <QPixmap>
#include <QFont>
#include <QApplication>
#include <QRegularExpression>
#include <QSysInfo>
#include <QVBoxLayout>
#include <QDesktopServices>
#include <QUrl>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QCoreApplication>
#include <QDateTime>
#include <QProcess>

#ifdef Q_OS_WIN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#include <objbase.h>
#include <shobjidl.h>
#include <sddl.h>
#include <string>
#include <vector>
#pragma comment(lib, "advapi32.lib")
#endif

namespace {

// 默认认证服务器参数（吉大校园网）
constexpr const char *kDefaultServer = "10.100.61.3";
constexpr int kDefaultPort = 61440;

QString normalizeMac(const QString &raw)
{
    QString s = raw.trimmed().toLower();
    s.remove(QRegularExpression(QStringLiteral("[:\\- ]")));
    return s;
}

bool isValidMac(const QString &mac)
{
    if (mac.size() != 12)
        return false;
    for (const QChar &c : mac) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

} // namespace

Drcom::Drcom(QWidget *parent)
    : QMainWindow(parent)
    , m_settings(QSettings::IniFormat, QSettings::UserScope,
                 QStringLiteral("JLU"), QStringLiteral("DrcomJLU"))
{
    ui.setupUi(this);
    setWindowIcon(makeAppIcon());

    // ---- 后台认证客户端 ----
    m_client = new DrcomClient(this);
    connect(m_client, &DrcomClient::loginStarted,    this, &Drcom::onClientLoginStarted);
    connect(m_client, &DrcomClient::loginSucceeded,  this, &Drcom::onClientLoginSucceeded);
    connect(m_client, &DrcomClient::loginFailed,     this, &Drcom::onClientLoginFailed);
    connect(m_client, &DrcomClient::loggedOut,       this, &Drcom::onClientLoggedOut);
    connect(m_client, &DrcomClient::connectionLost,  this, &Drcom::onClientConnectionLost);

    // ---- 按钮与输入 ----
    connect(ui.btnLogin,       &QPushButton::clicked, this, &Drcom::onLoginClicked);
    connect(ui.btnLogout,      &QPushButton::clicked, this, &Drcom::onLogoutClicked);
    connect(ui.btnSettings,    &QPushButton::clicked, this, &Drcom::onSettingsClicked);
    connect(ui.btnRefreshMac,  &QPushButton::clicked, this, &Drcom::onRefreshMacClicked);
    connect(ui.btnNav,         &QPushButton::clicked, this, &Drcom::onNavClicked);
    connect(ui.btnWindow,      &QPushButton::clicked, this, &Drcom::onWindowClicked);
    connect(ui.editPassword,   &QLineEdit::returnPressed, this, &Drcom::onLoginClicked);
    connect(ui.chkAuto, &QCheckBox::toggled, this, [this](bool on) {
        if (on)
            ui.chkRemember->setChecked(true);
    });
    connect(ui.chkRemember, &QCheckBox::toggled, this, [this](bool on) {
        if (!on)
            ui.chkAuto->setChecked(false);
    });
    connect(ui.chkReconnect, &QCheckBox::toggled, this, [this](bool on) {
        if (!on)
            cancelReconnect();
    });

    // ---- 保持唤醒 / 屏幕常亮 / 开机自启 ----
    connect(ui.chkAwake, &QCheckBox::toggled, this, [this](bool on) {
        if (!on)
            ui.chkAwakeDisplay->setChecked(false);
        updateAwakeModeControls();
        setKeepAwakeState();
        saveCheckStates();
        if (m_actAwakeToggle)
            m_actAwakeToggle->setChecked(on);   // 同步托盘开关
    });
    connect(ui.chkAwakeDisplay, &QCheckBox::toggled, this, [this](bool on) {
        if (on)
            ui.chkAwake->setChecked(true);
        setKeepAwakeState();
        saveCheckStates();
    });
    connect(ui.comboAwakeMode, &QComboBox::currentIndexChanged, this, [this](int) {
        updateAwakeModeControls();
        setKeepAwakeState();
        saveCheckStates();
        for (int i = 0; i < 3; ++i)             // 同步托盘模式选项
            if (m_actAwakeMode[i])
                m_actAwakeMode[i]->setChecked(ui.comboAwakeMode->currentIndex() == i);
    });
    connect(ui.spinAwakeMinutes, &QSpinBox::valueChanged, this, [this](int) {
        if (ui.chkAwake->isChecked() && ui.comboAwakeMode->currentIndex() == 1)
            setKeepAwakeState();
        saveCheckStates();
    });
    connect(ui.timeAwakeUntil, &QTimeEdit::timeChanged, this, [this](const QTime &) {
        if (ui.chkAwake->isChecked() && ui.comboAwakeMode->currentIndex() == 2)
            setKeepAwakeState();
        saveCheckStates();
    });
    connect(ui.chkAutoStart, &QCheckBox::toggled, this, [this](bool on) {
        setAutoStart(on);
        saveCheckStates();
    });

    // ---- 自动重连定时器（心跳掉线后触发，退避重连） ----
    m_reconnectTimer = new QTimer(this);
    m_reconnectTimer->setSingleShot(true);
    connect(m_reconnectTimer, &QTimer::timeout, this, &Drcom::onReconnectTick);

    // ---- 保持唤醒倒计时定时器（时长/直到时刻模式） ----
    m_awakeTimer = new QTimer(this);
    m_awakeTimer->setInterval(1000);
    connect(m_awakeTimer, &QTimer::timeout, this, &Drcom::onAwakeTick);

    // ---- 系统托盘 ----
    m_tray = new QSystemTrayIcon(makeAppIcon(), this);
    m_tray->setToolTip(QStringLiteral("吉林大学校园网认证客户端 · 未连接"));
    QMenu *trayMenu = new QMenu(this);
    QAction *actShow   = trayMenu->addAction(QStringLiteral("显示主界面"));
    QAction *actLogin  = trayMenu->addAction(QStringLiteral("立即登录"));
    QAction *actLogout = trayMenu->addAction(QStringLiteral("注销下线"));
    // ---- 托盘唤醒控制（独立于登录状态，随时可用） ----
    trayMenu->addSeparator();
    m_actAwakeToggle = trayMenu->addAction(QStringLiteral("保持唤醒"));
    m_actAwakeToggle->setCheckable(true);
    m_actAwakeToggle->setChecked(ui.chkAwake->isChecked());
    connect(m_actAwakeToggle, &QAction::toggled, this, [this](bool on) {
        ui.chkAwake->setChecked(on);   // 统一走主界面入口，避免两套状态
    });
    QMenu *awakeModeMenu = new QMenu(QStringLiteral("唤醒模式"), trayMenu);
    QActionGroup *awakeGrp = new QActionGroup(awakeModeMenu);
    awakeGrp->setExclusive(true);
    const QStringList awakeModes = {QStringLiteral("无限期"),
                                    QStringLiteral("持续时长"),
                                    QStringLiteral("直到时刻")};
    for (int i = 0; i < awakeModes.size(); ++i) {
        QAction *a = awakeModeMenu->addAction(awakeModes.at(i));
        a->setCheckable(true);
        a->setChecked(ui.comboAwakeMode->currentIndex() == i);
        awakeGrp->addAction(a);
        m_actAwakeMode[i] = a;
        connect(a, &QAction::triggered, this, [this, i] {
            ui.comboAwakeMode->setCurrentIndex(i);
        });
    }
    trayMenu->addMenu(awakeModeMenu);
    trayMenu->addSeparator();
    QAction *actExit   = trayMenu->addAction(QStringLiteral("退出"));
    connect(actShow, &QAction::triggered, this, [this] {
        showNormal();
        activateWindow();
        raise();
    });
    connect(actLogin, &QAction::triggered, this, [this] { attemptLogin(false); });
    connect(actLogout, &QAction::triggered, this, [this] { onLogoutClicked(); });
    m_actLogin = actLogin;
    m_actLogout = actLogout;
    connect(actExit, &QAction::triggered, this, [this] {
        m_closing = true;
        m_client->requestStop();
        m_tray->hide();
        QApplication::quit();
    });
    m_tray->setContextMenu(trayMenu);
    connect(m_tray, &QSystemTrayIcon::activated, this, &Drcom::onTrayActivated);
    m_tray->show();

    // ---- 读取配置并填充界面 ----
    loadSettings();
    applyTheme();                     // 按配置/系统主题加载浅色或深色样式
    if (ui.editMac->text().isEmpty())
        detectMac();

    setUiState(StateOffline);

    // 首次运行提示（明文保存密码，与官方客户端行为一致）
    if (!m_settings.value(QStringLiteral("conf/warningSeen"), false).toBool()) {
        m_settings.setValue(QStringLiteral("conf/warningSeen"), true);
        m_settings.sync();
        QMessageBox::information(
            this, QStringLiteral("提示"),
            QStringLiteral("本程序在勾选「记住密码」时将以明文形式保存账号密码，"
                           "仅供本机使用，请勿在公共电脑上勾选。\n\n"
                           "MAC 地址请填写 12 位小写十六进制，可点击「自动获取」。"));
    }

    // 启动时自动连接（勾选「自动连接」且已保存密码时生效）
    QTimer::singleShot(800, this, &Drcom::tryAutoConnect);
}

Drcom::~Drcom()
{
    if (m_client)
        m_client->requestStop();
}

void Drcom::closeEvent(QCloseEvent *event)
{
    if (m_closing) {
        event->accept();
        return;
    }
    // 关闭按钮 = 最小化到托盘
    event->ignore();
    hide();
    if (QSystemTrayIcon::isSystemTrayAvailable())
        showTrayMessage(QStringLiteral("吉林大学校园网认证客户端"),
                        QStringLiteral("程序仍在后台运行，双击托盘图标可显示主界面。"));
}

void Drcom::changeEvent(QEvent *event)
{
    QMainWindow::changeEvent(event);
    // 最小化按钮同样隐藏到托盘（认证需持续发送心跳包，保持后台运行）
    if (event->type() == QEvent::WindowStateChange && isMinimized()) {
        QTimer::singleShot(0, this, [this] {
            hide();
            if (QSystemTrayIcon::isSystemTrayAvailable())
                showTrayMessage(QStringLiteral("吉林大学校园网认证客户端"),
                                QStringLiteral("已最小化到托盘，认证连接保持运行。"));
        });
    }
}

// ------------------------------------------------------------------
// 登录 / 注销
// ------------------------------------------------------------------
void Drcom::onLoginClicked()
{
    attemptLogin(false);
}

bool Drcom::attemptLogin(bool silent, bool fromReconnect)
{
    if (m_client->isRunning())
        return false;

    const QString account = ui.editAccount->text().trimmed();
    const QString password = ui.editPassword->text();
    QString mac = normalizeMac(ui.editMac->text());

    QString error;
    if (account.isEmpty() || password.isEmpty())
        error = QStringLiteral("请输入账号和密码。");
    else if (!isValidMac(mac))
        error = QStringLiteral("MAC 地址格式不正确，应为 12 位十六进制，例如 f83dc6de1cf6。");
    else if (password.size() > 16)
        error = QStringLiteral("密码过长，请控制在 16 位以内（协议限制）。");
    if (!error.isEmpty()) {
        if (!silent)
            QMessageBox::warning(this, QStringLiteral("提示"), error);
        return false;
    }
    ui.editMac->setText(mac);

    // 用户手动登录：接管控制，退出自动重连流程
    if (!fromReconnect)
        cancelReconnect();

    // 保存选项与凭据
    saveCredentials();
    saveCheckStates();

    m_client->startLogin(account, password, QByteArray::fromHex(mac.toLatin1()), buildConfig());
    return true;
}

void Drcom::tryAutoConnect()
{
    if (!ui.chkAuto->isChecked())
        return;
    if (!hasSavedCredentials())   // 未保存密码时不自动连接
        return;
    attemptLogin(true);
}

bool Drcom::hasSavedCredentials() const
{
    return !ui.editAccount->text().trimmed().isEmpty()
        && !ui.editPassword->text().isEmpty()
        && isValidMac(normalizeMac(ui.editMac->text()));
}

void Drcom::onLogoutClicked()
{
    cancelReconnect();                    // 无论是否在重连等待中，注销即退出重连流程
    if (!m_client->isRunning())
        return;
    setStatusText(QStringLiteral("正在注销…"));
    m_client->requestStop();
}

// ------------------------------------------------------------------
// 校园网址导航 / 校园网之窗
// ------------------------------------------------------------------
void Drcom::onNavClicked()
{
    NavDialog dlg(this);
    dlg.exec();
}

void Drcom::onWindowClicked()
{
    // 校园网之窗：认证成功后的校园网信息推送门户
    QDesktopServices::openUrl(QUrl(QStringLiteral("http://login.jlu.edu.cn/notice.php")));
}

// ------------------------------------------------------------------
// 自动重连（心跳掉线后触发）
// ------------------------------------------------------------------
void Drcom::handleDropped()
{
    if (m_reconnectArmed)
        return;                       // 已在重连流程中
    if (!m_settings.value(QStringLiteral("conf/autoReconnect"), true).toBool())
        return;
    if (!hasSavedCredentials())
        return;                       // 没有可用凭据，无法自动重连
    m_reconnectArmed = true;
    m_reconnectDelay = 5;
    scheduleReconnect();
}

void Drcom::scheduleReconnect()
{
    if (!m_reconnectArmed)
        return;
    setStatusText(QStringLiteral("已断开，%1 秒后自动重连…").arg(m_reconnectDelay));
    m_reconnectTimer->start(m_reconnectDelay * 1000);
}

void Drcom::cancelReconnect()
{
    m_reconnectArmed = false;
    if (m_reconnectTimer)
        m_reconnectTimer->stop();
}

void Drcom::onReconnectTick()
{
    if (!m_reconnectArmed)
        return;
    if (!hasSavedCredentials()) {
        cancelReconnect();
        return;
    }
    if (m_client->isRunning()) {      // 上一次尝试还在进行中
        scheduleReconnect();
        return;
    }
    if (attemptLogin(true, true))
        m_reconnectDelay = qMin(m_reconnectDelay * 2, 60);   // 下次失败间隔翻倍
    else
        scheduleReconnect();
}

// ------------------------------------------------------------------
// 客户端信号处理
// ------------------------------------------------------------------
void Drcom::onClientLoginStarted()
{
    setUiState(StateLoggingIn);
    setStatusText(QStringLiteral("正在认证…"));
}

void Drcom::onClientLoginSucceeded(const QString &ip)
{
    m_onlineIp = ip;
    cancelReconnect();                    // 认证成功，退出重连流程
    setUiState(StateOnline);
    setIpText(ip);
    setStatusText(QStringLiteral("已连接"));
    m_tray->setToolTip(QStringLiteral("吉林大学校园网认证客户端 · 已连接 %1").arg(ip));
    showTrayMessage(QStringLiteral("认证成功"),
                    QStringLiteral("校园网认证成功，当前 IP：%1").arg(ip));
}

void Drcom::onClientLoginFailed(int code, const QString &message)
{
    setUiState(StateOffline);
    setIpText(QString());
    setStatusText(QStringLiteral("认证失败：%1").arg(message));

    // 账号或密码错误时清除已保存的密码（与官方客户端一致）。
    // 注：0x15 为真实的“客户端版本号错误”（服务器对 servicePack/AUTH_VERSION
    // 不一致客户端的拒绝），不按凭据错误处理；本客户端已与现网可登录客户端
    // （github.com/ZincGluxx/drcom-net-client）的协议常量逐字节对齐。
    const bool credentialError = (code == DrcomClient::ErrWrongPass);
    if (credentialError) {
        m_settings.remove(QStringLiteral("conf/password"));
        m_settings.sync();
    }

    if (m_reconnectArmed) {
        // 自动重连中：凭据错误则放弃，其余错误按退避继续重试
        if (credentialError || code == DrcomClient::ErrUserTerminated)
            cancelReconnect();
        else
            scheduleReconnect();
    }

    showTrayMessage(QStringLiteral("认证失败"), message, QSystemTrayIcon::Warning);
    if (isVisible() && !m_reconnectArmed) {
        QMessageBox::warning(this, QStringLiteral("认证失败"), message);
    }
}

void Drcom::onClientLoggedOut()
{
    cancelReconnect();                    // 用户主动注销，不再自动重连
    setUiState(StateOffline);
    setIpText(QString());
    setStatusText(QStringLiteral("已注销"));
    m_tray->setToolTip(QStringLiteral("吉林大学校园网认证客户端 · 未连接"));
}

void Drcom::onClientConnectionLost()
{
    setUiState(StateOffline);
    setIpText(QString());
    setStatusText(QStringLiteral("已断开：与服务器心跳中断"));
    m_tray->setToolTip(QStringLiteral("吉林大学校园网认证客户端 · 已断开"));
    showTrayMessage(QStringLiteral("连接已断开"),
                    QStringLiteral("与认证服务器心跳中断，网络可能已断开。"),
                    QSystemTrayIcon::Warning);
    handleDropped();                      // 尝试自动重连
}

void Drcom::onTrayActivated(QSystemTrayIcon::ActivationReason reason)
{
    if (reason == QSystemTrayIcon::DoubleClick || reason == QSystemTrayIcon::Trigger) {
        showNormal();
        activateWindow();
        raise();
    }
}

// ------------------------------------------------------------------
// 高级设置对话框
// ------------------------------------------------------------------
void Drcom::onSettingsClicked()
{
    QDialog dlg(this);
    dlg.setWindowTitle(QStringLiteral("高级设置"));
    dlg.setMinimumWidth(360);

    auto *editServer = new QLineEdit(
        m_settings.value(QStringLiteral("conf/server"), QString::fromLatin1(kDefaultServer)).toString(), &dlg);
    auto *spinPort = new QSpinBox(&dlg);
    spinPort->setRange(1, 65535);
    spinPort->setValue(m_settings.value(QStringLiteral("conf/port"), kDefaultPort).toInt());
    auto *editHostIp = new QLineEdit(
        m_settings.value(QStringLiteral("conf/hostIp"), QStringLiteral("0.0.0.0")).toString(), &dlg);
    editHostIp->setPlaceholderText(QStringLiteral("0.0.0.0 表示自动"));
    auto *editDns = new QLineEdit(
        m_settings.value(QStringLiteral("conf/dns"), QStringLiteral("10.10.10.10")).toString(), &dlg);
    auto *editHostName = new QLineEdit(
        m_settings.value(QStringLiteral("conf/hostName"),
                         QSysInfo::machineHostName()).toString(), &dlg);

    auto *comboTheme = new QComboBox(&dlg);
    comboTheme->addItem(QStringLiteral("跟随系统"));
    comboTheme->addItem(QStringLiteral("浅色"));
    comboTheme->addItem(QStringLiteral("深色"));
    comboTheme->setCurrentIndex(
        m_settings.value(QStringLiteral("conf/theme"), 0).toInt());

    auto *form = new QFormLayout;
    form->addRow(QStringLiteral("认证服务器"), editServer);
    form->addRow(QStringLiteral("服务器端口"), spinPort);
    form->addRow(QStringLiteral("本机 IP"), editHostIp);
    form->addRow(QStringLiteral("首选 DNS"), editDns);
    form->addRow(QStringLiteral("主机名"), editHostName);
    form->addRow(QStringLiteral("界面主题"), comboTheme);

    auto *hint = new QLabel(QStringLiteral("以上参数一般无需修改，仅当校园网认证服务器变更时使用。"), &dlg);
    hint->setWordWrap(true);
    hint->setStyleSheet(QStringLiteral("color:#8a9199;font-size:12px;"));

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    auto *layout = new QVBoxLayout(&dlg);
    layout->addLayout(form);
    layout->addWidget(hint);
    layout->addWidget(buttons);

    if (dlg.exec() != QDialog::Accepted)
        return;

    m_settings.setValue(QStringLiteral("conf/server"), editServer->text().trimmed().isEmpty()
                            ? QString::fromLatin1(kDefaultServer) : editServer->text().trimmed());
    m_settings.setValue(QStringLiteral("conf/port"), spinPort->value());
    m_settings.setValue(QStringLiteral("conf/hostIp"), editHostIp->text().trimmed().isEmpty()
                            ? QStringLiteral("0.0.0.0") : editHostIp->text().trimmed());
    m_settings.setValue(QStringLiteral("conf/dns"), editDns->text().trimmed().isEmpty()
                            ? QStringLiteral("10.10.10.10") : editDns->text().trimmed());
    m_settings.setValue(QStringLiteral("conf/hostName"), editHostName->text().trimmed());
    m_settings.setValue(QStringLiteral("conf/theme"), comboTheme->currentIndex());
    m_settings.sync();
    applyTheme();   // 主题切换立即生效
    ui.appSubLabel->setText(QStringLiteral("Dr.COM 校园网认证客户端 · 服务器 %1:%2")
                                .arg(m_settings.value(QStringLiteral("conf/server")).toString())
                                .arg(m_settings.value(QStringLiteral("conf/port")).toInt()));
}

// ------------------------------------------------------------------
// MAC 地址自动获取
// ------------------------------------------------------------------
void Drcom::onRefreshMacClicked()
{
    detectMac();
}

void Drcom::detectMac()
{
    const QList<QNetworkInterface> ifaces = QNetworkInterface::allInterfaces();
    QString best;
    for (const QNetworkInterface &iface : ifaces) {
        if (!(iface.flags() & QNetworkInterface::IsUp))
            continue;
        if (iface.flags() & QNetworkInterface::IsLoopBack)
            continue;
        const QString name = iface.name().toLower();
        if (name.contains(QStringLiteral("virtual")) ||
            name.contains(QStringLiteral("vmnet")) ||
            name.contains(QStringLiteral("vbox")) ||
            name.contains(QStringLiteral("docker")) ||
            name.contains(QStringLiteral("npcap")) ||
            name.contains(QStringLiteral("bluetooth")) ||
            name.contains(QStringLiteral("tunnel")))
            continue;
        const QString hw = iface.hardwareAddress().remove(QLatin1Char(':')).toLower();
        if (hw.size() == 12 && hw != QString(12, QLatin1Char('0'))) {
            best = hw;
            // 优先以太网 / WiFi
            if (iface.type() == QNetworkInterface::Ethernet ||
                iface.type() == QNetworkInterface::Wifi)
                break;
        }
    }
    if (!best.isEmpty())
        ui.editMac->setText(best);
}

// ------------------------------------------------------------------
// 配置读写
// ------------------------------------------------------------------
void Drcom::loadSettings()
{
    ui.editAccount->setText(m_settings.value(QStringLiteral("conf/account")).toString());
    ui.editPassword->setText(m_settings.value(QStringLiteral("conf/password")).toString());
    ui.editMac->setText(m_settings.value(QStringLiteral("conf/mac")).toString());
    ui.chkRemember->setChecked(m_settings.value(QStringLiteral("conf/remember"), false).toBool());
    ui.chkAuto->setChecked(m_settings.value(QStringLiteral("conf/autoLogin"), false).toBool());
    ui.chkReconnect->setChecked(m_settings.value(QStringLiteral("conf/autoReconnect"), true).toBool());
    // 先恢复唤醒模式控件，再恢复勾选（勾选会触发状态应用）
    ui.comboAwakeMode->setCurrentIndex(
        m_settings.value(QStringLiteral("conf/awakeMode"), 0).toInt());
    ui.spinAwakeMinutes->setValue(
        m_settings.value(QStringLiteral("conf/awakeMinutes"), 60).toInt());
    ui.timeAwakeUntil->setTime(QTime::fromString(
        m_settings.value(QStringLiteral("conf/awakeUntil"),
                         QTime::currentTime().addSecs(3600)
                             .toString(QStringLiteral("HH:mm"))).toString(),
        QStringLiteral("HH:mm")));
    ui.chkAwake->setChecked(m_settings.value(QStringLiteral("conf/keepAwake"), false).toBool());
    ui.chkAwakeDisplay->setChecked(m_settings.value(QStringLiteral("conf/keepDisplay"), false).toBool());
    ui.chkAutoStart->setChecked(
        m_settings.value(QStringLiteral("conf/autoStart"), false).toBool()
        && (taskExists() || runKeyExists()));

    ui.appSubLabel->setText(QStringLiteral("Dr.COM 校园网认证客户端 · 服务器 %1:%2")
                                .arg(m_settings.value(QStringLiteral("conf/server"),
                                                     QString::fromLatin1(kDefaultServer)).toString())
                                .arg(m_settings.value(QStringLiteral("conf/port"), kDefaultPort).toInt()));
}

void Drcom::saveCredentials()
{
    m_settings.setValue(QStringLiteral("conf/account"), ui.editAccount->text().trimmed());
    if (ui.chkRemember->isChecked())
        m_settings.setValue(QStringLiteral("conf/password"), ui.editPassword->text());
    else
        m_settings.remove(QStringLiteral("conf/password"));
    m_settings.setValue(QStringLiteral("conf/mac"), normalizeMac(ui.editMac->text()));
    m_settings.sync();
}

void Drcom::saveCheckStates()
{
    m_settings.setValue(QStringLiteral("conf/remember"), ui.chkRemember->isChecked());
    m_settings.setValue(QStringLiteral("conf/autoLogin"), ui.chkAuto->isChecked());
    m_settings.setValue(QStringLiteral("conf/autoReconnect"), ui.chkReconnect->isChecked());
    m_settings.setValue(QStringLiteral("conf/keepAwake"), ui.chkAwake->isChecked());
    m_settings.setValue(QStringLiteral("conf/keepDisplay"), ui.chkAwakeDisplay->isChecked());
    m_settings.setValue(QStringLiteral("conf/awakeMode"), ui.comboAwakeMode->currentIndex());
    m_settings.setValue(QStringLiteral("conf/awakeMinutes"), ui.spinAwakeMinutes->value());
    m_settings.setValue(QStringLiteral("conf/awakeUntil"),
                       ui.timeAwakeUntil->time().toString(QStringLiteral("HH:mm")));
    m_settings.setValue(QStringLiteral("conf/autoStart"), ui.chkAutoStart->isChecked());
    m_settings.sync();
}

DrcomConfig Drcom::buildConfig() const
{
    DrcomConfig cfg;
    cfg.server = m_settings.value(QStringLiteral("conf/server"),
                                  QString::fromLatin1(kDefaultServer)).toString();
    cfg.port = static_cast<quint16>(m_settings.value(QStringLiteral("conf/port"), kDefaultPort).toInt());
    cfg.hostIp = m_settings.value(QStringLiteral("conf/hostIp"), QStringLiteral("0.0.0.0")).toString();
    cfg.primaryDns = m_settings.value(QStringLiteral("conf/dns"),
                                      QStringLiteral("10.10.10.10")).toString();
    cfg.hostName = m_settings.value(QStringLiteral("conf/hostName"),
                                    QSysInfo::machineHostName()).toString();
    return cfg;
}

// ------------------------------------------------------------------
// 界面状态
// ------------------------------------------------------------------
void Drcom::setUiState(UiState state)
{
    m_state = state;
    const bool logging = (state == StateLoggingIn);
    const bool online = (state == StateOnline);

    ui.editAccount->setEnabled(!logging && !online);
    ui.editPassword->setEnabled(!logging && !online);
    ui.editMac->setEnabled(!logging && !online);
    ui.btnRefreshMac->setEnabled(!logging && !online);
    ui.chkRemember->setEnabled(!logging);
    ui.chkAuto->setEnabled(!logging);
    ui.btnSettings->setEnabled(!logging);

    ui.btnLogin->setEnabled(!logging && !online);
    ui.btnLogin->setText(logging ? QStringLiteral("认证中…") : QStringLiteral("登　录"));
    ui.btnLogout->setEnabled(logging || online);

    if (m_actLogin)
        m_actLogin->setEnabled(!logging && !online);
    if (m_actLogout)
        m_actLogout->setEnabled(logging || online);

    switch (state) {
    case StateOffline:  setStatusDot(QStringLiteral("#c4c9d1")); break;
    case StateLoggingIn:setStatusDot(QStringLiteral("#f5a623")); break;
    case StateOnline:   setStatusDot(QStringLiteral("#22b573")); break;
    }
}

void Drcom::setStatusDot(const QString &color)
{
    ui.statusDot->setStyleSheet(QStringLiteral(
        "background:%1;border-radius:6px;").arg(color));
}

void Drcom::setStatusText(const QString &text)
{
    ui.statusLabel->setText(text);
}

void Drcom::setIpText(const QString &ip)
{
    ui.ipLabel->setText(ip.isEmpty() ? QStringLiteral("IP: --")
                                     : QStringLiteral("IP: %1").arg(ip));
}

void Drcom::showTrayMessage(const QString &title, const QString &msg,
                            QSystemTrayIcon::MessageIcon icon)
{
    if (QSystemTrayIcon::isSystemTrayAvailable() && m_tray)
        m_tray->showMessage(title, msg, icon, 4000);
}

// ------------------------------------------------------------------
// 保持唤醒（PowerToys Awake 式，三模式）：
//   0=无限期  1=持续时长(分钟)  2=直到时刻
// ------------------------------------------------------------------
void Drcom::setKeepAwakeState()
{
    // 先停表并清除之前的保持状态
    if (m_awakeTimer)
        m_awakeTimer->stop();
#ifdef Q_OS_WIN
    SetThreadExecutionState(ES_CONTINUOUS);
#endif

    if (!ui.chkAwake->isChecked()) {
        updateAwakeHint();          // 显示「未启用」
        return;
    }

    const int mode = ui.comboAwakeMode->currentIndex();
    if (mode == 1) {
        m_awakeEnd = QDateTime::currentDateTime()
                         .addSecs(ui.spinAwakeMinutes->value() * 60);
    } else if (mode == 2) {
        QDateTime end(QDate::currentDate(), ui.timeAwakeUntil->time());
        if (end <= QDateTime::currentDateTime())
            end = end.addDays(1);       // 目标时刻已过则顺延到次日
        m_awakeEnd = end;
    }

#ifdef Q_OS_WIN
    EXECUTION_STATE es = ES_CONTINUOUS | ES_SYSTEM_REQUIRED; // 防止系统睡眠
    if (ui.chkAwakeDisplay->isChecked())
        es |= ES_DISPLAY_REQUIRED;      // 防止屏幕熄灭
    SetThreadExecutionState(es);
#endif

    updateAwakeHint();
    if (mode != 0 && m_awakeTimer)
        m_awakeTimer->start(1000);      // 时长/直到模式每秒刷新倒计时
}

// 按模式显示/启用对应输入控件
void Drcom::updateAwakeModeControls()
{
    const bool active = ui.chkAwake->isChecked();
    const int mode = ui.comboAwakeMode->currentIndex();
    ui.comboAwakeMode->setEnabled(active);
    ui.spinAwakeMinutes->setEnabled(active && mode == 1);
    ui.timeAwakeUntil->setEnabled(active && mode == 2);
    ui.labelAwakeHint->setVisible(true);   // 未启用也显示「未启用」文字
}

// 刷新提示：未启用 / 无限期 / 剩余时间 / 目标时刻
void Drcom::updateAwakeHint()
{
    if (!ui.chkAwake->isChecked()) {
        ui.labelAwakeHint->setText(QStringLiteral("未启用"));
        return;
    }
    const int mode = ui.comboAwakeMode->currentIndex();
    if (mode == 1) {
        const qint64 remainMs = QDateTime::currentDateTime().msecsTo(m_awakeEnd);
        const int secs = remainMs > 0 ? static_cast<int>(remainMs / 1000) : 0;
        ui.labelAwakeHint->setText(
            QStringLiteral("剩余 %1:%2:%3")
                .arg(secs / 3600, 2, 10, QLatin1Char('0'))
                .arg((secs % 3600) / 60, 2, 10, QLatin1Char('0'))
                .arg(secs % 60, 2, 10, QLatin1Char('0')));
    } else if (mode == 2) {
        ui.labelAwakeHint->setText(
            QStringLiteral("至 %1").arg(ui.timeAwakeUntil->time()
                                            .toString(QStringLiteral("HH:mm"))));
    } else {
        ui.labelAwakeHint->setText(QStringLiteral("无限期"));
    }
}

// 倒计时到点：自动结束保持唤醒（恢复系统自动睡眠）
void Drcom::onAwakeTick()
{
    if (!ui.chkAwake->isChecked()) {
        if (m_awakeTimer)
            m_awakeTimer->stop();
        return;
    }
    const int mode = ui.comboAwakeMode->currentIndex();
    if (mode == 0) {
        if (m_awakeTimer)
            m_awakeTimer->stop();
        updateAwakeHint();
        return;
    }
    if (QDateTime::currentDateTime() >= m_awakeEnd) {
        ui.chkAwake->setChecked(false);   // 触发 toggled -> 清除保持状态
        showTrayMessage(QStringLiteral("保持唤醒"),
                        QStringLiteral("设置的保持唤醒时长已结束，系统恢复自动睡眠。"));
        return;
    }
    updateAwakeHint();
}

// ------------------------------------------------------------------
// 开机自启：优先创建「登录时触发」的计划任务（由任务计划服务在登录
// 瞬间启动，且设置较高优先级，比 Explorer 的启动目录快得多）；
// 若权限不足创建失败，则回退到 HKCU\Run 注册表项。
// ------------------------------------------------------------------
void Drcom::setAutoStart(bool on)
{
#ifdef Q_OS_WIN
    const QString kTask = QStringLiteral("Drcom JLU Autostart");
    const QString kRunKeyPath = QStringLiteral(
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows"
        "\\CurrentVersion\\Run");

    // 迁移：清理旧版启动目录快捷方式，避免启动两份
    QFile::remove(
        QStandardPaths::writableLocation(QStandardPaths::ApplicationsLocation)
        + QStringLiteral("/Startup/吉林大学校园网认证.lnk"));

    QSettings runKey(kRunKeyPath, QSettings::NativeFormat);

    if (!on) {
        // 删除计划任务（不存在时 schtasks 返回非 0，忽略）
        QProcess delTask;
        delTask.start(QStringLiteral("schtasks"),
                      {QStringLiteral("/Delete"), QStringLiteral("/TN"),
                       kTask, QStringLiteral("/F")});
        delTask.waitForFinished(15000);
        delTask.readAllStandardOutput();
        delTask.readAllStandardError();
        runKey.remove(QStringLiteral("DrcomJLU"));
        runKey.sync();
        return;
    }

    if (createTask()) {                 // 首选：计划任务
        runKey.remove(QStringLiteral("DrcomJLU"));    // 避免双启动
        runKey.sync();
        return;
    }

    // 回退：HKCU Run 注册表项（普通用户也可写，无需提权）
    runKey.setValue(QStringLiteral("DrcomJLU"),
                    QDir::toNativeSeparators(
                        QCoreApplication::applicationFilePath()));
    runKey.sync();
#endif
}

// 计划任务是否已存在
bool Drcom::taskExists()
{
#ifdef Q_OS_WIN
    QProcess p;
    p.start(QStringLiteral("schtasks"),
            {QStringLiteral("/Query"), QStringLiteral("/TN"),
             QStringLiteral("Drcom JLU Autostart")});
    if (!p.waitForFinished(12000))
        return false;
    p.readAllStandardOutput();
    p.readAllStandardError();
    return p.exitStatus() == QProcess::NormalExit && p.exitCode() == 0;
#else
    return false;
#endif
}

// HKCU Run 注册表项是否存在
bool Drcom::runKeyExists()
{
#ifdef Q_OS_WIN
    QSettings runKey(QStringLiteral("HKEY_CURRENT_USER\\Software\\Microsoft"
                                    "\\Windows\\CurrentVersion\\Run"),
                     QSettings::NativeFormat);
    return runKey.contains(QStringLiteral("DrcomJLU"));
#else
    return false;
#endif
}

// 当前用户 SID（写入任务 XML，避免用户名编码/域名问题）
QString Drcom::currentUserSid()
{
#ifdef Q_OS_WIN
    HANDLE token = nullptr;
    QString sid;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        DWORD size = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        if (size > 0) {
            std::vector<char> buf(size);
            if (GetTokenInformation(token, TokenUser, buf.data(), size, &size)) {
                const TOKEN_USER *tu =
                    reinterpret_cast<const TOKEN_USER *>(buf.data());
                LPWSTR str = nullptr;
                if (ConvertSidToStringSidW(tu->User.Sid, &str)) {
                    sid = QString::fromWCharArray(str);
                    LocalFree(str);
                }
            }
        }
        CloseHandle(token);
    }
    return sid;
#else
    return QString();
#endif
}

// 创建登录触发计划任务（XML 导入，UTF-16 编码，路径含中文安全）
bool Drcom::createTask()
{
#ifdef Q_OS_WIN
    if (taskExists())
        return true;

    const QString sid = currentUserSid();
    if (sid.isEmpty())
        return false;

    const QString exe = QDir::toNativeSeparators(
        QCoreApplication::applicationFilePath());
    const QString workDir = QDir::toNativeSeparators(
        QCoreApplication::applicationDirPath());

    const QString xml = QStringLiteral(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>"
        "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
        "<RegistrationInfo><Author>Drcom JLU Client</Author>"
        "<Description>吉林大学校园网认证客户端开机自动启动</Description>"
        "</RegistrationInfo>"
        "<Triggers><LogonTrigger><Enabled>true</Enabled>"
        "<UserId>%1</UserId></LogonTrigger></Triggers>"
        "<Principals><Principal id=\"Author\"><UserId>%1</UserId>"
        "<LogonType>InteractiveToken</LogonType>"
        "<RunLevel>LeastPrivilege</RunLevel></Principal></Principals>"
        "<Settings>"
        "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
        "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
        "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
        "<AllowHardTerminate>true</AllowHardTerminate>"
        "<StartWhenAvailable>true</StartWhenAvailable>"
        "<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>"
        "<IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd>"
        "<RestartOnIdle>false</RestartOnIdle></IdleSettings>"
        "<AllowStartOnDemand>true</AllowStartOnDemand>"
        "<Enabled>true</Enabled><Hidden>false</Hidden>"
        "<RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun>"
        "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"
        "<Priority>4</Priority>"
        "</Settings>"
        "<Actions Context=\"Author\"><Exec><Command>%2</Command>"
        "<WorkingDirectory>%3</WorkingDirectory></Exec></Actions>"
        "</Task>")
                            .arg(sid, exe, workDir);

    // utf-16le + BOM 写入临时文件（schtasks /XML 的推荐编码）
    const QString xmlPath =
        QDir::tempPath() + QStringLiteral("/drcom_autostart.xml");
    QFile f(xmlPath);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return false;
    QByteArray bytes;
    bytes.append('\xFF');
    bytes.append('\xFE');
    const std::u16string u16 = xml.toStdU16String();
    for (char16_t c : u16) {
        bytes.append(static_cast<char>(c & 0xFF));
        bytes.append(static_cast<char>((c >> 8) & 0xFF));
    }
    f.write(bytes);
    f.close();

    QProcess proc;
    proc.start(QStringLiteral("schtasks"),
               {QStringLiteral("/Create"), QStringLiteral("/XML"),
                QDir::toNativeSeparators(xmlPath), QStringLiteral("/TN"),
                QStringLiteral("Drcom JLU Autostart"), QStringLiteral("/F")});
    const bool ok = proc.waitForFinished(20000)
                    && proc.exitStatus() == QProcess::NormalExit
                    && proc.exitCode() == 0;
    proc.readAllStandardOutput();
    proc.readAllStandardError();
    QFile::remove(xmlPath);

    if (!ok)
        showTrayMessage(QStringLiteral("开机自启"),
                        QStringLiteral("计划任务创建失败，已改用注册表启动项。"),
                        QSystemTrayIcon::Warning);
    return ok;
#else
    return false;
#endif
}

// ------------------------------------------------------------------
// 界面主题：按配置/系统主题加载浅色或深色样式表
//   conf/theme: 0=跟随系统  1=浅色  2=深色
// ------------------------------------------------------------------
bool Drcom::isSystemDarkMode()
{
#ifdef Q_OS_WIN
    QSettings reg(
        QStringLiteral("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows"
                       "\\CurrentVersion\\Themes\\Personalize"),
        QSettings::NativeFormat);
    return reg.value(QStringLiteral("AppsUseLightTheme"), 1).toInt() == 0;
#else
    return false;
#endif
}

void Drcom::applyTheme()
{
    const int theme = m_settings.value(QStringLiteral("conf/theme"), 0).toInt();
    const bool dark = (theme == 2) || (theme == 0 && isSystemDarkMode());
    QFile f(dark ? QStringLiteral(":/Drcom/style_dark.qss")
                 : QStringLiteral(":/Drcom/style.qss"));
    if (f.open(QIODevice::ReadOnly | QIODevice::Text))
        qApp->setStyleSheet(QString::fromUtf8(f.readAll()));
}

// ------------------------------------------------------------------
// 应用图标（运行时绘制，蓝色圆角方块 + “吉”字）
// ------------------------------------------------------------------
QIcon Drcom::makeAppIcon()
{
    QPixmap pm(64, 64);
    pm.fill(Qt::transparent);

    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing, true);

    QLinearGradient grad(0, 0, 0, 64);
    grad.setColorAt(0.0, QColor(QStringLiteral("#3d7bd6")));
    grad.setColorAt(1.0, QColor(QStringLiteral("#1e4e8c")));

    QPainterPath path;
    path.addRoundedRect(QRectF(2, 2, 60, 60), 14, 14);
    p.fillPath(path, grad);

    QFont font(QStringLiteral("Microsoft YaHei"));
    font.setPixelSize(40);
    font.setBold(true);
    p.setFont(font);
    p.setPen(Qt::white);
    p.drawText(pm.rect().adjusted(0, -3, 0, -3), Qt::AlignCenter,
               QStringLiteral("吉"));
    p.end();

    return QIcon(pm);
}
