#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>

class QUdpSocket;
class QHostAddress;

// ============================================================
// 吉林大学校园网 Dr.COM 认证协议实现
//   协议：UDP，本地绑定 61440 端口，认证服务器 10.100.61.3:61440
//   流程：challenge(0x01) -> login(0x03) -> keepalive(keep38/keep40)
//   协议常量与可正常登录的第三方客户端
//   （github.com/ZincGluxx/drcom-net-client，已在本机实测可登录）
//   逐字节对齐：
//     challenge[4] = 0x09
//     login servicePack（41 字节）="3dc79f5212e8170acfa9ec95f1d749916542be7b1"
//     login AUTH_VERSION={0x68,0x00}（位于 [311..312]，因 41 字节
//     servicePack 整体比 0x6a 文档布局后移 1 字节），ADAPTERNUM=0x03，
//     密码填充 pwdLen/4 字节 0，尾部 60 a2 + 28 字节 0，
//     checksum 逐 4 字节小端异或、余数忽略（与可用客户端一致）
// ============================================================

struct DrcomConfig
{
    QString server     = QStringLiteral("10.100.61.3"); // 认证服务器地址
    quint16 port       = 61440;                          // 认证服务器端口
    QString hostIp     = QStringLiteral("0.0.0.0");      // 本机绑定/上报 IP（0.0.0.0 = 自动）
    QString primaryDns = QStringLiteral("10.10.10.10");  // 首选 DNS（吉大校园网 DNS）
    QString hostName;                                    // 主机名（留空自动取本机名，登录包 32 字节左对齐）

    unsigned char authVersion[2]       = { 0x68, 0x00 }; // 现网可登录客户端的 AUTH_VERSION
    unsigned char keepAliveVersion[2]  = { 0xDC, 0x02 }; // keep40 默认版本
    unsigned char controlCheckStatus   = 0x20;           // 与官方客户端一致
    unsigned char adapterNum           = 0x03;           // 现网可登录客户端的 ADAPTERNUM
    unsigned char ipDog                = 0x01;           // 与官方客户端一致
};

class DrcomClient : public QObject
{
    Q_OBJECT

public:
    // 错误码（与 dr-jlu-win32 / dogcom 保持一致）
    enum ErrorCode {
        ErrOk             = 0x00,
        ErrCheckMac       = 0x01, // 有人正在用该 MAC 地址使用此账号
        ErrServerBusy     = 0x02, // 服务器繁忙
        ErrWrongPass      = 0x03, // 账号或密码错误
        ErrNotEnough      = 0x04, // 使用时长或流量超限
        ErrFrozen         = 0x05, // 账号被冻结
        ErrIpMismatch     = 0x07, // IP 地址不匹配
        ErrMacMismatch    = 0x0B, // MAC 地址不匹配
        ErrTooManyIp      = 0x14, // 账号对应多个 IP
        ErrUpdateClient   = 0x15, // 客户端版本号错误（servicePack/AUTH_VERSION 与服务器不一致）
        ErrIpMacMismatch  = 0x16, // 只可用于指定的 IP 和 MAC
        ErrMustUseDhcp    = 0x17, // 请设置为 DHCP
        ErrUnknown        = 0x18, // 未知错误
        ErrInit           = 0x19, // 网络初始化失败
        ErrCreateSocket   = 0x20, // 创建 socket 失败
        ErrBind           = 0x21, // 绑定端口失败（可能被其他客户端占用 61440）
        ErrSockOpt        = 0x22, // 设置 socket 选项失败
        ErrChallenge      = 0x23, // 与服务器握手失败
        ErrUserTerminated = 0x24, // 用户注销
        ErrTimeout        = 0x25, // 服务器响应超时
        ErrBadResponse    = 0x26, // 服务器返回异常报文
        ErrConnectionLost = 0x27  // 心跳失败，连接已断开
    };
    Q_ENUM(ErrorCode)

    static QString errorMessage(int code);

    explicit DrcomClient(QObject *parent = nullptr);
    ~DrcomClient() override;

    // 开始登录（会启动后台线程，登录期间不要重复调用）
    void startLogin(const QString &account, const QString &password,
                    const QByteArray &mac, const DrcomConfig &cfg);
    // 注销 / 中断（可在线程任意阶段调用）
    void requestStop();
    bool isRunning() const;

    // 生成 12 位小写十六进制 MAC 字符串（如 f83dc6de1cf6）
    static QString macToString(const QByteArray &mac);

signals:
    void loginStarted();                        // 开始认证
    void loginSucceeded(const QString &ip);     // 认证成功，ip 为服务器分配/返回的 IP
    void loginFailed(int code, const QString &message); // 认证失败
    void loggedOut();                           // 主动注销完成
    void connectionLost();                      // 心跳失败掉线
    void ipAssigned(const QString &ip);         // challenge 阶段服务器返回的 IP

private:
    void run();                       // 后台线程主体
    bool waitForPacket(QUdpSocket &sock, QByteArray &out, int timeoutMs,
                       bool ignoreStop = false); // ignoreStop：注销阶段可无视 m_stop
    bool interruptibleWait(int ms);   // 可被 requestStop 打断的等待
    QByteArray buildLoginPacket(const QByteArray &seed) const;
    bool doKeepalive1(QUdpSocket &sock, const QHostAddress &server, quint16 port,
                      const QByteArray &seed, const QByteArray &authInfo); // keep38（含重试）
    bool doKeepalive2(QUdpSocket &sock, const QHostAddress &server, quint16 port,
                      const QByteArray &authInfo); // keep40 阶段（extra/type1/type3）
    bool doInitialExtra(QUdpSocket &sock, const QHostAddress &server, quint16 port);
    bool exchangeKeep40(QUdpSocket &sock, const QHostAddress &server, quint16 port,
                        int type, const QByteArray &tail4, bool withIp);
    void drainSocket(QUdpSocket &sock);             // 非阻塞排空积压报文
    QByteArray buildKeep40Packet(int type, bool isExtra, const QByteArray &tail4);
    void sendLogout(QUdpSocket &sock, const QHostAddress &server, quint16 port,
                    const QByteArray &seed, const QByteArray &authInfo);

    static QByteArray ipToBytes(const QString &ip);
    static QString ipToString(const QByteArray &ip);

    QString m_account;
    QString m_password;
    QByteArray m_mac;      // 6 字节
    DrcomConfig m_cfg;

    // 会话状态（startLogin 时重置）
    QByteArray m_pass16;          // 协议内密码（最多 16 字节）
    unsigned char m_rand1 = 0;    // 本次会话 challenge 随机数 1
    unsigned char m_rand2 = 0;    // 本次会话 challenge 随机数 2
    QByteArray m_assignedIp;      // challenge 下发的本机 IP（4 字节）
    unsigned char m_keep40Seq = 0; // keep40 序号（0x00 起，响应后 +1）
    QByteArray m_keep40Tail;      // keep40 尾码（取自回包 [16..19]，4 字节）
    bool m_keep40First = true;    // keep40_extra 仅会话首轮发送
    bool m_keep40PairDone = false;// 是否已完成过 type1/type3 首对（决定 type1 携带尾码）
    bool m_loggedIn = false;      // 本会话是否已登录成功

    // 全局状态（客户端生命周期内不重置）
    int m_challengeTimes = 0x02;  // challenge 全局计数器（0x02 起，每次 +1）

    std::atomic_bool m_stop{ false };
    std::atomic_bool m_running{ false };
    std::thread m_thread;
    std::mutex m_mutex;
    std::condition_variable m_cv;
};
