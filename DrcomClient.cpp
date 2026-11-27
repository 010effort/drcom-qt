#include "DrcomClient.h"

#include <QHostAddress>
#include <QUdpSocket>
#include <QCryptographicHash>
#include <QHostInfo>
#include <QRandomGenerator>
#include <QDateTime>
#include <cstring>

// ============================================================
// 报文布局（与已实测可登录的第三方客户端
//   github.com/ZincGluxx/drcom-net-client 逐字节对齐）
//
// 1) Challenge（20 字节，发往服务器:61440）
//    [0]=0x01 [1]=times（全局计数器，从 0x02 起，每次 +1）
//    [2..3]=rand1 rand2  [4]=0x09  其余 0
//    服务器回应 [0]=0x02（长度 76）：seed=[4..7]，IP=[20..23]
//
// 2) Login（359 + passLen + passLen/4 字节；passLen>16 截断为 16）
//    [0]=0x03 [1]=0x01 [2]=0x00 [3]=len(user)+20
//    [4..19]   MD5A = MD5(0x03 0x01 seed password)
//    [20..55]  username 左对齐 36 字节
//    [56]=0x20 [57]=0x03（现网可登录客户端 adapterNum）
//    [58..63]  MD5A[0..5] 与 MAC 逐字节大端异或
//    [64..79]  MD5B = MD5(0x01 password seed 0x00*4)
//    [80]=0x01 [81..84] IP1 = challenge 下发的 IP（IP2/3/4 全零）
//    [97..104] checksum1（MD5 前 8 字节，输入=报文[0..96]+{0x14,0x00,0x07,0x0b}）
//    [105]=0x01（ipDog）
//    [110..141] 主机名 32 字节左对齐
//    [142..145] 首选 DNS=10.10.10.10  [146..153] DHCP/备用 DNS=0
//    [162..181] 操作系统版本信息（固定）
//    [182..190] "DrCOM" 主机名块，尾部 0x68
//    [246..286] ServicePack（41 字节，现网可登录客户端值）
//    [311..312] AUTH_VERSION = 0x68 0x00（因 41 字节 servicePack，
//               整体比 0x6a 文档布局后移 1 字节）
//    [313]=0 [314]=密码长度
//    [315..]   密码逐字节异或 MD5A 后循环左移 3 位
//    [..]=0x02 [..]=0x0c
//    checksum2（输入=报文[0..316+passLen] + {0x01,0x26,0x07,0x11,0x00,0x00} + MAC，
//              逐 4 字节小端异或、余数忽略，与可登录客户端一致）
//    00 00 + MAC + passLen/4 个 0 + 0x60 0xa2 + 28 字节 0
//    服务器回应 [0]=0x04 成功（auth_information=[23..38]），[0]=0x05 失败（原因=[4]）
//
// 3) Keepalive（与可登录客户端一致，并融合 newclient.py 的自愈策略）
//    keep38（38 字节）：[0]=0xff MD5A(16) 00 00 00 tail1(16) time2
//      time2 = 大端 2 字节（当前 Unix 秒 % 0xffff）；回包 [0]=0x07；
//      3 次尝试（每次刷新时间戳）
//    keep40_extra（40 字节，仅会话首轮）：
//      07 seq 28 00 0B 01 0f 27 2f 12 0... tail4@16 0...
//      回包 [2]=0x10 时 seq 前进并以 dc02 重发
//    keep40_1（40 字节）：07 seq 28 00 0B 01 dc 02 2f 12 0... tail4@16 0...
//      回包 tail2=[16..19]
//    keep40_2（40 字节）：07 seq 28 00 0B 03 dc 02 2f 12 0... tail4@16 0... IP@28
//      回包 tail2=[16..19]
//    每阶段失败立即重试；排空积压报文；连续 2 个完整周期失败才判定掉线；
//    成功周期按 20 秒节拍可中断等待
//
// 4) Logout（注销：先 challenge 再 80 字节注销包，尽力而为）
//    [0]=0x06 [1]=0x01 [2]=0x00 [3]=len(user)+20
//    [4..19]  MD5(0x06 0x01 salt 密码)
//    [20..55] username 左对齐 36 字节
//    [56]=0x20 [57]=0x03 [58..63]=MAC ^ MD5[0..5]  [64..79]=tail1[0..15]
//    服务器回应 [0]=0x04 成功
// ============================================================

QString DrcomClient::errorMessage(int code)
{
    switch (code) {
    case ErrCheckMac:      return QStringLiteral("[提示] 有人正在用该 MAC 地址使用此账号");
    case ErrServerBusy:    return QStringLiteral("[提示] 服务器繁忙，请稍后重试");
    case ErrWrongPass:     return QStringLiteral("[提示] 账号或密码错误");
    case ErrNotEnough:     return QStringLiteral("[提示] 该账号使用时长或流量超限");
    case ErrFrozen:        return QStringLiteral("[提示] 该账号已被冻结");
    case ErrIpMismatch:    return QStringLiteral("[提示] IP 地址不匹配，该账号只能用于指定 IP");
    case ErrMacMismatch:   return QStringLiteral("[提示] MAC 地址不匹配，该账号只能用于指定的 MAC 地址");
    case ErrTooManyIp:     return QStringLiteral("[提示] 该账号对应多个 IP 地址");
    case ErrUpdateClient:  return QStringLiteral("[提示] 客户端版本号错误，请升级客户端");
    case ErrIpMacMismatch: return QStringLiteral("[提示] 该账号只可用于指定的 IP 和 MAC 地址");
    case ErrMustUseDhcp:   return QStringLiteral("[提示] 请将计算机的 TCP/IPv4 属性设置为自动获取（DHCP）");
    case ErrInit:          return QStringLiteral("[提示] 程序网络初始化失败");
    case ErrCreateSocket:  return QStringLiteral("[提示] 创建网络套接字失败");
    case ErrBind:          return QStringLiteral("[提示] 绑定 61440 端口失败，请检查是否有其他客户端占用了端口");
    case ErrSockOpt:       return QStringLiteral("[提示] 设置网络套接字选项失败");
    case ErrChallenge:     return QStringLiteral("[提示] 与认证服务器握手失败，请检查网络连接");
    case ErrTimeout:       return QStringLiteral("[提示] 认证服务器响应超时，请稍后重试");
    case ErrBadResponse:   return QStringLiteral("[提示] 认证服务器返回了异常报文");
    case ErrConnectionLost:return QStringLiteral("[提示] 与服务器心跳中断，已断开连接");
    case ErrUserTerminated:return QStringLiteral("[提示] 用户注销");
    case ErrUnknown:
    default:               return QStringLiteral("[提示] 未知错误");
    }
}

DrcomClient::DrcomClient(QObject *parent)
    : QObject(parent)
{
}

DrcomClient::~DrcomClient()
{
    requestStop();
    if (m_thread.joinable())
        m_thread.join();
}

bool DrcomClient::isRunning() const
{
    return m_running.load();
}

void DrcomClient::requestStop()
{
    m_stop.store(true);
    m_cv.notify_all();
}

QString DrcomClient::macToString(const QByteArray &mac)
{
    if (mac.size() != 6)
        return QString();
    QString s;
    for (int i = 0; i < 6; ++i)
        s += QString::asprintf("%02x", static_cast<unsigned char>(mac.at(i)));
    return s;
}

void DrcomClient::startLogin(const QString &account, const QString &password,
                             const QByteArray &mac, const DrcomConfig &cfg)
{
    if (m_running.load())
        return;
    // 上一轮线程已结束但 std::thread 对象仍是 joinable：
    // 必须先 join 回收，直接赋值会触发 std::terminate 导致闪退
    if (m_thread.joinable())
        m_thread.join();
    m_account = account;
    m_password = password;
    m_mac = mac.size() == 6 ? mac : QByteArray(6, 0);
    m_cfg = cfg;
    if (m_cfg.hostName.isEmpty())
        m_cfg.hostName = QHostInfo::localHostName();

    // 会话状态（challenge_times 是客户端全局计数器，不随登录重置）
    m_pass16 = m_password.toLatin1().left(16);   // 协议内密码最多 16 字节
    m_rand1 = 0;
    m_rand2 = 0;
    m_assignedIp.clear();
    m_keep40Seq = 0;
    m_keep40Tail = QByteArray(4, 0);
    m_keep40First = true;
    m_keep40PairDone = false;
    m_loggedIn = false;

    m_stop.store(false);
    m_running.store(true);
    m_thread = std::thread(&DrcomClient::run, this);
}

// ------------------------------------------------------------------
// 后台线程主体
// ------------------------------------------------------------------
void DrcomClient::run()
{
    emit loginStarted();

    QUdpSocket socket;

    // 1. 绑定本地 61440 端口（与官方客户端一致，独占该端口）
    QHostAddress bindAddr = QHostAddress::AnyIPv4;
    if (!m_cfg.hostIp.isEmpty() && m_cfg.hostIp != QStringLiteral("0.0.0.0"))
        bindAddr = QHostAddress(m_cfg.hostIp);
    if (!socket.bind(bindAddr, m_cfg.port, QUdpSocket::DontShareAddress)) {
        emit loginFailed(ErrBind, errorMessage(ErrBind));
        m_running.store(false);
        return;
    }

    const QHostAddress server(m_cfg.server);

    // 2. Challenge（times 从 0x02 起全局递增，[4]=0x09 与可登录客户端一致）
    m_rand1 = static_cast<unsigned char>(QRandomGenerator::global()->bounded(256));
    m_rand2 = static_cast<unsigned char>(QRandomGenerator::global()->bounded(256));
    QByteArray challenge(20, 0);
    challenge[0] = static_cast<char>(0x01);
    challenge[1] = static_cast<char>(m_challengeTimes & 0xff);
    challenge[2] = static_cast<char>(m_rand1);
    challenge[3] = static_cast<char>(m_rand2);
    challenge[4] = static_cast<char>(0x09);
    ++m_challengeTimes;
    socket.writeDatagram(challenge, server, m_cfg.port);

    QByteArray resp;
    if (m_stop.load() || !waitForPacket(socket, resp, 3000)) {
        emit loginFailed(m_stop.load() ? ErrUserTerminated : ErrChallenge,
                         errorMessage(m_stop.load() ? ErrUserTerminated : ErrChallenge));
        m_running.store(false);
        return;
    }
    if (resp.size() < 24 || static_cast<unsigned char>(resp.at(0)) != 0x02) {
        emit loginFailed(ErrBadResponse, errorMessage(ErrBadResponse));
        m_running.store(false);
        return;
    }
    const QByteArray seed = resp.mid(4, 4);
    m_assignedIp = resp.mid(20, 4);
    emit ipAssigned(ipToString(m_assignedIp));

    // 3. Login
    if (!interruptibleWait(200)) {           // 与官方客户端一致，等待 0.2 秒
        emit loginFailed(ErrUserTerminated, errorMessage(ErrUserTerminated));
        m_running.store(false);
        return;
    }
    const QByteArray loginPacket = buildLoginPacket(seed);
    socket.writeDatagram(loginPacket, server, m_cfg.port);

    if (!waitForPacket(socket, resp, 3000)) {
        emit loginFailed(m_stop.load() ? ErrUserTerminated : ErrTimeout,
                         errorMessage(m_stop.load() ? ErrUserTerminated : ErrTimeout));
        m_running.store(false);
        return;
    }
    const unsigned char r0 = static_cast<unsigned char>(resp.at(0));
    if (r0 != 0x04 && r0 != 0x05) {
        emit loginFailed(ErrBadResponse, errorMessage(ErrBadResponse));
        m_running.store(false);
        return;
    }
    if (r0 == 0x05) {
        const int code = (resp.size() > 4) ? static_cast<unsigned char>(resp.at(4)) : ErrUnknown;
        emit loginFailed(code, errorMessage(code));
        m_running.store(false);
        return;
    }
    const QByteArray authInfo = resp.mid(23, 16);

    // 登录成功：排空服务器可能积压的通知/文件报文
    drainSocket(socket);

    // 4. 进入心跳保活循环
    m_loggedIn = true;
    emit loginSucceeded(ipToString(m_assignedIp));

    int failedCycles = 0;
    while (!m_stop.load()) {
        const qint64 cycleStart = QDateTime::currentMSecsSinceEpoch();

        bool ok = doKeepalive1(socket, server, m_cfg.port, seed, authInfo);
        if (ok)
            ok = doKeepalive2(socket, server, m_cfg.port, authInfo);

        if (ok) {
            failedCycles = 0;
            // 保持 20 秒心跳周期（扣除本轮已耗时间）
            const qint64 elapsed = QDateTime::currentMSecsSinceEpoch() - cycleStart;
            const int remainMs = static_cast<int>(20000 - elapsed);
            if (remainMs > 0 && !interruptibleWait(remainMs))
                break;
        } else {
            if (m_stop.load())
                break;
            drainSocket(socket);          // 排空错乱报文后立即重试整个周期
            if (++failedCycles >= 2) {   // 连续 2 个完整周期失败才判定掉线
                emit connectionLost();
                m_running.store(false);
                return;
            }
        }
    }

    // 5. 主动注销：先 challenge 再发 80 字节注销包（尽力而为）
    if (m_loggedIn && m_stop.load())
        sendLogout(socket, server, m_cfg.port, seed, authInfo);

    emit loggedOut();
    m_running.store(false);
}

// ------------------------------------------------------------------
// 接收数据报：自动跳过服务器 0x4d 通知报文，直到收到目标报文或超时
// ------------------------------------------------------------------
bool DrcomClient::waitForPacket(QUdpSocket &sock, QByteArray &out, int timeoutMs, bool ignoreStop)
{
    const qint64 deadline = QDateTime::currentMSecsSinceEpoch() + timeoutMs;
    for (;;) {
        if (m_stop.load() && !ignoreStop)
            return false;
        const int remain = static_cast<int>(deadline - QDateTime::currentMSecsSinceEpoch());
        if (remain <= 0)
            return false;
        if (!sock.waitForReadyRead(qMin(remain, 3000)))
            return false;
        while (sock.hasPendingDatagrams()) {
            const qint64 n = sock.pendingDatagramSize();
            if (n <= 0)
                continue;
            QByteArray data(n, Qt::Uninitialized);
            const qint64 got = sock.readDatagram(data.data(), n);
            if (got <= 0)
                continue;
            data.resize(static_cast<int>(got));
            if (!data.isEmpty() && static_cast<unsigned char>(data.at(0)) == 0x4d)
                continue;               // 0x4d 为服务器通知报文，跳过
            out = data;
            return true;
        }
    }
}

bool DrcomClient::interruptibleWait(int ms)
{
    std::unique_lock<std::mutex> lock(m_mutex);
    return !m_cv.wait_for(lock, std::chrono::milliseconds(ms),
                          [this] { return m_stop.load(); });
}

// ------------------------------------------------------------------
// 构建登录报文（与现网可登录客户端逐字节对齐）
// ------------------------------------------------------------------
QByteArray DrcomClient::buildLoginPacket(const QByteArray &seed) const
{
    QByteArray user = m_account.toLatin1();
    if (user.size() > 36)
        user = user.left(36);                          // 用户名域固定 36 字节
    const QByteArray pass = m_pass16;                  // 已截断为 16 字节
    const int pwdLen = pass.size();
    const int uLen = user.size();

    const int pwdPad = pwdLen / 4;                     // 密码填充（与可登录客户端一致）
    const int total = 359 + pwdLen + pwdPad;           // 与可登录客户端封包长度一致

    QByteArray pkt(total, 0);

    // --- 头 + MD5A + 用户名 ---
    pkt[0] = static_cast<char>(0x03);
    pkt[1] = static_cast<char>(0x01);
    pkt[2] = static_cast<char>(0x00);
    pkt[3] = static_cast<char>(uLen + 20);

    QByteArray md5aIn;
    md5aIn.append(static_cast<char>(0x03)).append(static_cast<char>(0x01)).append(seed).append(pass);
    const QByteArray md5a = QCryptographicHash::hash(md5aIn, QCryptographicHash::Md5);
    pkt.replace(4, 16, md5a);
    pkt.replace(20, uLen, user);                       // 左对齐，其余保持 0

    // --- 控制字段（现网可登录客户端 adapterNum=0x03）---
    pkt[56] = static_cast<char>(m_cfg.controlCheckStatus);
    pkt[57] = static_cast<char>(m_cfg.adapterNum);

    // MAC xor MD5A[0..5]（大端）
    quint64 sum = 0;
    for (int i = 0; i < 6; ++i)
        sum = static_cast<quint64>(static_cast<unsigned char>(md5a.at(i))) + sum * 256;
    quint64 mac = 0;
    for (int i = 0; i < 6; ++i)
        mac = static_cast<quint64>(static_cast<unsigned char>(m_mac.at(i))) + mac * 256;
    sum ^= mac;
    QByteArray macXor(6, 0);
    for (int i = 6; i > 0; --i) {
        macXor[i - 1] = static_cast<char>(sum % 256);
        sum /= 256;
    }
    pkt.replace(58, 6, macXor);

    // --- MD5B = MD5(0x01 password seed 0x00*4) ---
    QByteArray md5bIn;
    md5bIn.append(static_cast<char>(0x01)).append(pass).append(seed).append(QByteArray(4, 0));
    const QByteArray md5b = QCryptographicHash::hash(md5bIn, QCryptographicHash::Md5);
    pkt.replace(64, 16, md5b);
    pkt[80] = static_cast<char>(0x01);                 // numOfIP=1
    pkt.replace(81, 4, m_assignedIp.size() == 4 ? m_assignedIp : QByteArray(4, 0));
    // [85..96] IP2/3/4 全零

    // --- checksum1 ---
    QByteArray cs1In = pkt.left(97);
    cs1In.append(static_cast<char>(0x14)).append(static_cast<char>(0x00))
         .append(static_cast<char>(0x07)).append(static_cast<char>(0x0b));
    const QByteArray cs1 = QCryptographicHash::hash(cs1In, QCryptographicHash::Md5);
    pkt.replace(97, 8, cs1.left(8));

    pkt[105] = static_cast<char>(m_cfg.ipDog);
    // [106..109] 全零

    // --- 主机名 32 字节左对齐 ---
    QByteArray hostName = m_cfg.hostName.toLatin1();
    if (hostName.size() > 32)
        hostName = hostName.left(32);
    pkt.replace(110, hostName.size(), hostName);

    pkt.replace(142, 4, ipToBytes(m_cfg.primaryDns));  // 首选 DNS 10.10.10.10
    // [146..161] DHCP 服务器 + 备用 DNS + 保留：保持 0

    // --- 固定操作系统信息（与可登录客户端一致） ---
    static const unsigned char osInfoSize[4] = { 0x94, 0x00, 0x00, 0x00 };
    static const unsigned char osMajor[4]   = { 0x06, 0x00, 0x00, 0x00 };
    static const unsigned char osMinor[4]   = { 0x02, 0x00, 0x00, 0x00 };
    static const unsigned char osBuild[4]   = { 0xf0, 0x23, 0x00, 0x00 };
    static const unsigned char platformId[4]= { 0x02, 0x00, 0x00, 0x00 };
    static const unsigned char hostBlock[9] = { 0x44, 0x72, 0x43, 0x4f, 0x4d, 0x00, 0xcf, 0x07, 0x68 };
    static const char servicePack[42]       = "3dc79f5212e8170acfa9ec95f1d749916542be7b1";
    pkt.replace(162, 4, reinterpret_cast<const char *>(osInfoSize));
    pkt.replace(166, 4, reinterpret_cast<const char *>(osMajor));
    pkt.replace(170, 4, reinterpret_cast<const char *>(osMinor));
    pkt.replace(174, 4, reinterpret_cast<const char *>(osBuild));
    pkt.replace(178, 4, reinterpret_cast<const char *>(platformId));
    pkt.replace(182, 9, reinterpret_cast<const char *>(hostBlock));
    pkt.replace(246, 41, servicePack);                 // 41 字节 ServicePack
    // [287..310] 24 字节 0

    // --- AUTH_VERSION（因 41 字节 servicePack 后移 1 字节，位于 [311..312]）---
    pkt[311] = static_cast<char>(m_cfg.authVersion[0]);   // 0x68
    pkt[312] = static_cast<char>(m_cfg.authVersion[1]);   // 0x00

    // --- 密码加密区 ---
    pkt[313] = static_cast<char>(0x00);
    pkt[314] = static_cast<char>(pwdLen);                  // 密码长度
    for (int i = 0; i < pwdLen; ++i) {
        const int x = static_cast<unsigned char>(md5a.at(i)) ^ static_cast<unsigned char>(pass.at(i));
        pkt[315 + i] = static_cast<char>((((x << 3) & 0xff) + (x >> 5)) & 0xff);
    }
    pkt[315 + pwdLen]     = static_cast<char>(0x02);
    pkt[316 + pwdLen]     = static_cast<char>(0x0c);

    // --- checksum2（与可登录客户端一致：逐 4 字节小端异或，余数忽略）---
    QByteArray cs2Buf = pkt.left(317 + pwdLen);           // [0..316+passLen]（到 0x02 0x0c 为止）
    cs2Buf.append(static_cast<char>(0x01)).append(static_cast<char>(0x26))
          .append(static_cast<char>(0x07)).append(static_cast<char>(0x11))
          .append(static_cast<char>(0x00)).append(static_cast<char>(0x00));
    cs2Buf.append(m_mac);                                 // 共 329+passLen 字节

    quint32 sum2 = 1234;
    int i = 0;
    const int len = cs2Buf.size();
    for (; i + 3 < len; i += 4) {
        const quint32 g = static_cast<quint32>(static_cast<unsigned char>(cs2Buf.at(i)))
                        | (static_cast<quint32>(static_cast<unsigned char>(cs2Buf.at(i + 1))) << 8)
                        | (static_cast<quint32>(static_cast<unsigned char>(cs2Buf.at(i + 2))) << 16)
                        | (static_cast<quint32>(static_cast<unsigned char>(cs2Buf.at(i + 3))) << 24);
        sum2 ^= g;
    }
    // 余数（1..3 字节）忽略 —— 与现网可登录客户端一致
    sum2 = (1968 * sum2) & 0xffffffffULL;
    for (int j = 0; j < 4; ++j)
        pkt[317 + pwdLen + j] = static_cast<char>((sum2 >> (j * 8)) & 0xff);

    // --- 尾部：00 00 + MAC + passLen/4 个 0 + 0x60 0xa2 + 28 字节 0 ---
    pkt[321 + pwdLen] = static_cast<char>(0x00);
    pkt[322 + pwdLen] = static_cast<char>(0x00);
    pkt.replace(323 + pwdLen, 6, m_mac);
    pkt[329 + pwdLen + pwdPad]     = static_cast<char>(0x60);
    pkt[329 + pwdLen + pwdPad + 1] = static_cast<char>(0xa2);
    // 其余（含 28 字节 0）已由初始化置 0

    return pkt;
}

// ------------------------------------------------------------------
// 心跳 keep38（38 字节，与可登录客户端一致；3 次尝试，每次刷新时间戳）
// ------------------------------------------------------------------
bool DrcomClient::doKeepalive1(QUdpSocket &sock, const QHostAddress &server,
                               quint16 port, const QByteArray &seed,
                               const QByteArray &authInfo)
{
    QByteArray md5aIn;
    md5aIn.append(static_cast<char>(0x03)).append(static_cast<char>(0x01))
          .append(seed).append(m_pass16);
    const QByteArray md5a = QCryptographicHash::hash(md5aIn, QCryptographicHash::Md5);

    QByteArray p(38, 0);
    p[0] = static_cast<char>(0xff);
    p.replace(1, 16, md5a);
    p.replace(20, 16, authInfo);       // 登录成功回包的 tail1[0..15]

    // 3 次尝试（每次刷新时间戳），短暂网络抖动可当场恢复
    for (int attempt = 0; attempt < 3 && !m_stop.load(); ++attempt) {
        const quint16 foo = static_cast<quint16>(QDateTime::currentSecsSinceEpoch() % 0xffff);
        p[36] = static_cast<char>((foo >> 8) & 0xff);
        p[37] = static_cast<char>(foo & 0xff);
        sock.writeDatagram(p, server, port);

        QByteArray resp;
        if (waitForPacket(sock, resp, 3000) && !resp.isEmpty()
            && static_cast<unsigned char>(resp.at(0)) == 0x07)
            return true;
        if (m_stop.load())
            return false;
        interruptibleWait(1000);
    }
    return false;
}

// ------------------------------------------------------------------
// 心跳 keep40 阶段：首轮 extra → keep40_1(type1) → keep40_2(type3)
// ------------------------------------------------------------------
bool DrcomClient::doKeepalive2(QUdpSocket &sock, const QHostAddress &server,
                               quint16 port, const QByteArray &authInfo)
{
    if (!interruptibleWait(200))           // 与 keep38 间隔 0.2 秒
        return false;

    // 首轮：extra 握手（0f27；收到 0x10 文件确认时递增序号、换 dc02 重发）
    if (m_keep40First) {
        if (!doInitialExtra(sock, server, port))
            return false;
    }

    // keep40_1（type1）：首个周期携带零尾码，之后携带 authInfo 前 4 字节
    const QByteArray t1 = m_keep40PairDone
        ? (authInfo.size() >= 4 ? authInfo.left(4) : QByteArray(4, 0))
        : QByteArray(4, 0);
    if (!exchangeKeep40(sock, server, port, 1, t1, false))
        return false;

    // keep40_2（type3）：携带上一步尾码 + IP@28
    if (!exchangeKeep40(sock, server, port, 3, m_keep40Tail, true))
        return false;

    m_keep40PairDone = true;
    return true;
}

// 首轮 extra 握手：首发 0f27；超时/异常/0x10 文件确认均以 dc02 重发
bool DrcomClient::doInitialExtra(QUdpSocket &sock, const QHostAddress &server, quint16 port)
{
    bool useExtraVer = true;
    for (int attempt = 0; attempt < 6 && !m_stop.load(); ++attempt) {
        const QByteArray pkt = buildKeep40Packet(1, useExtraVer, QByteArray(4, 0));
        sock.writeDatagram(pkt, server, port);

        QByteArray resp;
        if (!waitForPacket(sock, resp, 3000)) {
            useExtraVer = false;
            continue;
        }
        if (resp.size() < 3 || static_cast<unsigned char>(resp.at(0)) != 0x07) {
            useExtraVer = false;
            continue;
        }
        if (static_cast<unsigned char>(resp.at(2)) == 0x10) {
            // 服务器文件确认：序号前进，以 dc02 重发
            m_keep40Seq = static_cast<unsigned char>((m_keep40Seq + 1) & 0xff);
            useExtraVer = false;
            continue;
        }
        // 正常响应：extra 完成（后续 type1 复用当前序号）
        if (resp.size() >= 20)
            m_keep40Tail = resp.mid(16, 4);
        m_keep40First = false;
        return true;
    }
    return false;
}

// 单个 keep40 报文的收发：3 次尝试，成功后推进序号并保存尾码
bool DrcomClient::exchangeKeep40(QUdpSocket &sock, const QHostAddress &server,
                                 quint16 port, int type,
                                 const QByteArray &tail4, bool withIp)
{
    for (int attempt = 0; attempt < 3 && !m_stop.load(); ++attempt) {
        QByteArray pkt = buildKeep40Packet(type, false, tail4);
        if (withIp)
            pkt.replace(28, 4, m_assignedIp.size() == 4 ? m_assignedIp : QByteArray(4, 0));
        sock.writeDatagram(pkt, server, port);

        QByteArray resp;
        if (waitForPacket(sock, resp, 3000) && resp.size() >= 20
            && static_cast<unsigned char>(resp.at(0)) == 0x07) {
            m_keep40Tail = resp.mid(16, 4);
            m_keep40Seq = static_cast<unsigned char>((m_keep40Seq + 1) & 0xff);
            return true;
        }
        if (m_stop.load())
            return false;
        interruptibleWait(1000);
    }
    return false;
}

// 非阻塞排空 socket 中积压的数据报（登录后、周期失败后使用）
void DrcomClient::drainSocket(QUdpSocket &sock)
{
    while (!m_stop.load() && sock.waitForReadyRead(0)) {
        while (sock.hasPendingDatagrams()) {
            const qint64 n = sock.pendingDatagramSize();
            sock.readDatagram(nullptr, 0);
            (void)n;
        }
    }
}

QByteArray DrcomClient::buildKeep40Packet(int type, bool isExtra, const QByteArray &tail4)
{
    QByteArray pkt(40, 0);
    pkt[0] = static_cast<char>(0x07);
    pkt[1] = static_cast<char>(m_keep40Seq & 0xff);
    pkt[2] = static_cast<char>(0x28);
    pkt[4] = static_cast<char>(0x0b);
    pkt[5] = static_cast<char>(type);
    if (isExtra) {
        pkt[6] = static_cast<char>(0x0f);
        pkt[7] = static_cast<char>(0x27);
    } else {
        pkt[6] = static_cast<char>(m_cfg.keepAliveVersion[0]);   // 0xdc
        pkt[7] = static_cast<char>(m_cfg.keepAliveVersion[1]);   // 0x02
    }
    pkt[8] = static_cast<char>(0x2f);
    pkt[9] = static_cast<char>(0x12);
    if (tail4.size() >= 4)
        pkt.replace(16, 4, tail4);
    return pkt;
}

// ------------------------------------------------------------------
// 注销：先 challenge 取新 salt，再发 80 字节注销包（尽力而为）
// ------------------------------------------------------------------
void DrcomClient::sendLogout(QUdpSocket &sock, const QHostAddress &server, quint16 port,
                             const QByteArray &seed, const QByteArray &authInfo)
{
    Q_UNUSED(seed)

    // 1) challenge（重新生成随机数，[4]=0x09 与登录一致）
    const unsigned char r1 = static_cast<unsigned char>(QRandomGenerator::global()->bounded(256));
    const unsigned char r2 = static_cast<unsigned char>(QRandomGenerator::global()->bounded(256));
    QByteArray chal(20, 0);
    chal[0] = static_cast<char>(0x01);
    chal[1] = static_cast<char>(m_challengeTimes & 0xff);
    chal[2] = static_cast<char>(r1);
    chal[3] = static_cast<char>(r2);
    chal[4] = static_cast<char>(0x09);
    ++m_challengeTimes;
    sock.writeDatagram(chal, server, port);

    QByteArray resp;
    if (!waitForPacket(sock, resp, 1000, true))     // 注销阶段允许无视 m_stop 继续等待
        return;
    if (resp.size() < 4 || static_cast<unsigned char>(resp.at(0)) != 0x02)
        return;
    const QByteArray salt = resp.mid(4, 4);

    // 2) 80 字节注销包
    QByteArray md5In;
    md5In.append(static_cast<char>(0x06)).append(static_cast<char>(0x01))
          .append(salt).append(m_pass16);
    const QByteArray md = QCryptographicHash::hash(md5In, QCryptographicHash::Md5);

    QByteArray p(80, 0);
    p[0] = static_cast<char>(0x06);
    p[1] = static_cast<char>(0x01);
    p[2] = static_cast<char>(0x00);
    p[3] = static_cast<char>(m_account.toLatin1().size() + 20);
    p.replace(4, 16, md);
    QByteArray user = m_account.toLatin1();
    if (user.size() > 36)
        user = user.left(36);
    p.replace(20, user.size(), user);
    p[56] = static_cast<char>(0x20);
    p[57] = static_cast<char>(m_cfg.adapterNum);     // 0x03，与登录一致

    quint64 s = 0;
    for (int i = 0; i < 6; ++i)
        s = static_cast<quint64>(static_cast<unsigned char>(md.at(i))) + s * 256;
    quint64 mac = 0;
    for (int i = 0; i < 6; ++i)
        mac = static_cast<quint64>(static_cast<unsigned char>(m_mac.at(i))) + mac * 256;
    s ^= mac;
    QByteArray xor6(6, 0);
    for (int i = 6; i > 0; --i) {
        xor6[i - 1] = static_cast<char>(s % 256);
        s /= 256;
    }
    p.replace(58, 6, xor6);
    p.replace(64, 16, authInfo);                   // tail1[0..15]

    sock.writeDatagram(p, server, port);
    waitForPacket(sock, resp, 1000, true);         // 接收 0x04（尽力而为）
}

QByteArray DrcomClient::ipToBytes(const QString &ip)
{
    const QHostAddress addr(ip);
    if (addr.isNull() || addr.protocol() != QAbstractSocket::IPv4Protocol)
        return QByteArray(4, 0);
    const quint32 v = addr.toIPv4Address();
    QByteArray out(4, 0);
    out[0] = static_cast<char>((v >> 24) & 0xff);
    out[1] = static_cast<char>((v >> 16) & 0xff);
    out[2] = static_cast<char>((v >> 8) & 0xff);
    out[3] = static_cast<char>(v & 0xff);
    return out;
}

QString DrcomClient::ipToString(const QByteArray &ip)
{
    if (ip.size() < 4)
        return QStringLiteral("0.0.0.0");
    return QString::asprintf("%d.%d.%d.%d",
                             static_cast<unsigned char>(ip.at(0)),
                             static_cast<unsigned char>(ip.at(1)),
                             static_cast<unsigned char>(ip.at(2)),
                             static_cast<unsigned char>(ip.at(3)));
}
