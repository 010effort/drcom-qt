#include "NavDialog.h"

#include <QPushButton>
#include <QGroupBox>
#include <QGridLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QDesktopServices>
#include <QUrl>
#include <QToolTip>

NavDialog::NavDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(QStringLiteral("吉林大学校园网址导航"));
    setMinimumWidth(560);

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(20, 18, 20, 16);
    root->setSpacing(12);

    auto *title = new QLabel(QStringLiteral("吉林大学校园常用网址导航"), this);
    title->setObjectName(QStringLiteral("navTitle"));
    auto *sub = new QLabel(QStringLiteral("点击名称用默认浏览器打开（校内站点需连接校园网）"), this);
    sub->setObjectName(QStringLiteral("navSub"));
    root->addWidget(title);
    root->addWidget(sub);

    // 校园网络与服务（含校园网之窗）
    addSection(QStringLiteral("校园网络与服务"), {
        { QStringLiteral("校园网之窗"),  QStringLiteral("http://login.jlu.edu.cn/notice.php") },
        { QStringLiteral("大数据和网络管理中心"), QStringLiteral("https://nic.jlu.edu.cn") },
        { QStringLiteral("校园网认证客户端下载"), QStringLiteral("http://login.jlu.edu.cn") },
        { QStringLiteral("无线校园网"), QStringLiteral("https://wifi.jlu.edu.cn") },
        { QStringLiteral("上网自助服务平台"), QStringLiteral("http://ip.jlu.edu.cn/pay/") },
    });

    // 综合门户
    addSection(QStringLiteral("综合门户"), {
        { QStringLiteral("吉林大学官网"), QStringLiteral("https://www.jlu.edu.cn") },
        { QStringLiteral("网上办事大厅"), QStringLiteral("https://ehall.jlu.edu.cn") },
        { QStringLiteral("校内办公网"), QStringLiteral("https://oa.jlu.edu.cn") },
        { QStringLiteral("电子邮件"), QStringLiteral("https://mail.jlu.edu.cn") },
        { QStringLiteral("校外访问 VPN"), QStringLiteral("https://webvpn.jlu.edu.cn/login") },
    });

    // 教学科研
    addSection(QStringLiteral("教学科研"), {
        { QStringLiteral("教务管理系统"), QStringLiteral("https://iedu.jlu.edu.cn") },
        { QStringLiteral("本科生选课平台"), QStringLiteral("https://icourses.jlu.edu.cn") },
        { QStringLiteral("图书馆"), QStringLiteral("https://lib.jlu.edu.cn") },
        { QStringLiteral("研究生院"), QStringLiteral("https://yjsy.jlu.edu.cn") },
        { QStringLiteral("研究生教育管理系统"), QStringLiteral("http://gim.jlu.edu.cn") },
        { QStringLiteral("智慧学工"), QStringLiteral("https://zhxg.jlu.edu.cn") },
        { QStringLiteral("学生工作部"), QStringLiteral("http://xsc.jlu.edu.cn") },
    });

    // 生活服务
    addSection(QStringLiteral("生活服务"), {
        { QStringLiteral("校园卡"), QStringLiteral("https://xyk.jlu.edu.cn") },
        { QStringLiteral("一卡通网上自助平台"), QStringLiteral("http://dsf.jlu.edu.cn") },
    });

    root->addStretch();
}

void NavDialog::addSection(const QString &title, const QList<QPair<QString, QString>> &links)
{
    auto *box = new QGroupBox(title, this);
    auto *grid = new QGridLayout(box);
    grid->setContentsMargins(12, 14, 12, 12);
    grid->setSpacing(8);

    const int cols = 3;
    for (int i = 0; i < links.size(); ++i) {
        auto *btn = makeLinkButton(links.at(i).first, links.at(i).second);
        grid->addWidget(btn, i / cols, i % cols);
    }
    static_cast<QVBoxLayout *>(layout())->addWidget(box);
}

QPushButton *NavDialog::makeLinkButton(const QString &name, const QString &url)
{
    auto *btn = new QPushButton(name, this);
    btn->setProperty("navUrl", url);
    btn->setToolTip(url);
    btn->setCursor(Qt::PointingHandCursor);
    connect(btn, &QPushButton::clicked, this, [this, url] { openUrl(url); });
    return btn;
}

void NavDialog::openUrl(const QString &url)
{
    QDesktopServices::openUrl(QUrl(url));
}
