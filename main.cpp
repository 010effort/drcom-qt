#include "Drcom.h"
#include <QtWidgets/QApplication>
#include <QFont>
#include <QFile>

int main(int argc, char *argv[])
{
    // 高分屏支持
    QApplication::setHighDpiScaleFactorRoundingPolicy(
        Qt::HighDpiScaleFactorRoundingPolicy::PassThrough);

    QApplication app(argc, argv);
    QApplication::setOrganizationName(QStringLiteral("JLU"));
    QApplication::setApplicationName(QStringLiteral("DrcomJLU"));
    QApplication::setApplicationDisplayName(QStringLiteral("吉林大学校园网认证客户端"));

    // 界面字体
    QFont font(QStringLiteral("Microsoft YaHei UI"), 10);
    app.setFont(font);

    // 加载样式表
    QFile qss(QStringLiteral(":/Drcom/style.qss"));
    if (qss.open(QIODevice::ReadOnly | QIODevice::Text))
        app.setStyleSheet(QString::fromUtf8(qss.readAll()));

    Drcom window;
    window.show();
    return app.exec();
}
