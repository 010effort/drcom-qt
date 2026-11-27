#pragma once

#include <QDialog>

class QPushButton;

// 吉林大学校园常用网址导航（独立对话框）
class NavDialog : public QDialog
{
    Q_OBJECT

public:
    explicit NavDialog(QWidget *parent = nullptr);

private:
    void addSection(const QString &title, const QList<QPair<QString, QString>> &links);
    QPushButton *makeLinkButton(const QString &name, const QString &url);
    void openUrl(const QString &url);
};
