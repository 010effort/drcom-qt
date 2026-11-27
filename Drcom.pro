# 吉林大学校园网认证客户端 (Dr.COM)
# 可用 qmake 构建：qmake Drcom.pro && nmake（MSVC）或 mingw32-make（MinGW）
QT += core gui widgets network

CONFIG += c++17
CONFIG -= app_bundle

TARGET = DrcomJLU
TEMPLATE = app

DEFINES += QT_DEPRECATED_WARNINGS

SOURCES += \
    main.cpp \
    Drcom.cpp \
    DrcomClient.cpp \
    NavDialog.cpp

HEADERS += \
    Drcom.h \
    DrcomClient.h \
    NavDialog.h

FORMS += \
    Drcom.ui

RESOURCES += \
    Drcom.qrc

RC_ICONS = app.ico
