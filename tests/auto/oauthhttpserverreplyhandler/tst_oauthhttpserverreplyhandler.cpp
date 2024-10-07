// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

#include <QtNetworkAuth/qoauthhttpserverreplyhandler.h>

#include <QtCore>
#include <QtTest>
#include <QtNetwork>

typedef QSharedPointer<QNetworkReply> QNetworkReplyPtr;

static constexpr std::chrono::seconds Timeout(20);

using namespace Qt::StringLiterals;

class tst_QOAuthHttpServerReplyHandler : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void callback_data();
    void callback();
    void callbackCaching();
    void callbackWithQuery();
    void badCallbackUris_data();
    void badCallbackUris();
    void badCallbackWrongMethod();
    void callbackDataReceived_data();
    void callbackDataReceived();
#ifndef QT_NO_SSL
    void localhostHttps();
#endif

private:
    QString testDataDir;
    [[nodiscard]] auto useTemporaryKeychain()
    {
#ifndef QT_NO_SSL
        // Set the same environment value as CI uses, so that it's possible
        // to run autotests locally without macOS asking for permission to use
        // a private key in keychain (with TLS sockets)
        auto value = qEnvironmentVariable("QT_SSL_USE_TEMPORARY_KEYCHAIN");
        qputenv("QT_SSL_USE_TEMPORARY_KEYCHAIN", "1");
        auto envRollback = qScopeGuard([value](){
            if (value.isEmpty())
                qunsetenv("QT_SSL_USE_TEMPORARY_KEYCHAIN");
            else
                qputenv("QT_SSL_USE_TEMPORARY_KEYCHAIN", value.toUtf8());
        });
        return envRollback;
#else
        // avoid maybe-unused warnings from callers
        return qScopeGuard([]{});
#endif // QT_NO_SSL
    }
};

void tst_QOAuthHttpServerReplyHandler::initTestCase()
{
    testDataDir = QFileInfo(QFINDTESTDATA("certs")).absolutePath();
    if (testDataDir.isEmpty())
        testDataDir = QCoreApplication::applicationDirPath();
    if (!testDataDir.endsWith(QLatin1String("/")))
        testDataDir += QLatin1String("/");
}

void tst_QOAuthHttpServerReplyHandler::callback_data()
{
    QTest::addColumn<QString>("callbackPath");
    QTest::addColumn<QString>("uri");
    QTest::addColumn<bool>("success");

    QTest::newRow("default") << QString() << QString() << true;
    QTest::newRow("empty") << "" << QString() << true;
    QTest::newRow("ascii-path") << "/foobar" << QString() << true;
    QTest::newRow("utf8-path") << "/áéíóú" << QString() << true;
    QTest::newRow("questionmark") << "/?" << QString() << true;
    QTest::newRow("hash") << "/#" << QString() << true;

    QTest::newRow("default-fragment") << QString() << "/#shouldntsee" << true;
    QTest::newRow("default-query") << QString() << "/?some=query" << true;

    QTest::newRow("default-wrongpath") << QString() << "/foo" << false;
    QTest::newRow("changed-wrongpath") << "/foo" << "/bar" << false;
    QTest::newRow("changed-wrongpathprefix") << "/foo" << "/foobar" << false;
    QTest::newRow("changed-wrongpathprefixpath") << "/foo" << "/foo/bar" << false;
}

void tst_QOAuthHttpServerReplyHandler::callback()
{
    QFETCH(QString, callbackPath);
    QFETCH(QString, uri);
    QFETCH(bool, success);

    int count = 0;
    QOAuthHttpServerReplyHandler replyHandler;
    QVERIFY(replyHandler.isListening());
    connect(&replyHandler, &QOAuthHttpServerReplyHandler::callbackReceived, this, [&](
            const QVariantMap &) {
        ++count;
        QTestEventLoop::instance().exitLoop();
    });

    if (!callbackPath.isNull())
        replyHandler.setCallbackPath(callbackPath);
    QUrl callback(replyHandler.callback());
    QVERIFY(!callback.isEmpty());

    // maybe change the URL
    callback = callback.resolved(QUrl(uri));

    QNetworkAccessManager networkAccessManager;
    QNetworkRequest request(callback);
    QNetworkReplyPtr reply;
    reply.reset(networkAccessManager.get(request));
    connect(reply.get(), &QNetworkReply::finished, &QTestEventLoop::instance(),
            &QTestEventLoop::exitLoop);

    if (!success) {
        QByteArray httpUri = callback.toEncoded(QUrl::RemoveScheme | QUrl::RemoveAuthority | QUrl::RemoveFragment);
        QTest::ignoreMessage(QtWarningMsg, "Invalid request: " + httpUri);
        QTest::ignoreMessage(QtWarningMsg, "Invalid request: " + httpUri);
    }
    QTestEventLoop::instance().enterLoop(Timeout);
    QCOMPARE(count > 0, success);
    QVERIFY(!QTestEventLoop::instance().timeout());
}

void tst_QOAuthHttpServerReplyHandler::callbackCaching()
{
    QOAuthHttpServerReplyHandler replyHandler;
    constexpr auto callbackPath = "/foo"_L1;
    constexpr auto callbackHost = "localhost"_L1;

    QVERIFY(replyHandler.isListening());
    replyHandler.setCallbackPath(callbackPath);
    QUrl callback = replyHandler.callback();
    QCOMPARE(callback.path(), callbackPath);
    QCOMPARE(callback.host(), callbackHost);

    replyHandler.close();
    QVERIFY(!replyHandler.isListening());
    callback = replyHandler.callback();
    // Should remain after close
    QCOMPARE(callback.path(), callbackPath);
    QCOMPARE(callback.host(), callbackHost);

    replyHandler.listen();
    QVERIFY(replyHandler.isListening());
    callback = replyHandler.callback();
    QCOMPARE(callback.path(), callbackPath);
    QCOMPARE(callback.host(), callbackHost);
}

void tst_QOAuthHttpServerReplyHandler::callbackWithQuery()
{
    int count = 0;
    QOAuthHttpServerReplyHandler replyHandler;
    QUrlQuery query("callback=test");
    QVERIFY(replyHandler.isListening());
    QUrl callback(replyHandler.callback());
    QVERIFY(!callback.isEmpty());
    callback.setQuery(query);

    connect(&replyHandler, &QOAuthHttpServerReplyHandler::callbackReceived, this, [&](
            const QVariantMap &parameters) {
        for (auto item : query.queryItems()) {
            QVERIFY(parameters.contains(item.first));
            QCOMPARE(parameters[item.first].toString(), item.second);
        }
        count = parameters.size();
        QTestEventLoop::instance().exitLoop();
    });

    QNetworkAccessManager networkAccessManager;
    QNetworkRequest request;
    request.setUrl(callback);
    QNetworkReplyPtr reply;
    reply.reset(networkAccessManager.get(request));
    connect(reply.get(), &QNetworkReply::finished, &QTestEventLoop::instance(),
            &QTestEventLoop::exitLoop);
    QTestEventLoop::instance().enterLoop(Timeout);
    QCOMPARE(count, query.queryItems().size());
    QVERIFY(!QTestEventLoop::instance().timeout());
}

void tst_QOAuthHttpServerReplyHandler::badCallbackUris_data()
{
    QTest::addColumn<QString>("uri");

    QTest::newRow("relative-path") << "foobar";
    QTest::newRow("encoded-slash") << "%2F";
    QTest::newRow("query") << "?some=query";
    QTest::newRow("full-url") << "http://localhost/";
    QTest::newRow("authority") << "//localhost";
    // requires QUrl fix
    //QTest::newRow("double-slash") << "//";
    //QTest::newRow("triple-slash") << "///";
}

void tst_QOAuthHttpServerReplyHandler::badCallbackUris()
{
    QFETCH(QString, uri);

    int count = 0;
    QOAuthHttpServerReplyHandler replyHandler;
    QVERIFY(replyHandler.isListening());
    connect(&replyHandler, &QOAuthHttpServerReplyHandler::callbackReceived, this, [&](
            const QVariantMap &) {
        ++count;
        QTestEventLoop::instance().exitLoop();
    });
    QUrl callback(replyHandler.callback());
    QVERIFY(!callback.isEmpty());

    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, replyHandler.port());
    socket.write("GET " + uri.toLocal8Bit() + " HTTP/1.0\r\n"
                 "Host: localhost\r\n"
                 "\r\n");
    connect(&socket, &QTcpSocket::disconnected, &QTestEventLoop::instance(),
            &QTestEventLoop::exitLoop);

    QTest::ignoreMessage(QtWarningMsg, "Invalid request: " + uri.toLocal8Bit());
    QTest::ignoreMessage(QtWarningMsg, "Invalid URL");

    QTestEventLoop::instance().enterLoop(Timeout);
    QCOMPARE(count, 0);
    QVERIFY(!QTestEventLoop::instance().timeout());
}

void tst_QOAuthHttpServerReplyHandler::badCallbackWrongMethod()
{
    int count = 0;
    QOAuthHttpServerReplyHandler replyHandler;
    QVERIFY(replyHandler.isListening());
    connect(&replyHandler, &QOAuthHttpServerReplyHandler::callbackReceived, this, [&](
            const QVariantMap &) {
        ++count;
        QTestEventLoop::instance().exitLoop();
    });
    QUrl callback(replyHandler.callback());
    QVERIFY(!callback.isEmpty());

    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, replyHandler.port());
    socket.write("EHLO localhost\r\n");
    connect(&socket, &QTcpSocket::disconnected, &QTestEventLoop::instance(),
            &QTestEventLoop::exitLoop);

    QTest::ignoreMessage(QtWarningMsg, "Invalid operation EHLO");
    QTest::ignoreMessage(QtWarningMsg, "Invalid Method");

    QTestEventLoop::instance().enterLoop(Timeout);
    QCOMPARE(count, 0);
    QVERIFY(!QTestEventLoop::instance().timeout());
}

void tst_QOAuthHttpServerReplyHandler::callbackDataReceived_data()
{
    QTest::addColumn<QString>("redirect_response_data");

    QTest::addRow("no_data") << u""_s;
    QTest::addRow("query_parameters") << u"?k1=v1"_s;
}

void tst_QOAuthHttpServerReplyHandler::callbackDataReceived()
{
    QFETCH(const QString, redirect_response_data);

    QOAuthHttpServerReplyHandler replyHandler;
    QSignalSpy spy(&replyHandler, &QOAuthHttpServerReplyHandler::callbackDataReceived);
    QVERIFY(replyHandler.isListening());

    QString expected_response_data = replyHandler.callback() + redirect_response_data;

    QNetworkAccessManager networkAccessManager;
    QNetworkRequest request(expected_response_data);
    QNetworkReplyPtr reply;

    reply.reset(networkAccessManager.get(request));

    QTRY_COMPARE(spy.size(), 1);
    QCOMPARE(spy.at(0).at(0).toByteArray(), expected_response_data.toLatin1());
}

#ifndef QT_NO_SSL
static QSslConfiguration createSslConfiguration(QString keyFileName, QString certificateFileName)
{
    QSslConfiguration configuration(QSslConfiguration::defaultConfiguration());

    QFile keyFile(keyFileName);
    if (keyFile.open(QIODevice::ReadOnly)) {
        QSslKey key(keyFile.readAll(), QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
        if (!key.isNull()) {
            configuration.setPrivateKey(key);
        } else {
            qCritical() << "Could not parse key: " << keyFileName;
        }
    } else {
        qCritical() << "Could not find key: " << keyFileName;
    }

    QList<QSslCertificate> localCert = QSslCertificate::fromPath(certificateFileName);
    if (!localCert.isEmpty() && !localCert.first().isNull()) {
        configuration.setLocalCertificate(localCert.first());
    } else {
        qCritical() << "Could not find certificate: " << certificateFileName;
    }
    return configuration;
}

void tst_QOAuthHttpServerReplyHandler::localhostHttps()
{
    if (!QSslSocket::supportsSsl())
        QSKIP("This test will fail because the backend does not support TLS");

    auto rollback = useTemporaryKeychain();

    // erros may vary, depending on backend
    const QSet<QSslError::SslError> expectedSslErrors{ QSslError::SelfSignedCertificate,
                                                       QSslError::CertificateUntrusted,
                                                       QSslError::HostNameMismatch };
    auto serverConfig = createSslConfiguration(testDataDir + "certs/selfsigned-server.key",
                                               testDataDir + "certs/selfsigned-server.crt");

    QOAuthHttpServerReplyHandler replyHandler;
    replyHandler.setCallbackPath(u"/callback"_s);

    // Initially the handler is a plain 'http' handler
    QVERIFY(replyHandler.isListening());
    QCOMPARE(QUrl(replyHandler.callback()).scheme(), u"http"_s);

    // Calling listen() with SSL configuration makes handler to use 'https'
    QVERIFY(replyHandler.listen(serverConfig));
    QVERIFY(replyHandler.isListening());
    const QUrl redirectUrl = replyHandler.callback() + u"?state=somestate&code=somecode"_s;
    QCOMPARE(redirectUrl.scheme(), u"https"_s);

    // Issue a HTTP GET to the handler's server to mimic OAuth2 redirection event
    QSignalSpy spy(&replyHandler, &QOAuthHttpServerReplyHandler::callbackReceived);
    QNetworkAccessManager networkAccessManager;
    QNetworkRequest networkRequest(redirectUrl);
    QNetworkReplyPtr reply;

    connect(&networkAccessManager, &QNetworkAccessManager::sslErrors, this,
            [&expectedSslErrors](QNetworkReply *reply, const QList<QSslError> &errors) {
        for (const auto &error : errors)
            QVERIFY(expectedSslErrors.contains(error.error()));
        reply->ignoreSslErrors();
    });

    reply.reset(networkAccessManager.get(networkRequest));
    QTRY_COMPARE(spy.size(), 1);
    const auto parameters = spy.at(0).at(0).toMap();
    QCOMPARE(parameters["state"_L1].toString(), u"somestate"_s);
    QCOMPARE(parameters["code"_L1].toString(), u"somecode"_s);

    // Call listen with invalid SSL configuration
    QTest::ignoreMessage(QtWarningMsg, "QSslConfiguration is null, cannot listen");
    QVERIFY(!replyHandler.listen(QSslConfiguration{}));
    QVERIFY(!replyHandler.isListening());

    // Call listen() without SSL configuration and verify it uses plain 'http' again
    QVERIFY(replyHandler.listen());
    QVERIFY(replyHandler.isListening());
    QCOMPARE(QUrl(replyHandler.callback()).scheme(), u"http"_s);
}
#endif // QT_NO_SSL


QTEST_MAIN(tst_QOAuthHttpServerReplyHandler)
#include "tst_oauthhttpserverreplyhandler.moc"
