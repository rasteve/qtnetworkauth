// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

#include <QtNetwork/qtnetwork-config.h>

#ifndef QT_NO_HTTP

#include <qabstractoauth2.h>
#include <private/qabstractoauth2_p.h>

#include <QtCore/qurl.h>
#include <QtCore/qurlquery.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qmessageauthenticationcode.h>

#include <QtNetwork/qnetworkreply.h>
#include <QtNetwork/qnetworkrequest.h>
#include <QtNetwork/qnetworkaccessmanager.h>
#include <QtNetwork/qhttpmultipart.h>

#ifndef QT_NO_SSL
#include <QtNetwork/qsslconfiguration.h>
#endif

QT_BEGIN_NAMESPACE

using namespace Qt::StringLiterals;

/*!
    \class QAbstractOAuth2
    \inmodule QtNetworkAuth
    \ingroup oauth
    \brief The QAbstractOAuth2 class is the base of all
    implementations of OAuth 2 authentication methods.
    \since 5.8

    The class defines the basic interface of the OAuth 2
    authentication classes. By inheriting this class, you
    can create custom authentication methods using the OAuth 2
    standard for different web services.

    A description of how OAuth 2 works can be found in:
    \l {https://tools.ietf.org/html/rfc6749}{The OAuth 2.0
    Authorization Framework}
*/

/*!
    \page oauth-http-method-alternatives
    \title OAuth2 HTTP method alternatives
    \brief This page provides alternatives for QtNetworkAuth
    OAuth2 HTTP methods.

    QtNetworkAuth provides HTTP Methods such as \l {QAbstractOAuth::get()}
    for issuing authenticated requests. In the case of OAuth2,
    this typically means setting the
    \l {QHttpHeaders::WellKnownHeader}{Authorization} header, as
    specified in \l {https://datatracker.ietf.org/doc/html/rfc6750#section-2.1}
    {RFC 6750}.

    Since this operation is straightforward to do, it is better to use
    the normal QtNetwork HTTP method APIs directly, and set this header
    manually. These QtNetwork APIs have less assumptions on the message
    content types and provide a broader set of APIs.

    See \l QRestAccessManager, \l QNetworkAccessManager, QNetworkRequest,
    QNetworkRequestFactory.

    \section1 QNetworkRequest

    The needed \e Authorization header can be set directly on each
    request needing authorization.

    \code
    using namespace Qt::StringLiterals;

    QOAuth2AuthorizationCodeFlow m_oauth;
    QNetworkRequest request;

    QHttpHeaders headers;
    headers.append(QHttpHeaders::WellKnownHeader::Authorization, u"Bearer "_s + m_oauth.token());
    request.setHeaders(headers);
    \endcode

    After setting the header, use the request normally with either
    \l QRestAccessManager or \l QNetworkAccessManager.

    \section1 QNetworkRequestFactory

    QNetworkRequestFactory is a convenience class introduced in Qt 6.7.
    It provides a suitable method for this task:
    \l {QNetworkRequestFactory::setBearerToken()}, as illustrated
    by the code below.

    \code
    QNetworkRequestFactory m_api({"https://www.example.com/v3"});
    QOAuth2AuthorizationCodeFlow m_oauth;
    // ...
    connect(&m_oauth, &QOAuth2AuthorizationCodeFlow::granted, this, [this]{
        m_api.setBearerToken(m_oauth.token().toLatin1());
    });
    \endcode

    After setting the bearer token, use the request factory normally
    with either \l QRestAccessManager or \l QNetworkAccessManager.
*/

#if QT_DEPRECATED_SINCE(6, 11)
/*!
    \deprecated [6.11] Use requestedScope and grantedScope properties instead.
    \property QAbstractOAuth2::scope
    \brief This property holds the desired scope which defines the
    permissions requested by the client.

    The scope value is updated to the scope value granted by the
    authorization server. In case of an empty scope response, the
    \l {https://datatracker.ietf.org/doc/html/rfc6749#section-5.1}
    {requested scope is assumed as granted and does not change}.

    The fact that this property serves two different roles, first
    as the requested scope and later as the granted scope, is an historical
    artefact. All new code is recommended to use
    \l QAbstractOAuth2::requestedScope and \l QAbstractOAuth2::grantedScope.

    \sa QAbstractOAuth2::grantedScope, QAbstractOAuth2::requestedScope
*/
#endif

/*!
    \since 6.9
    \property QAbstractOAuth2::grantedScope
    \brief This property holds the scope granted by the authorization
    server.

    The requested and granted scope may differ. End-user may have opted
    to grant only a subset of the scope, or server-side policies may
    change it. The application should be prepared to handle this
    scenario, and check the granted scope to see if it should impact
    the application logic.

    The server may omit indicating the granted scope altogether, as defined by
    \l {https://datatracker.ietf.org/doc/html/rfc6749#section-5.1}{RFC 6749}.
    In this case the implementation assumes the granted scope is the same as
    the requested scope.

    \sa QAbstractOAuth2::requestedScope
*/

/*!
    \since 6.9
    \property QAbstractOAuth2::requestedScope
    \brief This property holds the desired scope which defines the
    permissions requested by the client.

    \sa QAbstractOAuth2::grantedScope
*/

/*!
    \since 6.9
    \property QAbstractOAuth2::nonceMode
    \brief This property holds the current nonce mode (whether or not
           nonce is used).

    \sa NonceMode, nonce
*/

/*!
    \since 6.9
    \enum QAbstractOAuth2::NonceMode

    List of available
    \l {https://openid.net/specs/openid-connect-core-1_0-final.html#IDToken}{nonce}
    modes.

    \value Automatic Nonce is sent if the \l {requestedScope()} contains
           \c {openid}. This is the default mode, and sends \c {nonce} only
           when it's relevant to OIDC authentication flows.
    \value Enabled Nonce is sent during authorization stage.
    \value Disabled Nonce is not sent during authorization stage.

    \sa nonce, {Qt OAuth2 Overview}
*/

/*!
    \since 6.9
    \property QAbstractOAuth2::nonce

    This property holds the string sent to the server during
    authentication. The nonce is used to associate applicable
    token responses (OpenID Connect \c {id_token} in particular)
    with the authorization stage.

    The primary purpose of the \c {nonce} is to mitigate replay attacks.
    It ensures that the token responses received are in response
    to the authentication requests initiated by the application,
    preventing attackers from reusing tokens in unauthorized contexts.
    Therefore, it's important to include nonce verification as part of
    the token validation.

    In practice, authorization server vendors may refuse the OpenID Connect
    request if \l {https://openid.net/specs/openid-connect-core-1_0-final.html#AuthRequest}
    {a nonce isn't provided in the Authorization request}.

    The token itself is an opaque string, and should contain only
    URL-safe characters for maximum compatibility. Further the
    token must provide adequate entropy
    \l {https://openid.net/specs/openid-connect-core-1_0-final.html#NonceNotes}
    {so that it's unguessable to attackers}. There are no strict size
    limits for nonce, and authorization server vendors may impose their own
    minimum and maximum sizes.

    While the \c {nonce} can be set manually, Qt classes will
    generate a 32-character nonce \l {NonceMode}{when needed} if
    one isn't set.

    \sa nonceMode, {Qt OpenID Connect Support}
*/

/*!
    \since 6.9
    \property QAbstractOAuth2::idToken

    This property holds the received
    \l {https://openid.net/specs/openid-connect-core-1_0-final.html#CodeIDToken}
    {OpenID Connect ID token}.

    \sa NonceMode, nonce, {Qt OpenID Connect Support}
*/

/*!
    \fn template<typename Functor, QAbstractOAuth2::if_compatible_callback<Functor>> void QAbstractOAuth2::setNetworkRequestModifier(
                        const ContextTypeForFunctor<Functor> *context,
                        Functor &&callback)
    \since 6.9

    Sets the network request modification function to \a callback.
    This function is used to customize the network requests sent
    to the server.

    \a callback has to implement the signature
    \c {void(QNetworkRequest&, QAbstractOAuth::Stage)}. The provided
    QNetworkRequest can be directly modified, and it is used right after
    the callback finishes. \a callback can be a function pointer, lambda,
    member function, or any callable object. The provided
    QAbstractOAuth::Stage can be used to check to which stage
    the request relates to (token request, token refresh request,
    or authorization request in case of QOAuth2DeviceAuthorizationFlow).

    \a context controls the lifetime of the calls, and prevents
    access to de-allocated resources in case \a context is destroyed.
    In other words, if the object provided as context is destroyed,
    callbacks won't be executed. \a context must point to a valid
    QObject (and in case the callback is a member function,
    it needs to actually have it). Since the callback's results
    are used immediately, \a context must reside in the same
    thread as the QAbstractOAuth2 instance.

    \sa clearNetworkRequestModifier(), QNetworkRequest
*/

/*!
    \property QAbstractOAuth2::userAgent
    This property holds the User-Agent header used to create the
    network requests.

    The default value is "QtOAuth/1.0 (+https://www.qt.io)".
*/

/*!
    \property QAbstractOAuth2::clientIdentifierSharedKey
    This property holds the client shared key used as a password if
    the server requires authentication to request the token.
*/

/*!
    \property QAbstractOAuth2::state
    This property holds the string sent to the server during
    authentication. The state is used to identify and validate the
    request when the callback is received.

    Certain characters are illegal in the state element (see
    \l {https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.5}{RFC 6749}).
    The use of illegal characters could lead to an unintended state mismatch
    and a failing OAuth 2 authorization. Therefore, if you attempt to set
    a value that contains illegal characters, the state is ignored and a
    warning is logged.
*/

/*!
    \property QAbstractOAuth2::expiration
    This property holds the expiration time of the current access
    token.
*/

/*!
    \deprecated [6.13] Use serverReportedErrorOccurred instead
    \fn QAbstractOAuth2::error(const QString &error, const QString &errorDescription, const QUrl &uri)

    Signal emitted when the server responds to the authorization request with
    an error as defined in \l {https://www.rfc-editor.org/rfc/rfc6749#section-5.2}
    {RFC 6749 error response}.

    \a error is the name of the error; \a errorDescription describes the error
    and \a uri is an optional URI containing more information about the error.

    \sa QAbstractOAuth::requestFailed()
    \sa QAbstractOAuth2::serverReportedErrorOccurred()
*/

/*!
    \fn QAbstractOAuth2::serverReportedErrorOccurred(const QString &error,
                                                     const QString &errorDescription,
                                                     const QUrl &uri)
    \since 6.9

    Signal emitted when the server responds to the authorization request with
    an error as defined in \l {https://www.rfc-editor.org/rfc/rfc6749#section-5.2}
    {RFC 6749 error response}.

    \a error is the name of the error; \a errorDescription describes the error
    and \a uri is an optional URI containing more information about the error.

    To catch all errors, including these RFC defined errors, with a
    single signal, use \l {QAbstractOAuth::requestFailed()}.
*/

/*!
    \fn QAbstractOAuth2::authorizationCallbackReceived(const QVariantMap &data)

    Signal emitted when the reply server receives the authorization
    callback from the server: \a data contains the values received
    from the server.
*/

using OAuth2 = QAbstractOAuth2Private::OAuth2KeyString;
const QString OAuth2::accessToken =        u"access_token"_s;
const QString OAuth2::apiKey =             u"api_key"_s;
const QString OAuth2::clientIdentifier =   u"client_id"_s;
const QString OAuth2::clientSharedSecret = u"client_secret"_s;
const QString OAuth2::code =               u"code"_s;
const QString OAuth2::error =              u"error"_s;
const QString OAuth2::errorDescription =   u"error_description"_s;
const QString OAuth2::errorUri =           u"error_uri"_s;
const QString OAuth2::expiresIn =          u"expires_in"_s;
const QString OAuth2::grantType =          u"grant_type"_s;
const QString OAuth2::redirectUri =        u"redirect_uri"_s;
const QString OAuth2::refreshToken =       u"refresh_token"_s;
const QString OAuth2::responseType =       u"response_type"_s;
const QString OAuth2::scope =              u"scope"_s;
const QString OAuth2::state =              u"state"_s;
const QString OAuth2::tokenType =          u"token_type"_s;
const QString OAuth2::codeVerifier =       u"code_verifier"_s;
const QString OAuth2::codeChallenge =      u"code_challenge"_s;
const QString OAuth2::codeChallengeMethod = u"code_challenge_method"_s;
const QString OAuth2::nonce =              u"nonce"_s;
const QString OAuth2::idToken =            u"id_token"_s;
const QString OAuth2::deviceCode =         u"device_code"_s;
const QString OAuth2::userCode =           u"user_code"_s;
// RFC keyword is verification_uri[_complete], but some servers use 'url' (note L)
// https://datatracker.ietf.org/doc/html/rfc8628#section-3.2
const QString OAuth2::verificationUri =    u"verification_uri"_s;
const QString OAuth2::verificationUrl =    u"verification_url"_s;
const QString OAuth2::completeVerificationUri = u"verification_uri_complete"_s;
const QString OAuth2::completeVerificationUrl = u"verification_url_complete"_s;
const QString OAuth2::interval =           u"interval"_s;

QAbstractOAuth2Private::QAbstractOAuth2Private(const QPair<QString, QString> &clientCredentials,
                                               const QUrl &authorizationUrl,
                                               QNetworkAccessManager *manager) :
    QAbstractOAuthPrivate("qt.networkauth.oauth2",
                          authorizationUrl,
                          clientCredentials.first,
                          manager),
    clientIdentifierSharedKey(clientCredentials.second)
{}

QAbstractOAuth2Private::~QAbstractOAuth2Private()
{}

void QAbstractOAuth2Private::setGrantedScope(const QStringList &newScope)
{
    if (newScope == grantedScope)
        return;
    Q_Q(QAbstractOAuth2);
    grantedScope = newScope;
    Q_EMIT q->grantedScopeChanged(grantedScope);
}

QString QAbstractOAuth2Private::generateRandomState()
{
    return QString::fromUtf8(QAbstractOAuthPrivate::generateRandomString(8));
}

QString QAbstractOAuth2Private::generateNonce()
{
    // There is no strict minimum or maximum size for nonce, but
    // generating a 32-character base64 URL string provides
    // ~192 bits of entropy (32 characters * 6 bits per character).
    return QString::fromLatin1(QAbstractOAuthPrivate::generateRandomString(32));
}

QNetworkRequest QAbstractOAuth2Private::createRequest(QUrl url, const QVariantMap *parameters)
{
    QUrlQuery query(url.query());

    QNetworkRequest request;
    if (parameters) {
        for (auto it = parameters->begin(), end = parameters->end(); it != end; ++it)
            query.addQueryItem(it.key(), it.value().toString());
        url.setQuery(query);
    } else { // POST, PUT request
        addContentTypeHeaders(&request);
    }

    request.setUrl(url);
    request.setHeader(QNetworkRequest::UserAgentHeader, userAgent);
    const QString bearer = bearerFormat.arg(token);
    request.setRawHeader("Authorization", bearer.toUtf8());
    return request;
}

bool QAbstractOAuth2Private::authorizationShouldIncludeNonce() const
{
    switch (nonceMode) {
    case QAbstractOAuth2::NonceMode::Enabled:
        return true;
    case QAbstractOAuth2::NonceMode::Disabled:
        return false;
    case QAbstractOAuth2::NonceMode::Automatic:
        return requestedScope.contains("openid"_L1);
    };
    return false;
}

void QAbstractOAuth2Private::setIdToken(const QString &token)
{
    Q_Q(QAbstractOAuth2);
    if (idToken == token)
        return;
    idToken = token;
    emit q->idTokenChanged(idToken);
}

void QAbstractOAuth2Private::_q_tokenRequestFailed(QAbstractOAuth::Error error,
                                                const QString& errorString)
{
    Q_Q(QAbstractOAuth);
    qCWarning(loggingCategory) << "Token request failed:" << errorString;
    // If we were refreshing, reset status to Granted if we have an access token.
    // The access token might still be valid, and even if it wouldn't be,
    // refreshing can be attempted again.
    if (q->status() == QAbstractOAuth::Status::RefreshingToken) {
        if (!q->token().isEmpty())
            setStatus(QAbstractOAuth::Status::Granted);
        else
            setStatus(QAbstractOAuth::Status::NotAuthenticated);
    }
    emit q->requestFailed(error);
}

void QAbstractOAuth2Private::_q_tokenRequestFinished(const QVariantMap &values)
{
    Q_Q(QAbstractOAuth2);
    using Key = QAbstractOAuth2Private::OAuth2KeyString;

    if (values.contains(Key::error)) {
        _q_tokenRequestFailed(QAbstractOAuth::Error::ServerError,
                                    values.value(Key::error).toString());
        return;
    }

    bool ok;
    const QString accessToken = values.value(Key::accessToken).toString();
    tokenType = values.value(Key::tokenType).toString();
    int expiresIn = values.value(Key::expiresIn).toInt(&ok);
    if (!ok)
        expiresIn = -1;
    if (values.value(Key::refreshToken).isValid())
        q->setRefreshToken(values.value(Key::refreshToken).toString());

    if (accessToken.isEmpty()) {
        _q_tokenRequestFailed(QAbstractOAuth::Error::OAuthTokenNotFoundError,
                                    "Access token not received"_L1);
        return;
    }
    q->setToken(accessToken);

    // RFC 6749 section 5.1 https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
    // If the requested scope and granted scopes differ, server is REQUIRED to return
    // the scope. If OTOH the scopes match, the server MAY omit the scope in the response,
    // in which case we assume that the granted scope matches the requested scope.
    //
    // Note: 'scope' variable has two roles: requested scope, and later granted scope.
    // Therefore 'scope' needs to be set if the granted scope differs from 'scope'.
    const QString receivedGrantedScope = values.value(Key::scope).toString();
    const QStringList splitGrantedScope = receivedGrantedScope.split(" "_L1, Qt::SkipEmptyParts);
    if (splitGrantedScope.isEmpty()) {
        setGrantedScope(requestedScope);
    } else {
        setGrantedScope(splitGrantedScope);
#if QT_DEPRECATED_SINCE(6, 11)
        if (receivedGrantedScope != scope) {
            scope = receivedGrantedScope;
            QT_IGNORE_DEPRECATIONS(Q_EMIT q->scopeChanged(scope);)
        }
#endif
    }

    // An id_token must be included if this was an OIDC request
    // https://openid.net/specs/openid-connect-core-1_0-final.html#AuthRequest (cf. 'scope')
    // https://openid.net/specs/openid-connect-core-1_0-final.html#TokenResponse
    const QString receivedIdToken = values.value(Key::idToken).toString();
    if (grantedScope.contains("openid"_L1) && receivedIdToken.isEmpty()) {
        setIdToken({});
        _q_tokenRequestFailed(QAbstractOAuth::Error::OAuthTokenNotFoundError,
                                    "ID token not received"_L1);
        return;
    }
    setIdToken(receivedIdToken);

    const QDateTime currentDateTime = QDateTime::currentDateTime();
    if (expiresIn > 0 && currentDateTime.secsTo(expiresAt) != expiresIn) {
        expiresAt = currentDateTime.addSecs(expiresIn);
        Q_EMIT q->expirationAtChanged(expiresAt);
    }

    QVariantMap copy(values);
    copy.remove(Key::accessToken);
    copy.remove(Key::expiresIn);
    copy.remove(Key::refreshToken);
    copy.remove(Key::scope);
    copy.remove(Key::tokenType);
    copy.remove(Key::idToken);
    QVariantMap newExtraTokens = extraTokens;
    newExtraTokens.insert(copy);
    setExtraTokens(newExtraTokens);

    setStatus(QAbstractOAuth::Status::Granted);
}

bool QAbstractOAuth2Private::handleRfcErrorResponseIfPresent(const QVariantMap &data)
{
    Q_Q(QAbstractOAuth2);
    using Key = QAbstractOAuth2Private::OAuth2KeyString;
    const QString error = data.value(Key::error).toString();

    if (error.size()) {
        // RFC 6749, Section 5.2 Error Response
        const QString uri = data.value(Key::errorUri).toString();
        const QString description = data.value(Key::errorDescription).toString();
        qCWarning(loggingCategory, "Authorization stage: AuthenticationError: %s(%s): %s",
                  qPrintable(error), qPrintable(uri), qPrintable(description));

#if QT_DEPRECATED_SINCE(6, 13)
        QT_IGNORE_DEPRECATIONS(Q_EMIT q->error(error, description, uri);)
#endif
        Q_EMIT q->serverReportedErrorOccurred(error, description, uri);

        // Emit also requestFailed() so that it is a signal for all errors
        emit q->requestFailed(QAbstractOAuth::Error::ServerError);
        return true;
    }
    return false;
}

QAbstractOAuth2Private::RequestAndBody QAbstractOAuth2Private::createRefreshRequestAndBody(
    const QUrl &url)
{
    using Key = QAbstractOAuth2Private::OAuth2KeyString;

    RequestAndBody result;
    result.request.setUrl(url);

    QMultiMap<QString, QVariant> parameters;
#ifndef QT_NO_SSL
    if (sslConfiguration && !sslConfiguration->isNull())
        result.request.setSslConfiguration(*sslConfiguration);
#endif
    QUrlQuery query;
    parameters.insert(Key::grantType, QStringLiteral("refresh_token"));
    parameters.insert(Key::refreshToken, refreshToken);
    parameters.insert(Key::clientIdentifier, clientIdentifier);
    parameters.insert(Key::clientSharedSecret, clientIdentifierSharedKey);
    if (modifyParametersFunction)
        modifyParametersFunction(QAbstractOAuth::Stage::RefreshingAccessToken, &parameters);
    query = QAbstractOAuthPrivate::createQuery(parameters);
    result.request.setHeader(QNetworkRequest::ContentTypeHeader,
                      QStringLiteral("application/x-www-form-urlencoded"));

    callNetworkRequestModifier(result.request, QAbstractOAuth::Stage::RefreshingAccessToken);
    result.body = query.toString(QUrl::FullyEncoded).toUtf8();

    return result;
}

void QAbstractOAuth2Private::logAuthorizationStageWarning(QLatin1StringView message)
{
    static constexpr auto base = "Authorization stage: %s";
    qCWarning(loggingCategory, base, message.latin1());
}

void QAbstractOAuth2Private::logAuthorizationStageWarning(QLatin1StringView message, int detail)
{
    static constexpr auto base = "Authorization stage: %s: %d";
    qCWarning(loggingCategory, base, message.latin1(), detail);
}

void QAbstractOAuth2Private::logTokenStageWarning(QLatin1StringView message)
{
    static constexpr auto base = "Token stage: %s";
    qCWarning(loggingCategory, base, message.latin1());
}

bool QAbstractOAuth2Private::verifyThreadAffinity(const QObject *contextObject)
{
    Q_Q(QAbstractOAuth2);
    if (contextObject && (contextObject->thread() != q->thread())) {
        qCWarning(loggingCategory, "Context object must reside in the same thread");
        return false;
    }
    return true;
}

void QAbstractOAuth2Private::callNetworkRequestModifier(QNetworkRequest &request,
                                                       QAbstractOAuth::Stage stage)
{
    if (networkRequestModifier.contextObject && networkRequestModifier.slot) {
        if (!verifyThreadAffinity(networkRequestModifier.contextObject)) {
            Q_Q(QAbstractOAuth2);
            q->clearNetworkRequestModifier();
            return;
        }
        void *argv[] = { nullptr, &request, &stage};
        networkRequestModifier.slot->call(
            const_cast<QObject*>(networkRequestModifier.contextObject.get()), argv);
    }
}

/*!
    \reimp
*/
void QAbstractOAuth2::prepareRequest(QNetworkRequest *request, const QByteArray &verb,
                                     const QByteArray &body)
{
    Q_D(QAbstractOAuth2);
    Q_UNUSED(verb);
    Q_UNUSED(body);
    request->setHeader(QNetworkRequest::UserAgentHeader, d->userAgent);
    const QString bearer = d->bearerFormat.arg(d->token);
    request->setRawHeader("Authorization", bearer.toUtf8());
}

/*!
    Constructs a QAbstractOAuth2 object using \a parent as parent.
*/
QAbstractOAuth2::QAbstractOAuth2(QObject *parent) :
    QAbstractOAuth2(nullptr, parent)
{}

/*!
    Constructs a QAbstractOAuth2 object using \a parent as parent and
    sets \a manager as the network access manager.
*/
QAbstractOAuth2::QAbstractOAuth2(QNetworkAccessManager *manager, QObject *parent) :
    QAbstractOAuth(*new QAbstractOAuth2Private(qMakePair(QString(), QString()),
                                               QUrl(),
                                               manager),
                   parent)
{}

QAbstractOAuth2::QAbstractOAuth2(QAbstractOAuth2Private &dd, QObject *parent) :
    QAbstractOAuth(dd, parent)
{}

void QAbstractOAuth2::setResponseType(const QString &responseType)
{
    Q_D(QAbstractOAuth2);
    if (d->responseType != responseType) {
        d->responseType = responseType;
        Q_EMIT responseTypeChanged(responseType);
    }
}

void QAbstractOAuth2::setNetworkRequestModifierImpl(const QObject* context,
                                                   QtPrivate::QSlotObjectBase *slot)
{
    Q_D(QAbstractOAuth2);

    if (!context) {
        qCWarning(d->loggingCategory, "Context object must not be null, ignoring");
        return;
    }
    if (!d->verifyThreadAffinity(context))
        return;

    d->networkRequestModifier.contextObject = context;
    d->networkRequestModifier.slot.reset(slot);
}

/*!
    Clears the network request modifier.

    \sa setNetworkRequestModifier()
*/
void QAbstractOAuth2::clearNetworkRequestModifier()
{
    Q_D(QAbstractOAuth2);
    d->networkRequestModifier = {nullptr, nullptr};
}

/*!
    Destroys the QAbstractOAuth2 instance.
*/
QAbstractOAuth2::~QAbstractOAuth2()
{}

/*!
    The returned URL is based on \a url, combining it with the given
    \a parameters and the access token.
*/
QUrl QAbstractOAuth2::createAuthenticatedUrl(const QUrl &url, const QVariantMap &parameters)
{
    Q_D(const QAbstractOAuth2);
    if (Q_UNLIKELY(d->token.isEmpty())) {
        qCWarning(d->loggingCategory, "Empty access token");
        return QUrl();
    }
    QUrl ret = url;
    QUrlQuery query(ret.query());
    query.addQueryItem(OAuth2::accessToken, d->token);
    for (auto it = parameters.begin(), end = parameters.end(); it != end ;++it)
        query.addQueryItem(it.key(), it.value().toString());
    ret.setQuery(query);
    return ret;
}

/*!
    \deprecated [6.11] Please use QtNetwork classes directly instead, see
    \l {OAuth2 HTTP method alternatives}{HTTP method alternatives}.

    Sends an authenticated HEAD request and returns a new
    QNetworkReply. The \a url and \a parameters are used to create
    the request.

    \b {See also}: \l {https://tools.ietf.org/html/rfc2616#section-9.4}
    {Hypertext Transfer Protocol -- HTTP/1.1: HEAD}
*/
QNetworkReply *QAbstractOAuth2::head(const QUrl &url, const QVariantMap &parameters)
{
    Q_D(QAbstractOAuth2);
    QNetworkReply *reply = d->networkAccessManager()->head(d->createRequest(url, &parameters));
    connect(reply, &QNetworkReply::finished, this, [this, reply]() { emit finished(reply); });
    return reply;
}

/*!
    \deprecated [6.11] Please use QtNetwork classes directly instead, see
    \l {OAuth2 HTTP method alternatives}{HTTP method alternatives}.

    Sends an authenticated GET request and returns a new
    QNetworkReply. The \a url and \a parameters are used to create
    the request.

    \b {See also}: \l {https://tools.ietf.org/html/rfc2616#section-9.3}
    {Hypertext Transfer Protocol -- HTTP/1.1: GET}
*/
QNetworkReply *QAbstractOAuth2::get(const QUrl &url, const QVariantMap &parameters)
{
    Q_D(QAbstractOAuth2);
    QNetworkReply *reply = d->networkAccessManager()->get(d->createRequest(url, &parameters));
    connect(reply, &QNetworkReply::finished, this, [this, reply]() { emit finished(reply); });
    return reply;
}

/*!
    \deprecated [6.11] Please use QtNetwork classes directly instead, see
    \l {OAuth2 HTTP method alternatives}{HTTP method alternatives}.

    Sends an authenticated POST request and returns a new
    QNetworkReply. The \a url and \a parameters are used to create
    the request.

    \b {See also}: \l {https://tools.ietf.org/html/rfc2616#section-9.5}
    {Hypertext Transfer Protocol -- HTTP/1.1: POST}
*/
QNetworkReply *QAbstractOAuth2::post(const QUrl &url, const QVariantMap &parameters)
{
    Q_D(QAbstractOAuth2);
    const auto data = d->convertParameters(parameters);
    QT_IGNORE_DEPRECATIONS(return post(url, data);)
}

/*!
    \deprecated [6.11] Please use QtNetwork classes directly instead, see
    \l {OAuth2 HTTP method alternatives}{HTTP method alternatives}.

    \since 5.10

    \overload

    Sends an authenticated POST request and returns a new
    QNetworkReply. The \a url and \a data are used to create
    the request.

    \sa post(), {https://tools.ietf.org/html/rfc2616#section-9.6}
    {Hypertext Transfer Protocol -- HTTP/1.1: POST}
*/
QNetworkReply *QAbstractOAuth2::post(const QUrl &url, const QByteArray &data)
{
    Q_D(QAbstractOAuth2);
    QNetworkReply *reply = d->networkAccessManager()->post(d->createRequest(url), data);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() { emit finished(reply); });
    return reply;
}

/*!
    \deprecated [6.11] Please use QtNetwork classes directly instead, see
    \l {OAuth2 HTTP method alternatives}{HTTP method alternatives}.

    \since 5.10

    \overload

    Sends an authenticated POST request and returns a new
    QNetworkReply. The \a url and \a multiPart are used to create
    the request.

    \sa post(), QHttpMultiPart, {https://tools.ietf.org/html/rfc2616#section-9.6}
    {Hypertext Transfer Protocol -- HTTP/1.1: POST}
*/
QNetworkReply *QAbstractOAuth2::post(const QUrl &url, QHttpMultiPart *multiPart)
{
    Q_D(QAbstractOAuth2);
    QNetworkReply *reply = d->networkAccessManager()->post(d->createRequest(url), multiPart);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() { emit finished(reply); });
    return reply;
}

/*!
    \deprecated [6.11] Please use QtNetwork classes directly instead, see
    \l {OAuth2 HTTP method alternatives}{HTTP method alternatives}.

    Sends an authenticated PUT request and returns a new
    QNetworkReply. The \a url and \a parameters are used to create
    the request.

    \b {See also}: \l {https://tools.ietf.org/html/rfc2616#section-9.6}
    {Hypertext Transfer Protocol -- HTTP/1.1: PUT}
*/
QNetworkReply *QAbstractOAuth2::put(const QUrl &url, const QVariantMap &parameters)
{
    Q_D(QAbstractOAuth2);
    const auto data = d->convertParameters(parameters);
    QT_IGNORE_DEPRECATIONS(return put(url, data);)
}

/*!
    \deprecated [6.11] Please use QtNetwork classes directly instead, see
    \l {OAuth2 HTTP method alternatives}{HTTP method alternatives}.

    \since 5.10

    \overload

    Sends an authenticated PUT request and returns a new
    QNetworkReply. The \a url and \a data are used to create
    the request.

    \sa put(), {https://tools.ietf.org/html/rfc2616#section-9.6}
    {Hypertext Transfer Protocol -- HTTP/1.1: PUT}
*/
QNetworkReply *QAbstractOAuth2::put(const QUrl &url, const QByteArray &data)
{
    Q_D(QAbstractOAuth2);
    QNetworkReply *reply = d->networkAccessManager()->put(d->createRequest(url), data);
    connect(reply, &QNetworkReply::finished, this, std::bind(&QAbstractOAuth::finished, this, reply));
    return reply;
}

/*!
    \deprecated [6.11] Please use QtNetwork classes directly instead, see
    \l {OAuth2 HTTP method alternatives}{HTTP method alternatives}.

    \since 5.10

    \overload

    Sends an authenticated PUT request and returns a new
    QNetworkReply. The \a url and \a multiPart are used to create
    the request.

    \sa put(), QHttpMultiPart, {https://tools.ietf.org/html/rfc2616#section-9.6}
    {Hypertext Transfer Protocol -- HTTP/1.1: PUT}
*/
QNetworkReply *QAbstractOAuth2::put(const QUrl &url, QHttpMultiPart *multiPart)
{
    Q_D(QAbstractOAuth2);
    QNetworkReply *reply = d->networkAccessManager()->put(d->createRequest(url), multiPart);
    connect(reply, &QNetworkReply::finished, this, std::bind(&QAbstractOAuth::finished, this, reply));
    return reply;
}

/*!
    \deprecated [6.11] Please use QtNetwork classes directly instead, see
    \l {OAuth2 HTTP method alternatives}{HTTP method alternatives}.

    Sends an authenticated DELETE request and returns a new
    QNetworkReply. The \a url and \a parameters are used to create
    the request.

    \b {See also}: \l {https://tools.ietf.org/html/rfc2616#section-9.7}
    {Hypertext Transfer Protocol -- HTTP/1.1: DELETE}
*/
QNetworkReply *QAbstractOAuth2::deleteResource(const QUrl &url, const QVariantMap &parameters)
{
    Q_D(QAbstractOAuth2);
    QNetworkReply *reply = d->networkAccessManager()->deleteResource(
                d->createRequest(url, &parameters));
    connect(reply, &QNetworkReply::finished, this, [this, reply]() { emit finished(reply); });
    return reply;
}

#if QT_DEPRECATED_SINCE(6, 11)
QString QAbstractOAuth2::scope() const
{
    Q_D(const QAbstractOAuth2);
    return d->scope;
}
#endif

QStringList QAbstractOAuth2::grantedScope() const
{
    Q_D(const QAbstractOAuth2);
    return d->grantedScope;
}

#if QT_DEPRECATED_SINCE(6, 11)
void QAbstractOAuth2::setScope(const QString &scope)
{
    Q_D(QAbstractOAuth2);
    if (d->scope != scope) {
        d->scope = scope;
        QT_IGNORE_DEPRECATIONS(Q_EMIT scopeChanged(scope);)
    }
    QStringList splitScope = scope.split(" "_L1, Qt::SkipEmptyParts);
    if (d->requestedScope != splitScope) {
        d->requestedScope = splitScope;
        Q_EMIT requestedScopeChanged(splitScope);
    }
}
#endif

QStringList QAbstractOAuth2::requestedScope() const
{
    Q_D(const QAbstractOAuth2);
    return d->requestedScope;
}

void QAbstractOAuth2::setRequestedScope(const QStringList &scope)
{
    Q_D(QAbstractOAuth2);
    if (scope != d->requestedScope) {
        d->requestedScope = scope;
        Q_EMIT requestedScopeChanged(scope);
    }
#if QT_DEPRECATED_SINCE(6, 11)
    QString joinedScope = scope.join(" "_L1);
    if (joinedScope != d->scope) {
        d->scope = joinedScope;
        QT_IGNORE_DEPRECATIONS(Q_EMIT scopeChanged(joinedScope);)
    }
#endif
}

QString QAbstractOAuth2::userAgent() const
{
    Q_D(const QAbstractOAuth2);
    return d->userAgent;
}

void QAbstractOAuth2::setUserAgent(const QString &userAgent)
{
    Q_D(QAbstractOAuth2);
    if (d->userAgent != userAgent) {
        d->userAgent = userAgent;
        Q_EMIT userAgentChanged(userAgent);
    }
}

/*!
    Returns the \l {https://tools.ietf.org/html/rfc6749#section-3.1.1}
    {response_type} used.
*/
QString QAbstractOAuth2::responseType() const
{
    Q_D(const QAbstractOAuth2);
    return d->responseType;
}

QString QAbstractOAuth2::clientIdentifierSharedKey() const
{
    Q_D(const QAbstractOAuth2);
    return d->clientIdentifierSharedKey;
}

void QAbstractOAuth2::setClientIdentifierSharedKey(const QString &clientIdentifierSharedKey)
{
    Q_D(QAbstractOAuth2);
    if (d->clientIdentifierSharedKey != clientIdentifierSharedKey) {
        d->clientIdentifierSharedKey = clientIdentifierSharedKey;
        Q_EMIT clientIdentifierSharedKeyChanged(clientIdentifierSharedKey);
    }
}

QString QAbstractOAuth2::state() const
{
    Q_D(const QAbstractOAuth2);
    return d->state;
}

void QAbstractOAuth2::setState(const QString &state)
{
    Q_D(QAbstractOAuth2);
    // Allowed characters are defined in
    // https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.5
    // state      = 1*VSCHAR
    // Where
    // VSCHAR     = %x20-7E
    for (QChar c : state) {
        if (c < u'\x20' || c > u'\x7E') {
            qCWarning(d->loggingCategory, "setState() contains illegal character(s), ignoring");
            return;
        }
    }
    if (state != d->state) {
        d->state = state;
        Q_EMIT stateChanged(state);
    }
}

QDateTime QAbstractOAuth2::expirationAt() const
{
    Q_D(const QAbstractOAuth2);
    return d->expiresAt;
}

/*!
    \brief Gets the current refresh token.

    Refresh tokens usually have longer lifespans than access tokens,
    so it makes sense to save them for later use.

    Returns the current refresh token or an empty string, if
    there is no refresh token available.
*/
QString QAbstractOAuth2::refreshToken() const
{
    Q_D(const QAbstractOAuth2);
    return  d->refreshToken;
}

/*!
   \brief Sets the new refresh token \a refreshToken to be used.

    A custom refresh token can be used to refresh the access token via this method and then
    the access token can be refreshed via QOAuth2AuthorizationCodeFlow::refreshAccessToken().

*/
void QAbstractOAuth2::setRefreshToken(const QString &refreshToken)
{
    Q_D(QAbstractOAuth2);
    if (d->refreshToken != refreshToken) {
        d->refreshToken = refreshToken;
        Q_EMIT refreshTokenChanged(refreshToken);
    }
}

QAbstractOAuth2::NonceMode QAbstractOAuth2::nonceMode() const
{
    Q_D(const QAbstractOAuth2);
    return d->nonceMode;
}

void QAbstractOAuth2::setNonceMode(NonceMode mode)
{
    Q_D(QAbstractOAuth2);
    if (mode == d->nonceMode)
        return;
    d->nonceMode = mode;
    emit nonceModeChanged(d->nonceMode);
}

QString QAbstractOAuth2::nonce() const
{
    Q_D(const QAbstractOAuth2);
    return d->nonce;
}

void QAbstractOAuth2::setNonce(const QString &nonce)
{
    Q_D(QAbstractOAuth2);
    if (nonce == d->nonce)
        return;
    d->nonce = nonce;
    emit nonceChanged(d->nonce);
}

QString QAbstractOAuth2::idToken() const
{
    Q_D(const QAbstractOAuth2);
    return d->idToken;
}

#ifndef QT_NO_SSL
/*!
    \since 6.5

    Returns the TLS configuration to be used when establishing a mutual TLS
    connection between the client and the Authorization Server.

    \sa setSslConfiguration(), sslConfigurationChanged()
*/
QSslConfiguration QAbstractOAuth2::sslConfiguration() const
{
    Q_D(const QAbstractOAuth2);
    return d->sslConfiguration.value_or(QSslConfiguration());
}

/*!
    \since 6.5

    Sets the TLS \a configuration to be used when establishing
    a mutual TLS connection between the client and the Authorization Server.

    \sa sslConfiguration(), sslConfigurationChanged()
*/
void QAbstractOAuth2::setSslConfiguration(const QSslConfiguration &configuration)
{
    Q_D(QAbstractOAuth2);
    const bool configChanged = !d->sslConfiguration || (*d->sslConfiguration != configuration);
    if (configChanged) {
        d->sslConfiguration = configuration;
        Q_EMIT sslConfigurationChanged(configuration);
    }
}

/*!
    \fn void QAbstractOAuth2::sslConfigurationChanged(const QSslConfiguration &configuration)
    \since 6.5

    The signal is emitted when the TLS configuration has changed.
    The \a configuration parameter contains the new TLS configuration.

    \sa sslConfiguration(), setSslConfiguration()
*/
#endif // !QT_NO_SSL

QT_END_NAMESPACE

#include "moc_qabstractoauth2.cpp"

#endif // QT_NO_HTTP
