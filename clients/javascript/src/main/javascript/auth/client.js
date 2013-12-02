window._oauth = (function () {
    var oauth = {};

    var params = window.location.search.substring(1).split('&');
    for (var i = 0; i < params.length; i++) {
        var p = params[i].split('=');
        switch (decodeURIComponent(p[0])) {
            case 'code':
                oauth.code = p[1];
                break;
            case 'error':
                oauth.error = p[1];
                break;
            case 'state':
                oauth.state = p[1];
                break;
        }
    }

    oauth.callback = (oauth.code && oauth.state) || (oauth.error && oauth.state);

    if (oauth.callback) {
        console.debug('oauth callback');

        if (oauth.state && oauth.state.indexOf('#') != -1) {
            oauth.fragment = window._oauth.state.substr(window._oauth.state.indexOf('#') + 1);
        }

        window.history.replaceState({}, null, location.protocol + '//' + location.host + location.pathname);
    }

    return oauth;
}());

Keycloak = function (host, port, secure) {
    this._host = host;
    this._port = port;
    this._secure - secure;
}

Keycloak.prototype = {

    get authenticated() {
        return this._tokenParsed
    },

    get username() {
        return this._tokenParsed && this._tokenParsed.prn;
    },

    get realm() {
        return this._tokenParsed && this._tokenParsed.realm;
    },

    get realmAccess() {
        return this._tokenParsed && this._tokenParsed.realm_access;
    },

    get resourceAccess() {
        return this._tokenParsed && this._tokenParsed.resource_access;
    },

    get token() {
        return this._token;
    },

    init: function (config) {
        this._clientId = config.clientId;
        this._clientSecret = config.clientSecret;
        this._realm = config.realm || 'default';
        this._redirectUri = config.redirectUri || (location.protocol + '//' + location.hostname + (location.port && (':' + location.port)) + location.pathname);

        if (window._oauth.callback) {
            this._processCallback();
        } else if (config.onload) {
            switch (config.onload) {
                case 'login-required' :
                    this.login();
                    break;
                case 'check-sso' :
                    this.login(false);
                    break;
            }
        }

        this._callback = config.callback;
        this._loadProfile = config.loadProfile;
    },

    login: function (prompt) {
        window.location.href = this._createLoginUrl(prompt);
    },

    logout: function () {
        window.location.href = this._createLogoutUrl();
    },

    hasRealmRole: function (role) {
        var access = this.realmAccess;
        return access && access.roles.indexOf(role) >= 0 || false;
    },

    hasResourceRole: function (role, resource) {
        var access = this.resourceAccess[resource || this._clientId];
        return access && access.roles.indexOf(role) >= 0 || false;
    },

    get _baseUrl() {
        return (this._secure ? 'https' : 'http') + '://' + this._host + ':' + this._port + '/auth-server/rest/realms/' + encodeURIComponent(this._realm);
    },

    _processCallback: function () {
        var code = window._oauth.code;
        var error = window._oauth.error;
        var state = window._oauth.state;

        if (code) {
            if (state == sessionStorage.state) {
                var params = 'code=' + code + '&client_id=' + encodeURIComponent(this._clientId) + '&password=' + encodeURIComponent(this._clientSecret);
                var codeUrl = this._baseUrl + '/tokens/access/codes';

                var tokenReq = new XMLHttpRequest();
                tokenReq.open('POST', codeUrl, true);
                tokenReq.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

                var inst = this;
                tokenReq.onreadystatechange = function () {
                    if (tokenReq.readyState == 4) {
                        if (tokenReq.status == 200) {
                            console.debug('oauth received token');

                            inst._token = JSON.parse(tokenReq.responseText)['access_token'];
                            inst._tokenParsed = inst._parseToken(inst._token);

                            window._oauth.token = inst._token;

                            inst._callback && inst._callback('authenticated');

                            if (this._loadProfile) {
                                var profileUrl = inst._baseUrl + '/account';
                                var profileReq = new XMLHttpRequest();
                                profileReq.open('GET', profileUrl, true);
                                profileReq.setRequestHeader('Accept', 'application/json');
                                profileReq.setRequestHeader('Authorization', 'bearer ' + inst._token);

                                profileReq.onreadystatechange = function () {
                                    if (profileReq.readyState == 4) {
                                        if (profileReq.status == 200) {
                                            console.debug('oauth loaded profile');

                                            inst._user = JSON.parse(profileReq.responseText);
                                            inst._callback && inst._callback('authenticated-profile');
                                        }
                                    }
                                }

                                profileReq.send();
                            }
                        } else {
                            inst._callback && inst._callback(false);
                        }

                    }
                };

                tokenReq.send(params);
            } else if (error) {
                this._callback('error');
            }
        }
    },

    _parseToken: function (token) {
        return JSON.parse(atob(token.split('.')[1]));
    },

    _createLoginUrl: function (prompt) {
        var state = this._createUUID();
//        if (location.hash) {
//            state += '#' + location.hash;
//        }
        sessionStorage.state = state;
        var url = this._baseUrl
            + '/tokens/login'
            + '?client_id=' + encodeURIComponent(this._clientId)
            + '&redirect_uri=' + encodeURIComponent(this._redirectUri)
            + '&state=' + encodeURIComponent(state)
            + '&response_type=code';

        if (prompt == false) {
            url += '&prompt=none';
        }

        return url;
    },

    _createLogoutUrl: function () {
        var url = this._baseUrl
            + '/tokens/logout'
            + '?redirect_uri=' + encodeURIComponent(this._redirectUri);
        return url;
    },

    _createUUID: function () {
        var s = [];
        var hexDigits = '0123456789abcdef';
        for (var i = 0; i < 36; i++) {
            s[i] = hexDigits.substr(Math.floor(Math.random() * 0x10), 1);
        }
        s[14] = '4';
        s[19] = hexDigits.substr((s[19] & 0x3) | 0x8, 1);
        s[8] = s[13] = s[18] = s[23] = '-';
        var uuid = s.join('');
        return uuid;
    }

}
