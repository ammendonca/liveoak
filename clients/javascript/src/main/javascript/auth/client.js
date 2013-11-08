
Keycloak = function(host, port, secure) {
    this._host = host;
    this._port = port;
    this._secure - secure;
}

Keycloak.prototype = {

    get authenticated() {
        return this._tokenParsed
    },

    get user() {
        return this._user;
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

    get tokenParsed() {
        return this._tokenParsed;
    },

    init: function(config) {
        this._clientId = config.clientId;
        this._clientSecret = config.clientSecret;
        this._realm = config.realm || 'default';
        this._redirectUri = config.redirectUri || (location.protocol + '//' + location.hostname + (location.port && (':' + location.port)) + location.pathname);

        if (!this._processCallback()) {
            window.location.href = this._createLoginUrl() + '&prompt=none';
        }
    },

    login: function() {
        window.location.href = this._createLoginUrl();
    },

    logout: function() {
        window.location.href = this._createLogoutUrl();
    },

    hasRealmAccess: function(role) {
        var access = this.realmAccess;
        return access && access.roles.indexOf(role) >= 0 || false;
    },

    hasResourceAccess: function(role, resource) {
        var access = this.resourceAccess[resource || this._clientId];
        return access && access.roles.indexOf(role) >= 0 || false;
    },

    get _baseUrl() {
        return (this._secure ? 'https' : 'http') + '://' + this._host + ':' + this._port + '/auth-server/rest/realms/' + encodeURIComponent(this._realm);
    },

    _processCallback: function() {
        var code = this._queryParam('code');
        var error = this._queryParam('error');
        var state = this._queryParam('state');

        if (error) {
            this._updateLocation(state);
            this.authCallback && this.authCallback(false);
            return true;
        } else if (code) {
            if (state == sessionStorage.state) {
                var params = 'code=' + code + '&client_id=' + encodeURIComponent(this._clientId) + '&password=' + encodeURIComponent(this._clientSecret);
                var url = this._baseUrl + '/tokens/access/codes';

                var tokenReq = new XMLHttpRequest();
                tokenReq.open('POST', url, true);
                tokenReq.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

                var kc = this;
                tokenReq.onreadystatechange = function() {
                    if (tokenReq.readyState == 4) {
                        if (tokenReq.status == 200) {
                            kc._token = JSON.parse(tokenReq.responseText)['access_token'];
                            kc._tokenParsed = kc._parseToken(kc._token);

                            var url = kc._baseUrl + '/account';
                            var profileReq = new XMLHttpRequest();
                            profileReq.open('GET', url, true);
                            profileReq.setRequestHeader('Accept', 'application/json');
                            profileReq.setRequestHeader('Authorization', 'bearer ' + kc._token);

                            profileReq.onreadystatechange = function() {
                                if (profileReq.readyState == 4) {
                                    if (profileReq.status == 200) {
                                        kc._user = JSON.parse(profileReq.responseText);
                                        kc.authCallback && kc.authCallback(true);
                                    } else {
                                        kc.authCallback && kc.authCallback(false);
                                    }
                                }
                            }
                        } else {
                            kc.authCallback && kc.authCallback(false);
                        }

                        profileReq.send();
                    }
                };

                tokenReq.send(params);
            }

            this._updateLocation(state);
            return true;
        } else {
            return false;
        }
    },

    _parseToken : function(token) {
        return JSON.parse(atob(token.split('.')[1]));
    },

    _createLoginUrl: function() {
        var state = this._createUUID();
        if (location.hash) {
            state += '#' + location.hash;
        }
        sessionStorage.state = state;
        var url = this._baseUrl
            + '/tokens/login'
            + '?client_id=' +  encodeURIComponent(this._clientId)
            + '&redirect_uri=' +  encodeURIComponent(this._redirectUri)
            + '&state=' +  encodeURIComponent(state)
            + '&response_type=code';
        return url;
    },

    _createLogoutUrl: function() {
        var url = this._baseUrl
            + '/tokens/logout'
            + '?redirect_uri=' +  encodeURIComponent(this._redirectUri);
        return url;
    },

    _updateLocation: function(state) {
        var s = decodeURIComponent(state);
        var fragment = '';
        if (s && s.indexOf('#') != -1) {
            fragment = s.substr(s.indexOf('#') + 1);
        }
        window.history.replaceState({}, document.title, location.protocol + '//' + location.host + location.pathname + fragment);
    },

    _createUUID: function() {
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
    },

    _queryParam: function(name) {
        var params = window.location.search.substring(1).split('&');
        for (var i = 0; i < params.length; i++) {
            var p = params[i].split('=');
            if (decodeURIComponent(p[0]) == name) {
                return p[1];
            }
        }
    }

}
