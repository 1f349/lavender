/* Simple OAuth 2.0 Client flow library

  Author: MrMelon54, timdream

  Usage:
  POP2.init(client_id, scope)
  	Initialize the library.
    redirect_uri is the current page (window.location.href).
    This function should be put before Analytics so that the second click won't result a page view register.
  POP2.getToken(callback)
    Send access token to the callback function as the first argument.
    If not logged in this triggers login popup and execute login after logged in.
    Be sure to call this function in user-triggered event (such as click) to prevent popup blocker.
    If not sure do use isLoggedIn() below to check first.
  POP2.isLoggedIn()
    boolean

*/

"use strict";

(function (w) {
    const windowName = 'pop2_oauth2_login_popup';

    if (window.name === windowName) {
        if (
            window.opener &&
            window.opener.POP2
        ) {
            if (window.location.hash.indexOf('access_token') !== -1) {
                window.opener.POP2.receiveToken(
                    window.location.hash.replace(/^.*access_token=([^&]+).*$/, '$1'),
                    parseInt(window.location.hash.replace(/^.*expires_in=([^&]+).*$/, '$1'))
                );
            }
            if (window.location.search.indexOf('error=')) {
                window.opener.POP2.receiveToken('ERROR');
            }
        }
        window.close();
    }

    function popupCenterScreen(url, title, w, h) {
        const top = (screen.availHeight - h) / 4, left = (screen.availWidth - w) / 2;
        return openWindow(url, title, `scrollbars=yes,width=${w},height=${h},top=${top},left=${left}`);
    }

    function openWindow(url, winnm, options) {
        const wTop = firstAvailableValue([window.screen.availTop, window.screenY, window.screenTop, 0]);
        const wLeft = firstAvailableValue([window.screen.availLeft, window.screenX, window.screenLeft, 0]);
        let top = "0",
            left = "0",
            result;
        if ((result = /top=(\d+)/g.exec(options))) top = parseInt(result[1]);
        if ((result = /left=(\d+)/g.exec(options))) left = parseInt(result[1]);
        if (options) {
            options = options.replace("top=" + top, "top=" + (parseInt(top) + wTop));
            options = options.replace("left=" + left, "left=" + (parseInt(left) + wLeft));
            w = window.open(url, winnm, options);
        } else w = window.open(url, winnm);
        return w;
    }

    function firstAvailableValue(arr) {
        for (let i = 0; i < arr.length; i++)
            if (typeof arr[i] != 'undefined')
                return arr[i];
    }

    let client_endpoint,
        client_id,
        scope = '',
        redirect_uri = window.location.href.substr(0, window.location.href.length - window.location.hash.length).replace(/#$/, ''),
        access_token,
        callbackWaitForToken,
        w_width = 400,
        w_height = 360;

    w.POP2 = {
        // init
        init: function (f_client_endpoint, f_client_id, f_scope, width, height) {
            if (!f_client_endpoint) return false;
            if (!f_client_id) return false;
            client_endpoint = f_client_endpoint;
            client_id = f_client_id;
            if (f_scope) scope = f_scope;
            if (width) w_width = width;
            if (height) w_height = height;
        },
        // receive token from popup
        receiveToken: function (token, expires_in) {
            if (token !== 'ERROR') {
                access_token = token;
                if (callbackWaitForToken) callbackWaitForToken(access_token);
                setTimeout(
                    function () {
                        access_token = undefined;
                    },
                    expires_in * 1000
                );
            } else if (token === false) {
                callbackWaitForToken = undefined;
            }
        },
        // boolean, indicate logged in or not
        isLoggedIn: function () {
            return !!access_token;
        },
        // pass the access token to callback
        // if not logged in this triggers login popup;
        // use isLoggedIn to check login first to prevent popup blocker
        getToken: function (callback) {
            if (!client_id || !redirect_uri || !scope) {
                alert('You need init() first. Check the program flow.');
                return false;
            }
            if (!access_token) {
                callbackWaitForToken = callback;
                popupCenterScreen(
                    client_endpoint
                    + '?response_type=token'
                    + '&redirect_uri=' + encodeURIComponent(redirect_uri)
                    + '&scope=' + encodeURIComponent(scope)
                    + '&client_id=' + encodeURIComponent(client_id),
                    windowName,
                    w_width,
                    w_height
                );
            } else {
                return callback(access_token);
            }
        }
    };
})(this);
