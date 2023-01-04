// Ref: https://github.com/expressjs/csurf/tree/741f484

import Tokens from 'csrf';
import { sign } from 'cookie-signature';

const optionDefaults = {
  headerName: 'X-XSRF-TOKEN',
  ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
  cookieOptions: { // https://expressjs.com/en/api.html#res.cookie
    name: 'XSRF-TOKEN',
  },
  csrfOptions: { // https://github.com/pillarjs/csrf#options
    saltLength: 8,
    secretLength: 18,
  },
};

/**
 * CSRF protection middleware that implements Double Submit Cookie pattern.
 *
 * This middleware adds a `req.csrfToken()` function to make a token
 * which should be added to requests which mutate
 * state, within a hidden form field, query-string etc. This
 * token is validated against the visitor's cookie.
 *
 * @param {Object} options
 * @return {Function} middleware
 * @public
 */

function csurf(options) {
  const opts = Object.assign(optionDefaults, options);
  const { name, signed } = opts.cookieOptions;
  const tokens = new Tokens(opts.csrfOptions);

  return (req, res, next) => {
    // get the secret from the request
    const cookieKey = signed ? 'signedCookies' : 'cookies';
    const cookies = req[cookieKey];

    // validate the configuration against request
    if (!cookies || (signed && !req.secret)) {
      return next(new Error('Misconfigured csrf'));
    }

    let secret = cookies[name];
    let token;

    // lazy-load token getter
    req.csrfToken = () => {
      if (!token) {
        token = tokens.create(secret);
      }
      return token;
    };

    // generate & set secret
    if (!secret) {
      secret = tokens.secretSync();
      const secretValue = signed
        ? `s:${sign(secret, req.secret)}`
        : secret;
      res.cookie(name, secretValue, opts.cookieOptions);
    }

    // verify the incoming token
    if (opts.ignoreMethods.indexOf(req.method) === -1
    && !tokens.verify(secret, req.headers[opts.headerName])) {
      const error = new Error('Invalid csrf token');
      error.status = 403;
      return next(error);
    }

    return next();
  };
}

export default csurf;
