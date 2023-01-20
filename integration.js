'use strict';

const request = require('postman-request');
const _ = require('lodash');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');

let Logger;
let requestWithDefaults;

const MAX_PARALLEL_LOOKUPS = 10;

const IGNORED_IPS = new Set(['127.0.0.1', '255.255.255.255', '0.0.0.0']);

const NodeCache = require('node-cache');
const tokenCache = new NodeCache({
  stdTTL: 10 * 59
});

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function startup(logger) {
  let defaults = {};
  Logger = logger;

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0)
    defaults.cert = fs.readFileSync(config.request.cert);

  if (typeof config.request.key === 'string' && config.request.key.length > 0)
    defaults.key = fs.readFileSync(config.request.key);

  if (
    typeof config.request.passphrase === 'string' &&
    config.request.passphrase.length > 0
  )
    defaults.passphrase = config.request.passphrase;

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0)
    defaults.ca = fs.readFileSync(config.request.ca);

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0)
    defaults.proxy = config.request.proxy;

  if (typeof config.request.rejectUnauthorized === 'boolean')
    defaults.rejectUnauthorized = config.request.rejectUnauthorized;

  requestWithDefaults = request.defaults(defaults);
}

function getAuthToken(options, callback) {
  const cacheKey = options.url + options.securityToken;
  let token = tokenCache.get(cacheKey);
  if (token) return callback(null, token);

  requestWithDefaults(
    {
      method: 'POST',
      uri: `${options.url}/user/session`,
      headers: {
        'Content-Type': 'application/json'
      },
      body: {
        security_token: options.securityToken
      },
      json: true
    },
    (err, resp, body) => {
      if (err) return callback(err);

      Logger.trace({ body }, 'Result of token lookup');

      if (resp.statusCode != 200)
        return callback({ err: new Error('status code was not 200'), body });

      tokenCache.set(cacheKey, body.access_token);

      Logger.trace({ tokenCache }, 'Checking TokenCache');

      callback(null, body.jwt.access);
    }
  );
}

function doLookup(entities, { url, ..._options }, cb) {
  let lookupResults = [];
  let tasks = [];
  let options = { ..._options, url: url.endsWith('/') ? url.slice(0, -1) : url };
  Logger.debug(entities);

  getAuthToken(options, (err, token) => {
    if (err) {
      Logger.error({ err }, 'get token errored');
      return cb({
        err: 'Error getting Auth Token',
        detail: `Auth Error: Verify your URL and Security Token are correct ${err}`
      });
    }

    Logger.trace({ token }, 'Token in doLookup');

    entities
      .filter(({ isIP, value }) => !isIP || (isIP && !IGNORED_IPS.has(value)))
      .forEach((entity) => {
        let requestOptions = {
          method: 'GET',
          headers: {
            Authorization: 'Bearer ' + token,
            'Content-Type': 'application/json'
          },
          json: true
        };

        if (entity.isIPv4) {
          (requestOptions.uri = `${options.url}/query/assets`),
            (requestOptions.qs = {
              dsl_filter: `{"search":[{"fields":["compute.public_ips","compute.private_ips"],"phrase":"${entity.value}"}]}`
            });
        } else if (entity.isDomain) {
          (requestOptions.uri = `${options.url}/query/assets`),
            (requestOptions.qs = {
              dsl_filter: `{"search":[{"fields":["compute.public_dnss","compute.private_dnss"],"phrase":"${entity.value}"}]}`
            });
        } else if (entity.type === 'cve') {
          (requestOptions.uri = `${options.url}/query/cves`),
            (requestOptions.qs = {
              dsl_filter: `{"search":[{"fields":["cve_id"],"phrase":"${entity.value}"}]}`
            });
        } else {
          return;
        }

        Logger.trace({ uri: requestOptions }, 'Request URI');

        tasks.push(function (done) {
          requestWithDefaults(requestOptions, function (error, res, body) {
            if (error) return done(error);

            Logger.trace(
              { body, statusCode: res ? res.statusCode : 'N/A' },
              'Result of Lookup'
            );

            let result = {};

            if (res.statusCode === 200) {
              result = { entity, body };
            } else if (res.statusCode === 404) {
              result = {
                entity,
                body: null
              };
            } else if (res.statusCode === 202) {
              result = {
                entity,
                body: null
              };
            } else if (res.statusCode === 403) {
              error = {
                err: 'Non-Existent Device',
                detail:
                  'A warning will result if an investigation is performed with a non-existent device.'
              };
            } else if (res.statusCode === 429) {
              error = {
                err: 'API Limit Exceeded',
                detail:
                  'You may have exceeded the rate limits for your organization or package'
              };
            } else if (res.statusCode === 401) {
              error = {
                err: 'JWT Token Expired',
                detail: 'JWT Token expired'
              };
            } else if (Math.round(res.statusCode / 10) * 10 === 500) {
              error = {
                err: 'Server Error',
                detail: 'Unexpected Server Error'
              };
            }

            done(null, result);
          });
        });
      });

    async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
      if (err) {
        Logger.error({ err }, 'Error');
        return cb({ err, detail: 'Error Performing Lookup' });
      }

      Logger.trace({ results }, 'Results');
      results.forEach((result) => {
        if (
          result.body === null ||
          _isMiss(result.body.data) ||
          _.isEmpty(result.body.data)
        ) {
          lookupResults.push({
            entity: result.entity,
            data: null
          });
        } else {
          lookupResults.push({
            entity: result.entity,
            data: {
              summary: [],
              details: result.body
            }
          });
        }
      });

      Logger.debug({ lookupResults }, 'Results');
      cb(null, lookupResults);
    });
  });
}

function _isMiss(body) {
  return !body || (body && Array.isArray(body) && body.length === 0);
}

function validateStringOption(errors, options, optionName, errMessage) {
  if (
    typeof options[optionName].value !== 'string' ||
    (typeof options[optionName].value === 'string' &&
      options[optionName].value.length === 0)
  )
    errors.push({
      key: optionName,
      message: errMessage
    });
}

const validateUrlOption = ({ value: url }, otherErrors = []) =>
  url &&
  url.endsWith('//') &&
  otherErrors.push({
    key: 'url',
    message: 'Your Url must not end with a //'
  });

function validateOptions(options, callback) {
  let errors = [];

  validateUrlOption(options.url, errors);
  validateStringOption(errors, options, 'url', 'You must provide a valid API URL');
  validateStringOption(
    errors,
    options,
    'securityToken',
    'You must provide a valid Security Token'
  );
  callback(null, errors);
}

module.exports = {
  doLookup,
  startup,
  validateOptions
};
