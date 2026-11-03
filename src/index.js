import get from 'lodash/get.js';
import isEqual from 'lodash/isEqual.js';
import merge from 'lodash/merge.js';
import omit from 'lodash/omit.js';

const SECRET_KEYS = ['password', 'token', 'privateKey'];

export function mergeLayers(...layers) {
  return merge({}, ...layers);
}

export function redact(config) {
  return omit(config, SECRET_KEYS);
}

export function readPath(config, path, fallback = undefined) {
  return get(config, path, fallback);
}

export function sameConfig(a, b) {
  return isEqual(redact(a), redact(b));
}
