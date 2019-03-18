import json
import jwt
import requests
from jwt.algorithms import RSAAlgorithm

from django.conf import settings
from django.core.cache import cache
from django.utils.functional import cached_property


class TokenError(Exception):
    pass


class TokenValidator:
    def __init__(self, aws_region, aws_user_pool, audience):
        self.aws_region = aws_region
        self.aws_user_pool = aws_user_pool
        self.audience = audience

    @cached_property
    def pool_url(self):
        return 'https://cognito-idp.%s.amazonaws.com/%s' % (
            self.aws_region, self.aws_user_pool)

    @cached_property
    def _json_web_keys(self):
        response = requests.get(self.pool_url + '/.well-known/jwks.json')
        response.raise_for_status()
        json_data = response.json()
        return {item['kid']: json.dumps(item) for item in json_data['keys']}

    def _get_public_key(self, token):
        try:
            headers = jwt.get_unverified_header(token)
        except jwt.DecodeError as exc:
            raise TokenError(str(exc))

        if getattr(settings, 'COGNITO_PUBLIC_KEYS_CACHING_ENABLED', False):
            cache_key = 'django_cognito_jwt:%s' % headers['kid']
            jwk_data = cache.get(cache_key)

            if not jwk_data:
                jwk_data = self._json_web_keys.get(headers['kid'])
                timeout = getattr(settings, 'COGNITO_PUBLIC_KEYS_CACHING_TIMEOUT', 300)
                cache.set(cache_key, jwk_data, timeout=timeout)
        else:
            jwk_data = self._json_web_keys.get(headers['kid'])

        if jwk_data:
            return RSAAlgorithm.from_jwk(jwk_data)

    def validate(self, token):
        public_key = self._get_public_key(token)
        if not public_key:
            raise TokenError("No key found for this token")

        try:
            custom_audience_name = getattr(settings, 'COGNITO_CUSTOM_AUDIENCE_NAME', 'aud')
            
            options = {
                # make expiration required, since it's important to security
                'require_exp': True,
                # disable audience verification and perform it explicitly
                'verify_aud': False if custom_audience_name else True,
            }
            
            jwt_data = jwt.decode(
                token,
                public_key,
                audience=self.audience,
                issuer=self.pool_url,
                algorithms=['RS256'],
                options=options,
            )
            
            # verify audience with support for custom audiance claims
            if custom_audience_name:
                self._validate_aud(jwt_data, self.audience, custom_audience_name)
        except (jwt.InvalidTokenError, jwt.ExpiredSignature, jwt.DecodeError) as exc:
            raise TokenError(str(exc))
        return jwt_data

    def _validate_aud(self, payload, audience, custom_audience_name):
        if audience_calim_name not in payload:
            # Application specified an audience, but it could not be
            # verified since the token does not contain a claim.
            raise MissingRequiredClaimError(custom_audience_name)

        if audience is None:
            # Application did not specify an audience, but
            # the token has the 'aud' claim
            raise InvalidAudienceError('Invalid audience')

        audience_claim = payload[custom_audience_name]
        if audience_claim != audience:
            raise InvalidAudienceError('Invalid audience')
