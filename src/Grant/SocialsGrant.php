<?php 
	
namespace App\Http\Grant;


use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use League\OAuth2\Server\Grant\AbstractGrant;
use Psr\Http\Message\ServerRequestInterface;
use Illuminate\Http\Request;
use App\Models\v1\SocialAccounts;
use Laravel\Passport\Bridge;
use Laravel\Passport\Bridge\User;

/**
 * 
 */
class SocialsGrant extends AbstractGrant
{
	
		/**
     * @param UserRepositoryInterface         $userRepository
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     */
    public function __construct(
        UserRepositoryInterface $userRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository
    ) {
        $this->setUserRepository($userRepository);
        $this->setRefreshTokenRepository($refreshTokenRepository);

        $this->refreshTokenTTL = new \DateInterval('P1M');
    }

    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $accessTokenTTL
    ) {
        // Validate request
        $client = $this->validateClient($request);
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request, $this->defaultScope));
        $user = $this->validateUser($request, $client);

        // Finalize the requested scopes
        $finalizedScopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $user->getIdentifier());

        // Issue and persist new tokens
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $user->getIdentifier(), $finalizedScopes);
        $refreshToken = $this->issueRefreshToken($accessToken);

        // Send events to emitter
        $this->getEmitter()->emit(new RequestEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request));
        $this->getEmitter()->emit(new RequestEvent(RequestEvent::REFRESH_TOKEN_ISSUED, $request));

        // Inject tokens into response
        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        return $responseType;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ClientEntityInterface  $client
     *
     * @throws OAuthServerException
     *
     * @return UserEntityInterface
     */
    protected function validateUser(ServerRequestInterface $request, ClientEntityInterface $client)
    {
        $provider_user_id = $this->getRequestParameter('provider_user_id', $request);
        if (is_null($provider_user_id)) {
            throw OAuthServerException::invalidRequest('provider_user_id');
        }

        $provider_user_name = $this->getRequestParameter('provider_user_name', $request);
        if (is_null($provider_user_name)) {
            throw OAuthServerException::invalidRequest('provider_user_name');
        }

        $user = $this->getUserFromSocialCredentials(new Request($request->getParsedBody()));
        if($user instanceof UserEntityInterface === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));

            throw OAuthServerException::invalidCredentials();
        }

        return $user;
    }

     /**
     * 
     * {@inheritdoc}
     */
    private function getUserFromSocialCredentials(Request $request)
    {
    	 $provider = config('auth.guards.api.provider');

        if (is_null($model = config('auth.providers.'.$provider.'.model'))) {
            throw new RuntimeException('Unable to determine authentication model from configuration.');
        }
        $socialAccount = SocialAccounts::where('provider_user_id', $request->provider_user_id)->where('provider_user_name',$request->provider_user_name)->first();

        if (!$socialAccount) return;

        $user = $socialAccount->user()->first();
        if (!$socialAccount) ;

        return new User($user->getAuthIdentifier());
    }
    /**
     * 
     * {@inheritdoc}
     */
    public function getIdentifier()
    {
        return 'social_grant';
    }
}

 ?>