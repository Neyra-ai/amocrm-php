<?php

namespace AmoCRM\Request;

use AmoCRM\OAuth\OAuthTokenPersistenceHandlerInterface;
use AmoCRM\OAuth2\Client\Provider\AmoCRM;
use DateTime;
use AmoCRM\Exception;
use AmoCRM\NetworkException;
use League\OAuth2\Client\Grant\RefreshToken;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;

/**
 * Class Request
 *
 * Класс отправляющий запросы к API amoCRM используя cURL
 *
 * @package AmoCRM\Request
 * @author dotzero <mail@dotzero.ru>
 * @link http://www.dotzero.ru/
 * @link https://github.com/dotzero/amocrm-php
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
class Request
{
    /**
     * @var bool Использовать устаревшую схему авторизации
     */
    protected $v1 = false;

    /**
     * @var bool Флаг вывода отладочной информации
     */
    private $debug = false;

    /**
     * @var ParamsBag|null Экземпляр ParamsBag для хранения аргументов
     */
    private $parameters = null;

    /**
     * @var AmoCRM
     */
    private $oauthProvider;

    /**
     * @var OAuthTokenPersistenceHandlerInterface
     */
    private $oauthTokenPersistenceHandler;

    /**
     * @var CurlHandle Экземпляр CurlHandle
     */
    private $curlHandle;

    /**
     * @var int|null Последний полученный HTTP код
     */
    private $lastHttpCode = null;

    /**
     * @var string|null Последний полученный HTTP ответ
     */
    private $lastHttpResponse = null;

    /**
     * Request constructor
     *
     * @param ParamsBag $parameters Экземпляр ParamsBag для хранения аргументов
     * @param AmoCRM $oauthProvider
     * @param OAuthTokenPersistenceHandlerInterface $oauthTokenPersistenceHandler
     * @param CurlHandle|null $curlHandle Экземпляр CurlHandle для повторного использования
     */
    public function __construct(
        ParamsBag $parameters,
        AmoCRM $oauthProvider,
        OAuthTokenPersistenceHandlerInterface $oauthTokenPersistenceHandler,
        CurlHandle $curlHandle = null
    ) {
        $this->parameters = $parameters;
        $this->oauthProvider = $oauthProvider;
        $this->oauthTokenPersistenceHandler = $oauthTokenPersistenceHandler;
        $this->curlHandle = $curlHandle !== null ? $curlHandle : new CurlHandle();
    }

    /**
     * Установка флага вывода отладочной информации
     *
     * @param bool $flag Значение флага
     * @return $this
     */
    public function debug($flag = false)
    {
        $this->debug = (bool)$flag;

        return $this;
    }

    /**
     * Возвращает последний полученный HTTP код
     *
     * @return int|null
     */
    public function getLastHttpCode()
    {
        return $this->lastHttpCode;
    }

    /**
     * Возвращает последний полученный HTTP ответ
     *
     * @return null|string
     */
    public function getLastHttpResponse()
    {
        return $this->lastHttpResponse;
    }

    /**
     * Возвращает экземпляр ParamsBag для хранения аргументов
     *
     * @return ParamsBag|null
     */
    protected function getParameters()
    {
        return $this->parameters;
    }

    /**
     * Выполнить HTTP GET запрос и вернуть тело ответа
     *
     * @param string $url Запрашиваемый URL
     * @param array $parameters Список GET параметров
     * @param null|string $modified Значение заголовка IF-MODIFIED-SINCE
     * @return mixed
     * @throws Exception
     * @throws NetworkException
     */
    protected function getRequest($url, $parameters = [], $modified = null)
    {
        if (!empty($parameters)) {
            $this->parameters->addGet($parameters);
        }

        return $this->request($url, $modified);
    }

    /**
     * Выполнить HTTP POST запрос и вернуть тело ответа
     *
     * @param string $url Запрашиваемый URL
     * @param array $parameters Список POST параметров
     * @return mixed
     * @throws Exception
     * @throws NetworkException
     */
    protected function postRequest($url, $parameters = [])
    {
        if (!empty($parameters)) {
            $this->parameters->addPost($parameters);
        }

        return $this->request($url);
    }

    /**
     * Подготавливает список заголовков HTTP
     *
     * @param string $accessToken
     * @param mixed $modified Значение заголовка IF-MODIFIED-SINCE
     * @return array
     * @throws \Exception
     */
    protected function prepareHeaders(string $accessToken, $modified = null)
    {
        $headers = [
            'Connection: keep-alive',
            'Content-Type: application/json',
        ];

        if ($modified !== null) {
            if (is_int($modified)) {
                $headers[] = 'IF-MODIFIED-SINCE: ' . $modified;
            } else {
                $headers[] = 'IF-MODIFIED-SINCE: ' . (new DateTime($modified))->format(DateTime::RFC1123);
            }
        }

        $providerHeaders = $this->oauthProvider->getHeaders($accessToken);
        $providerHeadersCurlConverted = [];

        foreach ($providerHeaders as $header => $value) {
            $providerHeadersCurlConverted[] = sprintf('%s: %s', $header, $value);
        }

        return array_merge($headers, $providerHeadersCurlConverted);
    }

    /**
     * Подготавливает URL для HTTP запроса
     *
     * @param string $url Запрашиваемый URL
     * @return string
     */
    protected function prepareEndpoint($url)
    {
        return sprintf('%s/%s', rtrim($this->oauthProvider->urlAccount(), '/'), ltrim($url, '/'));
    }

    /**
     * Выполнить HTTP запрос и вернуть тело ответа
     *
     * @param string $url Запрашиваемый URL
     * @param null|string $modified Значение заголовка IF-MODIFIED-SINCE
     * @return mixed
     * @throws Exception
     * @throws NetworkException
     * @throws IdentityProviderException
     */
    protected function request($url, $modified = null)
    {
        $state = $this->parameters->getAuth('state');
        $accessToken = $this->oauthTokenPersistenceHandler->getToken($state);

        if ($accessToken->hasExpired()) {
            $accessToken = $this->oauthProvider->getAccessToken(
                new RefreshToken(),
                ['refresh_token' => $accessToken->getRefreshToken()]
            );

            $this->oauthTokenPersistenceHandler->saveToken($state, $accessToken);
        }

        $headers = $this->prepareHeaders($accessToken->getToken(), $modified);
        $endpoint = $this->prepareEndpoint($url);

        $this->printDebug('url', $endpoint);
        $this->printDebug('headers', $headers);

        $ch = $this->curlHandle->open();

        curl_setopt($ch, CURLOPT_URL, $endpoint);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_ENCODING, '');

        if ($this->parameters->hasPost()) {
            $fields = json_encode([
                'request' => $this->parameters->getPost(),
            ]);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $fields);
            $this->printDebug('post params', $fields);
        }

        if ($this->parameters->hasProxy()) {
            curl_setopt($ch, CURLOPT_PROXY, $this->parameters->getProxy());
        }

        $result = curl_exec($ch);
        $info = curl_getinfo($ch);
        $error = curl_error($ch);
        $errno = curl_errno($ch);

        $this->curlHandle->close();

        $this->lastHttpCode = $info['http_code'];
        $this->lastHttpResponse = $result;

        $this->printDebug('curl_exec', $result);
        $this->printDebug('curl_getinfo', $info);
        $this->printDebug('curl_error', $error);
        $this->printDebug('curl_errno', $errno);

        if ($result === false && !empty($error)) {
            throw new NetworkException($error, $errno);
        }

        return $this->parseResponse($result, $info);
    }

    /**
     * Парсит HTTP ответ, проверяет на наличие ошибок и возвращает тело ответа
     *
     * @param string $response HTTP ответ
     * @param array $info Результат функции curl_getinfo
     * @return mixed
     * @throws Exception
     */
    protected function parseResponse($response, $info)
    {
        $result = json_decode($response, true);

        if (floor($info['http_code'] / 100) >= 3) {
            if (isset($result['response']['error_code']) && $result['response']['error_code'] > 0) {
                $code = $result['response']['error_code'];
            } elseif ($result !== null) {
                $code = 0;
            } else {
                $code = $info['http_code'];
            }
            if ($this->v1 === false && isset($result['response']['error'])) {
                throw new Exception($result['response']['error'], $code);
            } elseif (isset($result['response'])) {
                throw new Exception(json_encode($result['response']));
            } else {
                throw new Exception('Invalid response body.', $code);
            }
        } elseif (!isset($result['response'])) {
            return false;
        }

        return $result['response'];
    }

    /**
     * Вывода отладочной информации
     *
     * @param string $key Заголовок отладочной информации
     * @param mixed $value Значение отладочной информации
     * @param bool $return Возврат строки вместо вывода
     * @return mixed
     */
    protected function printDebug($key = '', $value = null, $return = false)
    {
        if ($this->debug !== true) {
            return false;
        }

        if (!is_string($value)) {
            $value = print_r($value, true);
        }

        $line = sprintf('[DEBUG] %s: %s', $key, $value);

        if ($return === false) {
            return print_r($line . PHP_EOL);
        }

        return $line;
    }
}
