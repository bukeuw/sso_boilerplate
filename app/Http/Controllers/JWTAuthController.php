<?php

namespace App\Http\Controllers;

use App\User;
use Illuminate\Support\Facades\Auth;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', [
            'except' => [
                'login',
                'loginV2',
                'register',
            ]
        ]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(LoginRequest $request)
    {
        $credentials = $request->only(['email', 'password']);

        if (! $token = Auth::attempt($credentials)) {
            return response()->json([
                'error' => 'Unauthorized'
            ], 401);
        }

        return $this->respondWithToken($token);
    }

    public function loginV2(LoginRequest $request)
    {
        try {
            $credentials = $request->only(['email', 'password']);
            $client = new Client([
                'base_uri' => env('SSO_URL', ''),
            ]);
            $response = $client->request('POST', 'user', [
                'form_params' => [
                    'username' => $credentials['email'],
                    'password' => $credentials['password'],
                    'app' => env('SSO_APP_NAME', 'universal'),
                ]
            ]);

            $jsonData = json_decode($response->getBody()->getContents());


            $token = $jsonData->token;

            $tokenParts = explode('.', $token);
            $header = base64_decode($tokenParts[0]);
            $payload = base64_decode($tokenParts[1]);
            $signatureProvided = $tokenParts[2];
            $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
            $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
            $signature = hash_hmac('sha256', "$base64UrlHeader.$base64UrlPayload", env('JWT_SECRET', ''), true);
            $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
            $signatureValid = ($base64UrlSignature === $signatureProvided);

            if ($signatureValid) {
                $user = User::find($jsonData->data->id);
                $newToken = auth()->login($user);
                return response()->json([
                    'status' => true,
                    'message' => 'Success get data user',
                    'data' => json_decode($payload, true),
                    'token'=> $newToken,
                ], 200);
            } else {
                return response()->json([
                    'status' => false,
                    'message' => 'Token invalid'
                ], 404);
            }
        } catch (RequestException $ex) {
            $error = json_decode($ex->getResponse()->getBody());

            return response()->json([
                'message' => $error->messages,
            ], 401);
        }
    }

    /**
     * Register a user
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(RegisterRequest $request)
    {
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);

        if (!$user) {
            return response()->json(['error' => 'Failed to create user'], 400);
        }

        return response()->json([
            'success' => true,
        ]);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function user()
    {
        return response()->json([
            'user' => Auth::user()
        ]);
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        Auth::logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(Auth::refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => Auth::factory()->getTTL() * 60
        ]);
    }
}
