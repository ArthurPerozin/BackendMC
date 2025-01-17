<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Http\Repositories\AuthRepository;
use App\Http\Requests\AuthRequest;
use App\Http\Services\Auth\GetPermissionsService;
use App\Http\Services\Auth\TokenRevocationService;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class AuthController
 * 
 * This controller handles authentication-related actions such as login and logout.
 * It utilizes various services and repositories to perform these actions.
 * 
 * @package App\Http\Controllers
 * 
 * @property AuthRepository $authRepository
 * @property TokenRevocationService $tokenRevocationService
 * @property GetPermissionsService $getPermissionsService
 */
class AuthController extends Controller
{
    /**
     * AuthController constructor.
     * 
     * @param AuthRepository $authRepository
     * @param TokenRevocationService $tokenRevocationService
     * @param GetPermissionsService $getPermissionsService
     */
    public function __construct(
        AuthRepository $authRepository,
        TokenRevocationService $tokenRevocationService,
        GetPermissionsService $getPermissionsService
    ) {
        $this->authRepository = $authRepository;
        $this->tokenRevocationService = $tokenRevocationService;
        $this->getPermissionsService = $getPermissionsService;
    }

    /**
     * Handle the authentication process.
     * 
     * @param AuthRequest $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function store(AuthRequest $request)
    {
        $data = $request->only('email', 'password');
        $authenticated = $this->authRepository->attempt($data);

        if (!$authenticated) {
            return $this->error("Não autorizado. Credenciais incorretas", Response::HTTP_UNAUTHORIZED);
        }

        $this->tokenRevocationService->handle($request);
        $profile_id = $request->user()->profile_id;
        $profile =$this->authRepository->findProfileById($profile_id);
        $permissionsUser = $this->getPermissionsService->handle($profile->name);
        $token = $request->user()->createToken('@academia', $permissionsUser);
        $token = $token->plainTextToken;

        return $this->response('Autorizado', Response::HTTP_OK, [
            'name' =>  $request->user()->name,
            'profile' => $profile->name,
            'permissions' => $permissionsUser,
            'token' => $token
        ]);
    }

    /**
     * Handle the logout process.
     * 
     * @param Request $request
     * @return \Illuminate\Http\Response
     */
    public function logout(Request $request)
    {
        $this->tokenRevocationService->handle($request);
        return response('', Response::HTTP_NO_CONTENT, []);
    }
}
