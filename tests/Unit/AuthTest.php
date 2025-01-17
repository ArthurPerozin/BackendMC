<?php

namespace Tests\Unit;

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;
use Tests\TestCase;

class AuthTest extends TestCase
{
    protected $mockUser;

    public function setUp(): void
    {
        parent::setUp();

        $this->mockUser = new User([
            'name' => 'Admin User',
            'email' => env('DEFAULT_EMAIL', 'admin@teste.com'),
            'password' => Hash::make(env('DEFAULT_PASSWORD', 'admMyCommands@2025!')),
            'profile_id' => 1,
        ]);
    }

    public function test_admin_can_login()
    {
        Auth::shouldReceive('attempt')
            ->once()
            ->with([
                'email' => env('DEFAULT_EMAIL', 'admin@teste.com'),
                'password' => env('DEFAULT_PASSWORD', 'admMyCommands@2025!'),
            ])
            ->andReturn(true);

        Auth::shouldReceive('user')
            ->once()
            ->andReturn($this->mockUser);

        $response = $this->postJson('/api/login', [
            'email' => env('DEFAULT_EMAIL', 'admin@teste.com'),
            'password' => env('DEFAULT_PASSWORD', 'admMyCommands@2025!'),
        ]);

        $response->assertStatus(Response::HTTP_OK)
            ->assertJsonStructure([
                'message',
                'status',
                'data' => [
                    'name',
                    'profile',
                    'permissions',
                    'token',
                ],
            ])->assertJson([
                'message' => 'Autorizado',
                'status' => Response::HTTP_OK,
                'data' => [
                    'name' => 'Admin User',
                    'profile' => 'ADMIN',
                ],
            ]);
    }

    public function test_admin_can_not_login_with_invalid_credentials()
    {
        Auth::shouldReceive('attempt')
            ->once()
            ->with([
                'email' => env('DEFAULT_EMAIL', 'admin@teste.com'),
                'password' => 'wrong-password',
            ])
            ->andReturn(false);

        $response = $this->postJson('/api/login', [
            'email' => env('DEFAULT_EMAIL', 'admin@teste.com'),
            'password' => 'wrong-password',
        ]);

        $response->assertStatus(Response::HTTP_UNAUTHORIZED)
            ->assertJson([
                'message' => 'Não autorizado. Credenciais incorretas',
                'status' => Response::HTTP_UNAUTHORIZED,
            ]);
    }

    public function test_admin_can_not_login_without_email()
    {
        $response = $this->postJson('/api/login', [
            'password' => env('DEFAULT_PASSWORD', 'admMyCommands@2025!'),
        ]);

        $response->assertStatus(Response::HTTP_BAD_REQUEST)
            ->assertJson([
                'message' => 'O email é obrigatório',
            ]);
    }

    public function test_admin_permissions_load_correctly()
    {
        Auth::shouldReceive('attempt')
            ->once()
            ->with([
                'email' => env('DEFAULT_EMAIL', 'admin@teste.com'),
                'password' => env('DEFAULT_PASSWORD', 'admMyCommands@2025!'),
            ])
            ->andReturn(true);

        Auth::shouldReceive('user')
            ->once()
            ->andReturn($this->mockUser);

        $response = $this->postJson('/api/login', [
            'email' => env('DEFAULT_EMAIL', 'admin@teste.com'),
            'password' => env('DEFAULT_PASSWORD', 'admMyCommands@2025!'),
        ]);

        $response->assertStatus(Response::HTTP_OK)
            ->assertJson([
                'data' => [
                    'permissions' => [
                        'create-users',
                        'get-users',
                        'delete-users',
                        'update-users',
                    ],
                ],
            ]);
    }

    public function test_admin_can_logout()
    {
        Auth::shouldReceive('logout')
            ->once();

        $response = $this->postJson('/api/logout');

        $response->assertStatus(Response::HTTP_NO_CONTENT);
    }
}
