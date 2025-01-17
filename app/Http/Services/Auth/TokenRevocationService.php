<?php

namespace App\Http\Services\Auth;

use Illuminate\Http\Request;

class TokenRevocationService
{
    public function handle(Request $request)
    {
        $request->user()->tokens()->delete();
    }
}