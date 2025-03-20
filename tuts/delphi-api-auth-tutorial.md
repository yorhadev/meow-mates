# Laravel Authentication with Delphi API (No Database)

This tutorial demonstrates how to implement Laravel authentication with a Delphi API backend without using a database in your Laravel application.

## Overview

This approach creates a custom authentication driver that communicates with your Delphi API for authentication while allowing you to use Laravel's built-in Auth facade. The main components are:

1. A custom user provider that interfaces with the Delphi API
2. A generic user class that implements Laravel's Authenticatable interface
3. Configuration for Laravel's auth system
4. Middleware to handle token refreshing

## Implementation Steps

### 1. Create a Custom User Provider

Create a class to handle communication with your Delphi API:

```php
<?php
// app/Auth/DelphiUserProvider.php

namespace App\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Facades\Http;

class DelphiUserProvider implements UserProvider
{
    protected $apiUrl;

    public function __construct(array $config)
    {
        $this->apiUrl = $config['api_url'];
    }

    public function retrieveById($identifier)
    {
        // Since we don't have a database, we'll use the session data
        $userData = session('user_data');
        if (!$userData || $userData['id'] != $identifier) {
            return null;
        }
        
        return $this->getGenericUser($userData);
    }

    public function retrieveByToken($identifier, $token)
    {
        // Not implemented for this provider
        return null;
    }

    public function updateRememberToken(Authenticatable $user, $token)
    {
        // Not implemented for this provider
    }

    public function retrieveByCredentials(array $credentials)
    {
        // We'll use this to check the credentials against the Delphi API
        $response = Http::post("{$this->apiUrl}/login", [
            'username' => $credentials['username'],
            'password' => $credentials['password'],
        ]);
        
        if ($response->successful()) {
            $userData = $response->json();
            
            // Store the token in session
            session([
                'delphi_api_token' => $userData['token'],
                'user_data' => $userData['user'] ?? [],
                'token_expires_at' => now()->addMinutes($userData['expires_in'] ?? 60),
            ]);
            
            return $this->getGenericUser($userData['user'] ?? []);
        }
        
        return null;
    }

    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        // We've already validated in retrieveByCredentials
        return true;
    }
    
    protected function getGenericUser($userData)
    {
        // Create a generic user object that implements Authenticatable
        return new DelphiUser($userData);
    }
}
```

### 2. Create a Custom User Class

Create a generic user class that implements the Authenticatable interface:

```php
<?php
// app/Auth/DelphiUser.php

namespace App\Auth;

use Illuminate\Contracts\Auth\Authenticatable;

class DelphiUser implements Authenticatable
{
    protected $attributes;

    public function __construct(array $attributes)
    {
        $this->attributes = $attributes;
    }

    public function getAuthIdentifierName()
    {
        return 'id';
    }

    public function getAuthIdentifier()
    {
        return $this->attributes[$this->getAuthIdentifierName()] ?? null;
    }

    public function getAuthPassword()
    {
        return $this->attributes['password'] ?? null;
    }

    public function getRememberToken()
    {
        return $this->attributes[$this->getRememberTokenName()] ?? null;
    }

    public function setRememberToken($value)
    {
        $this->attributes[$this->getRememberTokenName()] = $value;
    }

    public function getRememberTokenName()
    {
        return 'remember_token';
    }
    
    // Add methods to access user attributes
    public function getAttribute($key)
    {
        return $this->attributes[$key] ?? null;
    }
    
    public function getAttributes()
    {
        return $this->attributes;
    }
    
    // Magic method to access attributes directly
    public function __get($key)
    {
        return $this->getAttribute($key);
    }
}
```

### 3. Register the Custom User Provider

Create a service provider to register your custom user provider:

```php
<?php
// app/Providers/DelphiAuthServiceProvider.php

namespace App\Providers;

use App\Auth\DelphiUserProvider;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Auth;

class DelphiAuthServiceProvider extends ServiceProvider
{
    public function boot()
    {
        Auth::provider('delphi', function ($app, array $config) {
            return new DelphiUserProvider($config);
        });
    }
}
```

### 4. Update the Auth Configuration

Update your `config/auth.php` file to use the new provider:

```php
'providers' => [
    'users' => [
        'driver' => 'delphi',
        'api_url' => env('DELPHI_API_URL', 'http://delphi-api'),
    ],
],

'guards' => [
    'web' => [
        'driver' => 'session',
        'provider' => 'users',
    ],
    // ...
],
```

### 5. Register the Service Provider

Add your new service provider to the `providers` array in `config/app.php`:

```php
'providers' => [
    // ...
    App\Providers\DelphiAuthServiceProvider::class,
],
```

### 6. Create a Middleware to Refresh Tokens

```php
<?php
// app/Http/Middleware/RefreshDelphiToken.php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;

class RefreshDelphiToken
{
    public function handle(Request $request, Closure $next)
    {
        if (Auth::check() && session()->has('token_expires_at')) {
            // Check if token is about to expire
            if (now()->addMinutes(5) > session('token_expires_at')) {
                // Refresh the token - adjust this to match your Delphi API
                $response = Http::withHeaders([
                    'Authorization' => 'Bearer ' . session('delphi_api_token'),
                ])->post(config('auth.providers.users.api_url') . '/refresh-token');
                
                if ($response->successful()) {
                    $data = $response->json();
                    session([
                        'delphi_api_token' => $data['token'],
                        'token_expires_at' => now()->addMinutes($data['expires_in'] ?? 60),
                    ]);
                } else {
                    // Token refresh failed, log the user out
                    Auth::logout();
                    return redirect()->route('login');
                }
            }
        }
        
        return $next($request);
    }
}
```

### 7. Register the Middleware

Add the middleware to the `$middlewareGroups` or `$routeMiddleware` array in `app/Http/Kernel.php`:

```php
protected $middlewareGroups = [
    'web' => [
        // ...
        \App\Http\Middleware\RefreshDelphiToken::class,
    ],
];

// Or as a route middleware
protected $routeMiddleware = [
    // ...
    'refresh.delphi.token' => \App\Http\Middleware\RefreshDelphiToken::class,
];
```

### 8. Add a Service to Make Authenticated Requests

```php
<?php
// app/Services/DelphiApiService.php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Http\Client\Response;

class DelphiApiService
{
    protected string $baseUrl;
    
    public function __construct()
    {
        $this->baseUrl = config('auth.providers.users.api_url');
    }
    
    public function makeAuthenticatedRequest(string $endpoint, array $data = [], string $method = 'get')
    {
        $token = session('delphi_api_token');
        
        return Http::withHeaders([
            'Authorization' => "Bearer {$token}",
            // Add any other headers required by your Delphi API
        ])->$method("{$this->baseUrl}/{$endpoint}", $data);
    }
}
```

### 9. Create the Authentication Controller

```php
<?php
// app/Http/Controllers/AuthController.php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Inertia\Inertia;

class AuthController extends Controller
{
    public function showLogin()
    {
        return Inertia::render('Auth/Login');
    }
    
    public function login(Request $request)
    {
        $credentials = $request->validate([
            'username' => 'required|string',
            'password' => 'required|string',
        ]);
        
        if (Auth::attempt($credentials)) {
            $request->session()->regenerate();
            
            return redirect()->intended('/dashboard');
        }
        
        return back()->withErrors([
            'credentials' => 'The provided credentials do not match our records.',
        ]);
    }
    
    public function logout(Request $request)
    {
        Auth::logout();
        
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        
        return redirect('/login');
    }
}
```

### 10. Create Routes

Add routes in `routes/web.php`:

```php
use App\Http\Controllers\AuthController;
use App\Http\Controllers\DashboardController;

Route::get('/login', [AuthController::class, 'showLogin'])->name('login');
Route::post('/login', [AuthController::class, 'login']);
Route::post('/logout', [AuthController::class, 'logout'])->name('logout');

// Protected routes
Route::middleware('auth')->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index'])->name('dashboard');
    // Add other protected routes
});
```

### 11. Create a Login Form in Vue with Inertia

```vue
<!-- resources/js/Pages/Auth/Login.vue -->
<template>
  <div class="min-h-screen flex items-center justify-center bg-gray-50">
    <div class="max-w-md w-full p-6 bg-white rounded-lg shadow-md">
      <h1 class="text-xl font-semibold mb-6">Login</h1>
      
      <form @submit.prevent="submit">
        <div class="mb-4">
          <label class="block text-sm font-medium text-gray-700">Username</label>
          <input 
            v-model="form.username" 
            type="text" 
            class="mt-1 block w-full rounded-md border-gray-300 shadow-sm"
          />
          <div v-if="errors.username" class="text-red-500 text-sm mt-1">
            {{ errors.username }}
          </div>
        </div>
        
        <div class="mb-6">
          <label class="block text-sm font-medium text-gray-700">Password</label>
          <input 
            v-model="form.password" 
            type="password" 
            class="mt-1 block w-full rounded-md border-gray-300 shadow-sm"
          />
          <div v-if="errors.password" class="text-red-500 text-sm mt-1">
            {{ errors.password }}
          </div>
        </div>
        
        <div v-if="errors.credentials" class="mb-4 text-red-500 text-sm">
          {{ errors.credentials }}
        </div>
        
        <button 
          type="submit" 
          class="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 text-white rounded-md"
          :disabled="processing"
        >
          {{ processing ? 'Logging in...' : 'Login' }}
        </button>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { useForm } from '@inertiajs/vue3';

const form = useForm({
  username: '',
  password: '',
});

const processing = ref(false);

const submit = () => {
  processing.value = true;
  form.post('/login', {
    onFinish: () => {
      processing.value = false;
    },
  });
};
</script>
```

### 12. Share Auth Data with Inertia

Update your `HandleInertiaRequests` middleware to share auth data with all Inertia requests:

```php
public function share(Request $request)
{
    return array_merge(parent::share($request), [
        'auth' => [
            'user' => Auth::check() ? Auth::user()->getAttributes() : null,
        ],
    ]);
}
```

## Using Authentication in Your App

With this setup, you can use Laravel's Auth facade as usual:

```php
// Check if user is logged in
if (Auth::check()) {
    // User is logged in
}

// Get the current user
$user = Auth::user();

// Access user attributes
$username = Auth::user()->username;
```

In your Vue components with Inertia:

```vue
<template>
  <div>
    <p v-if="$page.props.auth.user">
      Hello, {{ $page.props.auth.user.name }}!
    </p>
  </div>
</template>

<script setup>
import { usePage } from '@inertiajs/vue3';

const user = usePage().props.auth.user;
</script>
```

## Handling API Requests

To make authenticated requests to your Delphi API:

```php
// In a controller
public function getUserData(DelphiApiService $apiService)
{
    $response = $apiService->makeAuthenticatedRequest('user-data');
    
    if ($response->successful()) {
        return Inertia::render('UserData', [
            'userData' => $response->json(),
        ]);
    }
    
    return back()->withErrors([
        'error' => 'Failed to fetch user data',
    ]);
}
```

## Conclusion

This approach allows you to use Laravel's built-in authentication system with a Delphi API backend without requiring a database in your Laravel application. The authentication state is maintained using sessions, and the tokens are refreshed automatically when they're about to expire.

The main benefits of this approach include:

1. Using Laravel's standard Auth facade and middleware
2. Maintaining clean separation between your frontend and backend
3. Handling token expiration and refresh automatically
4. No database required in your Laravel application
