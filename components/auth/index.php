<?php

require_once 'vendor/autoload.php';
require_once '../../src/App.php';

use Illuminate\Encryption\Encrypter;
use Illuminate\Routing\Router;
use Illuminate\Auth\Access\Gate;
use Illuminate\Auth\Middleware\RequirePassword;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Access\Gate as GateContract;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Contracts\Routing\UrlGenerator;
use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Events\Dispatcher;
use Illuminate\Hashing\HashManager;
use Illuminate\Http\Request;
use Illuminate\Pipeline\Pipeline;
use Illuminate\Session\SessionManager;

$container = App::getInstance();

$container->instance(\Illuminate\Contracts\Foundation\Application::class, $container);

$container->alias(\Illuminate\Contracts\Foundation\Application::class, \Illuminate\Contracts\Container\Container::class);

$request = Request::capture();

$container->bind(Illuminate\Http\Request::class, function ($app) use ($request) {
    return $request;
});

$container->alias(Illuminate\Http\Request::class, 'request');

$events = new Dispatcher(new Container);

$container->bind(Illuminate\Events\Dispatcher::class, function ($app) use ($events) {
    return $events;
});

$container->alias(Illuminate\Events\Dispatcher::class, 'events');

$container->bind(\Illuminate\Filesystem\Filesystem::class, function ($app) {
    return new \Illuminate\Filesystem\Filesystem;
});

$container->alias(\Illuminate\Filesystem\Filesystem::class, 'files');

$container->singleton('auth', function ($app) {
    // Once the authentication service has actually been requested by the developer
    // we will set a variable in the application indicating such. This helps us
    // know that we need to set any queued cookies in the after event later.
    $app['auth.loaded'] = true;

    return new Illuminate\Auth\AuthManager($app);
});

$container->alias('auth', \Illuminate\Contracts\Auth\Factory::class);

$container->singleton('auth.driver', function ($app) {
    return $app['auth']->guard();
});

$container->bind(
    AuthenticatableContract::class, function ($app) {
        return call_user_func($app['auth']->userResolver());
    }
);

$container->singleton(GateContract::class, function ($app) {
    return new Gate($app, function () use ($app) {
        return call_user_func($app['auth']->userResolver());
    });
});

$container->bind(
    RequirePassword::class, function ($app) {
        return new RequirePassword(
            $app[ResponseFactory::class],
            $app[UrlGenerator::class],
            $app['config']->get('auth.password_timeout')
        );
    }
);

$container->bind('config', function ($app) {
    return new Repository(require __DIR__ . '/config/app.php');
});

$container->rebinding('request', function ($app, $request) {
    $request->setUserResolver(function ($guard = null) use ($app) {
        return call_user_func($app['auth']->userResolver(), $guard);
    });
});

$container->rebinding('events', function ($app, $dispatcher) {
    if (! $app->resolved('auth')) {
        return;
    }

    if ($app['auth']->hasResolvedGuards() === false) {
        return;
    }

    if (method_exists($guard = $app['auth']->guard(), 'setDispatcher')) {
        $guard->setDispatcher($dispatcher);
    }
});

$container->singleton('hash', function ($app) {
    return new HashManager($app);
});

$container->singleton('hash.driver', function ($app) {
    return $app['hash']->driver();
});

// Now we need to fire up the session manager
$container->singleton('session', function ($app) {
    return new SessionManager($app);
});

$container->singleton('session.store', function ($app) {
    // First, we will create the session manager which is responsible for the
    // creation of the various session drivers when they are needed by the
    // application instance, and will resolve them on a lazy load basis.
    return $app->make('session')->driver();
});

$container->singleton('cookie', function ($app) {
    $config = $app->make('config')->get('session');

    return (new \Illuminate\Cookie\CookieJar)->setDefaultPathAndDomain(
        $config['path'], $config['domain'], $config['secure'], $config['same_site'] ?? null
    );
});

$container->singleton(EncrypterContract::class, function ($app) {
    return new Encrypter('1hs8heis)2(-*3d.');
});

$container->alias('cookie', \Illuminate\Contracts\Cookie\QueueingFactory::class);

// Configuration
// Note that you can set several directories where your templates are located
$pathsToTemplates = [__DIR__ . '/templates'];
$pathToCompiledTemplates = __DIR__ . '/compiled';

// Dependencies
$filesystem = new \Illuminate\Filesystem\Filesystem;
$eventDispatcher = new \Illuminate\Events\Dispatcher($container);

// Create View Factory capable of rendering PHP and Blade templates
$viewResolver = new \Illuminate\View\Engines\EngineResolver;
$bladeCompiler = new \Illuminate\View\Compilers\BladeCompiler($filesystem, $pathToCompiledTemplates);

$viewResolver->register('blade', function () use ($bladeCompiler) {
    return new \Illuminate\View\Engines\CompilerEngine($bladeCompiler);
});

$viewFinder = new \Illuminate\View\FileViewFinder($filesystem, $pathsToTemplates);
$viewFactory = new \Illuminate\View\Factory($viewResolver, $viewFinder, $eventDispatcher);
$viewFactory->setContainer($container);
\Illuminate\Support\Facades\Facade::setFacadeApplication($container);
$container->instance(\Illuminate\Contracts\View\Factory::class, $viewFactory);
$container->alias(
    \Illuminate\Contracts\View\Factory::class, 
    (new class extends \Illuminate\Support\Facades\View {
        public static function getFacadeAccessor() { return parent::getFacadeAccessor(); }
    })::getFacadeAccessor()
);
$container->instance(\Illuminate\View\Compilers\BladeCompiler::class, $bladeCompiler);
$container->alias(
    \Illuminate\View\Compilers\BladeCompiler::class, 
    (new class extends \Illuminate\Support\Facades\Blade {
        public static function getFacadeAccessor() { return parent::getFacadeAccessor(); }
    })::getFacadeAccessor()
);

$capsule = new Capsule;

$capsule->addConnection([
    'driver'    => 'mysql',
    'host'      => 'localhost',
    'database'  => 'illuminate_non_laravel',
    'username'  => 'root',
    'password'  => '',
    'charset'   => 'utf8',
    'collation' => 'utf8_unicode_ci',
    'prefix'    => '',
], 'mysql');

$capsule->addConnection([
    'driver'    => 'sqlite',
    'database' => 'database.sqlite',
    'prefix' => '',
]);

$capsule->setEventDispatcher($events);
$capsule->setAsGlobal();
$capsule->bootEloquent();

// Create the router instance
$router = new Router($events, $container);

// Global middlewares
$globalMiddleware = [
    \Illuminate\Cookie\Middleware\EncryptCookies::class,
    \Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse::class,
    \App\Middleware\StartSession::class,
    // \Illuminate\Session\Middleware\AuthenticateSession::class,
    \Illuminate\View\Middleware\ShareErrorsFromSession::class,
    \App\Middleware\VerifyCsrfToken::class,
    \Illuminate\Routing\Middleware\SubstituteBindings::class,
    
];

// Array middlewares
$routeMiddleware = [
    'auth' => \App\Middleware\Authenticate::class,
    'guest' => \App\Middleware\RedirectIfAuthenticated::class,
];

// Load middlewares to router
foreach ($routeMiddleware as $key => $middleware) {
    $router->aliasMiddleware($key, $middleware);
}

// Load the routes
require_once 'routes.php';

// Create a request from server variables
$request = Request::capture();

// Dispatching the request:
// When it comes to dispatching the request, you have two options:
// a) you either send the request directly through the router
// or b) you pass the request object through a stack of (global) middlewares
// then dispatch it.

// a. Dispatch the request through the router
// $response = $router->dispatch($request);

// b. Pass the request through the global middlewares pipeline then dispatch it through the router
$response = (new Pipeline($container))
    ->send($request)
    ->through($globalMiddleware)
    ->then(function ($request) use ($router) {
        return $router->dispatch($request);
    });

// Send the response back to the browser
$response->send();

// User::create([
//     'email' => 'admin',
//     'name' => 'admin',
//     'password' => $container->get('hash')->make('password'),
// ]);