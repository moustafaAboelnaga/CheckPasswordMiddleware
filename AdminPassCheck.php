<?php

namespace App\Http\Middleware;

use Closure;
use Auth;
use Illuminate\Support\Facades\Session;

class CheckPasswordMiddleware
{
    /**
     * Prevent Auth Sesssion From Pressisting after Changing Password
     *
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        //check if user authenticated or not
        if (! Auth::check()) {
            return redirect('/');
        }
        // Definig session and password vairables
        $session = session('password_hash');
        $pass =  Auth::user()->getAuthPassword();
        //check if session null that's mean that user isn't logged and previous password not saved in sesssion so we'll store the new one resume his request
        if ($session == null) {
            session()->put(['password_hash' => Auth::guard('admin')->user()->getAuthPassword()]);
            return $next($request);
        }
        //if session is not null
        else
        {
            // if hased password stored in session equql to the current password of the user we'll resume his request
            if($session == $pass)
                return $next($request);
            //if not we'll end his session and logout 
            else
                \Session::forget('password_hash');
            Session::flush();
            Auth::logout();
            return redirect('login');
        }
        return $next($request);
    }
}
