<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Auth;
use Validator;
use App\Models\User;

class AuthController extends Controller
{
/* dn một hàm tạo (constructor) cho AuthController, trong đó middleware 'auth:api' được áp dụng 
    cho tất cả các phương thức trong AuthController, trừ 'login' và 'register'.
     Điều này có nghĩa là các phương thức trong AuthController sẽ yêu cầu xác thực (authorization) 
     thông qua JWT (middleware 'auth:api') để truy cập, ngoại trừ phương thức login và register 
     (được định nghĩa trong nhóm route trong api.php). */
    public function __construct(){
      $this->middleware('auth:api',['except'=>['login','register']]);
    }
 
    //register
   public function register(Request $request){
     $validator=Validator::make($request->all(),[
        'name'=>'required',
        'email'=>'required|string|email|unique:users',
        'password'=>'required|string|confirmed|min:6',
     ]);
     if($validator->fails()){
        return response()->json($validator->errors()->toJson(),400);
     }
     $user=User::create(array_merge(
        $validator->validated(),
        ['password'=>bcrypt($request->password)]
     ));
     return response()->json([
         'message'=>'User successfully register',
         'user'=>$user
     ],201);
   }
   //login
   public function login(Request $request){
    $validator=Validator::make($request->all(),[
        'email'=>'required|email',
        'password'=>'required|string|min:6'
    ]);
    if($validator->fails()){
        return response()->json($validator->errors()->toJson(),422);
     }
     if(!$token=auth()->attempt($validator->validated())){
        return response()->json(['error'=>'Unauthorized'],401);
     }
     return $this->createNewToken($token);
   }
    //create token
    public function createNewToken($token){
      return response()->json([
         'access_token'=>$token,
         'token_type'=>'bearer',
         'expires_in'=>auth()->factory()->getTTL()*60,
         'user'=>auth()->user()
      ]);
    }
   //logout 
   public function logout(){
    auth()->logout();
    return response()->json([
        'message'=>'User logged out'
    ]);
   }
  
   //see profile user
   public function profile(){
    return response()->json(auth()->user());
   }    

}
