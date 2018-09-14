<?php

namespace jeremykenedy\laravelusers\App\Http\Controllers;

use App\Http\Controllers\Controller;
use Auth;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Validator;

class UsersManagementController extends Controller
{
    private $_authEnabled;
    private $_rolesEnabled;
    private $_rolesMiddlware;
    private $_rolesMiddleWareEnabled;

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->_authEnabled = config('laravelusers.authEnabled');
        $this->_rolesEnabled = config('laravelusers.rolesEnabled');
        $this->_rolesMiddlware = config('laravelusers.rolesMiddlware');
        $this->_rolesMiddleWareEnabled = config('laravelusers.rolesMiddlwareEnabled');

        if ($this->_authEnabled) {
            $this->middleware('auth');
        }

        if ($this->_rolesEnabled && $this->_rolesMiddleWareEnabled) {
            $this->middleware($this->_rolesMiddlware);
        }
    }

    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        $pagintaionEnabled = config('laravelusers.enablePagination');

        if ($pagintaionEnabled) {
            $users = config('laravelusers.defaultUserModel')::paginate(config('laravelusers.paginateListSize'));
        } else {
            $users = config('laravelusers.defaultUserModel')::all();
        }

        $data = [
            'users' => $users,
            'pagintaionEnabled' => $pagintaionEnabled,
        ];

        return view(config('laravelusers.showUsersBlade'), $data);
    }

    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function create()
    {
        $roles = [];

        if ($this->_rolesEnabled) {
            $roles = config('laravelusers.roleModel')::all();
        }

        $data = [
            'rolesEnabled' => $this->_rolesEnabled,
            'roles' => $roles,
        ];

        return view(config('laravelusers.createUserBlade'))->with($data);
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {

        $rules = [
            'name' => 'required|string|max:255|unique:users',
            'email' => 'required|email|max:255|unique:users',
            'password' => 'required|string|confirmed|min:6',
            'password_confirmation' => 'required|string|same:password',
            'type' => 'required',
            'phone' => 'required',
            'cin' => 'required',
            'permis' => 'required',
            'adresse' => 'required',
            'ville' => 'required',
            'date_naissance' => 'required',
        ];

        if ($this->_rolesEnabled) {
            $rules['role'] = 'required';
        }

        $messages = [
            'name.unique' => trans('laravelusers::laravelusers.messages.userNameTaken'),
            'name.required' => trans('laravelusers::laravelusers.messages.userNameRequired'),
            'email.required' => trans('laravelusers::laravelusers.messages.emailRequired'),
            'email.email' => trans('laravelusers::laravelusers.messages.emailInvalid'),
            'password.required' => trans('laravelusers::laravelusers.messages.passwordRequired'),
            'password.min' => trans('laravelusers::laravelusers.messages.PasswordMin'),
            'password.max' => trans('laravelusers::laravelusers.messages.PasswordMax'),
            'type.required' => trans('laravelusers::laravelusers.messages.roleRequired'),
        ];

        $validator = Validator::make($request->all(), $rules, $messages);

        if ($validator->fails()) {
            return back()->withErrors($validator)->withInput();
        }

        $user = config('laravelusers.defaultUserModel')::create([
            'name' => $request->input('name'),
            'email' => $request->input('email'),
            'password' => bcrypt($request->input('password')),
            'phone' => $request->input('phone'),
            'cin' => $request->input('cin'),
            'permis' => $request->input('permis'),
            'adresse' => $request->input('adresse'),
            'ville' => $request->input('ville'),
            'date_naissance' => $request->input('date_naissance'),
            'observation' => $request->input('observation'),
        ]);

        if ($this->_rolesEnabled) {
            $user->attachRole($request->input('role'));
            $user->save();
        }

        $user->type = $request->input('type');
        $user->save();

        return redirect('users')->with('success', trans('laravelusers::laravelusers.messages.user-creation-success'));
    }

    /**
     * Display the specified resource.
     *
     * @param int $id
     *
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {

        $user = config('laravelusers.defaultUserModel')::find($id);
        $config = array();
        $config['center'] = $user->location ?  $user->location :  $user->ville;
        app('map')->initialize($config);

        function random_color()
        {
            $color = str_pad(dechex(mt_rand(0, 255)), 2, '0', STR_PAD_LEFT);
            $color .= str_pad(dechex(mt_rand(0, 255)), 2, '0', STR_PAD_LEFT);
            $color .= str_pad(dechex(mt_rand(0, 255)), 2, '0', STR_PAD_LEFT);
            return $color;
        }
        if ($user->location) {
            $marker = array();
            $marker['position'] = $user->location;
            $marker['infowindow_content'] = $user->name;
            $marker['animation'] = 'DROP';
            //$marker['onclick'] = 'window.location.replace("' . route('users') . '/' . $user->id . '");';
            $marker['icon'] = 'http://chart.apis.google.com/chart?chst=d_map_pin_letter&chld=' . substr($user->name, 0, 1) . '|' . random_color() . '|000000';
            app('map')->add_marker($marker);
        }
        $map = app('map')->create_map();
        return view(config('laravelusers.showIndividualUserBlade'))->with([
            "map" => $map,
            "user" => $user
        ]);
    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param int $id
     *
     * @return \Illuminate\Http\Response
     */
    public function edit($id)
    {
        $user = config('laravelusers.defaultUserModel')::findOrFail($id);
        $roles = [];
        $currentRole = '';

        if ($this->_rolesEnabled) {
            $roles = config('laravelusers.roleModel')::all();

            foreach ($user->roles as $user_role) {
                $currentRole = $user_role;
            }
        }

        $data = [
            'user' => $user,
            'rolesEnabled' => $this->_rolesEnabled,
        ];

        if ($this->_rolesEnabled) {
            $data['roles'] = $roles;
            $data['currentRole'] = $currentRole;
        }

        return view(config('laravelusers.editIndividualUserBlade'))->with($data);
    }

    /**
     * Update the specified resource in storage.
     *
     * @param \Illuminate\Http\Request $request
     * @param int                      $id
     *
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, $id)
    {
        $currentUser = Auth::user();
        $user = config('laravelusers.defaultUserModel')::find($id);
        $emailCheck = ($request->input('email') != '') && ($request->input('email') != $user->email);
        $passwordCheck = $request->input('password') != null;

        $rules = [
            'name' => 'required|max:255',
        ];

        if ($emailCheck) {
            $rules['email'] = 'required|email|max:255|unique:users';
        }

        if ($passwordCheck) {
            $rules['password'] = 'required|string|min:6|max:20|confirmed';
            $rules['password_confirmation'] = 'required|string|same:password';
        }
        $rules['type'] = 'required';

        if ($this->_rolesEnabled) {
            $rules['role'] = 'required';
        }
        if ($rules['type'] == "super") {
            if (!$currentUser->isSuperAdmin()) {
                return back()->with('error', 'You can\'t give this privilege!');
            }
        }
        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return back()->withErrors($validator)->withInput();
        }

        $user->name = $request->input('name');

        if ($emailCheck) {
            $user->email = $request->input('email');
        }

        if ($passwordCheck) {
            $user->password = bcrypt($request->input('password'));
        }

        $user->type = $request->input('type');
        if ($this->_rolesEnabled) {
            $user->detachAllRoles();
            $user->attachRole($request->input('role'));
        }

        $user->phone = $request->input('phone');
        $user->cin = $request->input('cin');
        $user->permis = $request->input('permis');
        $user->adresse = $request->input('adresse');
        $user->ville = $request->input('ville');
        $user->date_naissance = $request->input('date_naissance');
        $user->observation = $request->input('observation');
        $user->save();

        return back()->with('success', trans('laravelusers::laravelusers.messages.update-user-success'));
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param int $id
     *
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        $currentUser = Auth::user();
        $user = config('laravelusers.defaultUserModel')::findOrFail($id);

        if ($currentUser->id != $user->id) {
            if ($currentUser->isSuperAdmin()) {
                $user->delete();
                return redirect('users')->with('success', trans('laravelusers::laravelusers.messages.delete-success'));
            } elseif ($currentUser->isAdmin()) {
                if (!$user->isAdmin()) {
                    $user->delete();
                    return redirect('users')->with('success', trans('laravelusers::laravelusers.messages.delete-success'));
                } else {
                    return back()->with('error', "You can't delete this user.");
                }
            } else {
                return back()->with('error', '?');
            }
        } else {
            return back()->with('error', trans('laravelusers::laravelusers.messages.cannot-delete-yourself'));
        }

    }

    /**
     * Method to search the users.
     *
     * @param Request $request
     *
     * @return \Illuminate\Http\Response
     */
    public function search(Request $request)
    {
        $searchTerm = $request->input('user_search_box');
        $searchRules = [
            'user_search_box' => 'required|string|max:255',
        ];
        $searchMessages = [
            'user_search_box.required' => 'Search term is required',
            'user_search_box.string' => 'Search term has invalid characters',
            'user_search_box.max' => 'Search term has too many characters - 255 allowed',
        ];

        $validator = Validator::make($request->all(), $searchRules, $searchMessages);

        if ($validator->fails()) {
            return response()->json([
                json_encode($validator),
            ], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        $results = config('laravelusers.defaultUserModel')::where('id', 'like', $searchTerm . '%')
            ->orWhere('name', 'like', $searchTerm . '%')
            ->orWhere('cin', 'like', $searchTerm . '%')
            ->orWhere('permis', 'like', $searchTerm . '%')
            ->orWhere('adresse', 'like', $searchTerm . '%')
            ->orWhere('ville', 'like', $searchTerm . '%')
            ->orWhere('name', 'like', $searchTerm . '%')
            ->orWhere('date_naissance', 'like', $searchTerm . '%')
            ->orWhere('phone', 'like', $searchTerm . '%')
            ->orWhere('email', 'like', $searchTerm . '%')->get();

        // Attach roles to results
        foreach ($results as $result) {
            $roles = [
                'roles' => $result->roles,
            ];
            $result->push($roles);
        }

        return response()->json([
            json_encode($results),
        ], Response::HTTP_OK);
    }
}
