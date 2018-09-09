@extends(config('laravelusers.laravelUsersBladeExtended'))

@section('template_title')
    @lang('laravelusers::laravelusers.showing-user', ['name' => $user->name])
@endsection

@section('template_linked_css')
    @if(config('laravelusers.enabledDatatablesJs'))
        <link rel="stylesheet" type="text/css" href="{{ config('laravelusers.datatablesCssCDN') }}">
    @endif
    @if(config('laravelusers.fontAwesomeEnabled'))
        <link rel="stylesheet" type="text/css" href="{{ config('laravelusers.fontAwesomeCdn') }}">
    @endif
    @include('laravelusers::partials.styles')
    @include('laravelusers::partials.bs-visibility-css')
@endsection

@section('add2header')

    @if(config('laravelusers.fontAwesomeEnabled'))
        <link rel="stylesheet" type="text/css" href="{{ config('laravelusers.fontAwesomeCdn') }}">
    @endif
<script>
var centreGot = false;
// Try W3C Geolocation (Preferred)
				if(navigator.geolocation) {

navigator.geolocation.getCurrentPosition(function(position) {
    $.ajaxSetup({
        headers: {
            'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
        }
    });
    
    $.ajax({
        type: "POST",
        url: "/UserPos",
        data: {
            pos:position.coords.latitude+","+position.coords.longitude
        },
        success: function (msg) {
            console.log("User position updated!");
        },
        error: function (e, r, o) {
            console.log("Couldn't update user position!");
        }
    });
});
// Browser doesn't support Geolocation
				}else{
					console.log('Your browser does not support geolocation.');
				}

</script>

{!! $map['js'] !!}
@endsection

@section('content')
    <div class="container-fluid">
        @if(config('laravelusers.enablePackageBootstapAlerts'))
            <div class="row">
                <div class="col-lg-10 offset-lg-1">
                    @include('laravelusers::partials.form-status')
                </div>
            </div>
        @endif
        <div class="row">
            <div class="col-md-5 col-sm-12">
                <div class="card">
                    <div class="card-header">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            @lang('laravelusers::laravelusers.showing-user-title', ['name' => $user->name])
                            <div class="float-right">
                                <a href="{{ route('users') }}" class="btn btn-light btn-sm float-right" data-toggle="tooltip" data-placement="left" title="@lang('laravelusers::laravelusers.tooltips.back-users')">
                                    @if(config('laravelusers.fontAwesomeEnabled'))
                                        <i class="fas fa-fw fa-reply-all" aria-hidden="true"></i>
                                    @endif
                                    @lang('laravelusers::laravelusers.buttons.back-to-users')
                                </a>
                            </div>
                        </div>
                    </div>
                    <div class="card-body">
                        <h4 class="text-muted text-center">
                            {{ $user->name }}
                        </h4>
                        @if($user->email)
                            <p class="text-center" data-toggle="tooltip" data-placement="top" title="@lang('laravelusers::laravelusers.tooltips.email-user', ['user' => $user->email])">
                                {{ Html::mailto($user->email, $user->email) }}
                            </p>
                        @endif
                        <div class="row mb-4">
                            <div class="col-3 offset-3 col-sm-4 offset-sm-2 col-md-4 offset-md-2 col-lg-3 offset-lg-3">
                                <a href="/users/{{$user->id}}/edit" class="btn btn-block btn-md btn-warning">
                                    @lang('laravelusers::laravelusers.buttons.edit-user')
                                </a>
                            </div>
                            <div class="col-3 col-sm-4 col-md-4 col-lg-3">
                                {!! Form::open(array('url' => 'users/' . $user->id, 'class' => 'form-inline')) !!}
                                    {!! Form::hidden('_method', 'DELETE') !!}
                                    {!! Form::button(trans('laravelusers::laravelusers.buttons.delete-user'), array('class' => 'btn btn-danger btn-md btn-block','type' => 'button', 'data-toggle' => 'modal', 'data-target' => '#confirmDelete', 'data-title' => 'Delete User', 'data-message' => 'Are you sure you want to delete this user?')) !!}
                                {!! Form::close() !!}
                            </div>
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <div class="row">
                                    <div class="col-4 col-sm-3">
                                        <strong>
                                            @lang('laravelusers::laravelusers.show-user.id')
                                        </strong>
                                    </div>
                                    <div class="col-8 col-sm-9">
                                        {{ $user->id }}
                                    </div>
                                </div>
                            </li>
                            @if ($user->name)
                                <li class="list-group-item">
                                    <div class="row">
                                        <div class="col-4 col-sm-3">
                                            <strong>
                                                @lang('laravelusers::laravelusers.show-user.name')
                                            </strong>
                                        </div>
                                        <div class="col-8 col-sm-9">
                                            {{ $user->name }}
                                        </div>
                                    </div>
                                </li>
                            @endif
                            @if ($user->phone)
                                <li class="list-group-item">
                                    <div class="row">
                                        <div class="col-4 col-sm-3">
                                            <strong>
                                                phone
                                            </strong>
                                        </div>
                                        <div class="col-8 col-sm-9">
                                            {{ $user->phone }}
                                        </div>
                                    </div>
                                </li>
                            @endif
                            @if ($user->cin)
                                <li class="list-group-item">
                                    <div class="row">
                                        <div class="col-4 col-sm-3">
                                            <strong>
                                                cin
                                            </strong>
                                        </div>
                                        <div class="col-8 col-sm-9">
                                            {{ $user->cin }}
                                        </div>
                                    </div>
                                </li>
                            @endif
                            @if ($user->permis)
                                <li class="list-group-item">
                                    <div class="row">
                                        <div class="col-4 col-sm-3">
                                            <strong>
                                                permis
                                            </strong>
                                        </div>
                                        <div class="col-8 col-sm-9">
                                            {{ $user->permis }}
                                        </div>
                                    </div>
                                </li>
                            @endif
                            @if ($user->adresse)
                                <li class="list-group-item">
                                    <div class="row">
                                        <div class="col-4 col-sm-3">
                                            <strong>
                                                adresse
                                            </strong>
                                        </div>
                                        <div class="col-8 col-sm-9">
                                            {{ $user->adresse }}
                                        </div>
                                    </div>
                                </li>
                            @endif
                            @if ($user->ville)
                                <li class="list-group-item">
                                    <div class="row">
                                        <div class="col-4 col-sm-3">
                                            <strong>
                                                ville
                                            </strong>
                                        </div>
                                        <div class="col-8 col-sm-9">
                                            {{ $user->ville }}
                                        </div>
                                    </div>
                                </li>
                            @endif
                            @if ($user->date_naissance)
                                <li class="list-group-item">
                                    <div class="row">
                                        <div class="col-4 col-sm-3">
                                            <strong>
                                                date_naissance
                                            </strong>
                                        </div>
                                        <div class="col-8 col-sm-9">
                                            {{ $user->date_naissance }}
                                        </div>
                                    </div>
                                </li>
                            @endif
                            @if ($user->type)
                                <li class="list-group-item">
                                    <div class="row">
                                        <div class="col-4 col-sm-3">
                                            <strong>
                                                Role
                                            </strong>
                                        </div>
                                        <div class="col-8 col-sm-9">
                                            @if ($user->type == 'default')
                                                 Normal
                                            @elseif($user->type == 'super')
											Super Admin
                                            @else
                                            Admin
                                                @endif
                                        </div>
                                    </div>
                                </li>
                            @endif
                            @if ($user->email)
                                <li class="list-group-item">
                                    <div class="row">
                                        <div class="col-12 col-sm-3">
                                            <strong>
                                                @lang('laravelusers::laravelusers.show-user.email')
                                            </strong>
                                        </div>
                                        <div class="col-12 col-sm-9">
                                            {{ $user->email }}
                                        </div>
                                    </div>
                                </li>
                            @endif
                            @if(config('laravelusers.rolesEnabled'))
                                <li class="list-group-item">
                                    <div class="row">
                                        <div class="col-4 col-sm-3">
                                            <strong>
                                                {{ trans('laravelusers::laravelusers.show-user.labelRole') }}
                                            </strong>
                                        </div>
                                        <div class="col-8 col-sm-9">
                                            @foreach ($user->roles as $user_role)
                                                @if ($user_role->name == 'User')
                                                    @php $labelClass = 'primary' @endphp
                                                @elseif ($user_role->name == 'Admin')
                                                    @php $labelClass = 'warning' @endphp
                                                @elseif ($user_role->name == 'Unverified')
                                                    @php $labelClass = 'danger' @endphp
                                                @else
                                                    @php $labelClass = 'default' @endphp
                                                @endif
                                                <span class="badge badge-{{$labelClass}}">{{ $user_role->name }}</span>
                                            @endforeach
                                        </div>
                                    </div>
                                </li>
                                <li class="list-group-item">
                                    <div class="row">
                                        <div class="col-12 col-sm-3">
                                            <strong>
                                                {!! trans_choice('laravelusers::laravelusers.show-user.labelAccessLevel', 1) !!}
                                            </strong>
                                        </div>
                                        <div class="col-12 col-sm-9">
                                            @if($user->level() >= 5)
                                                <span class="badge badge-primary margin-half margin-left-0">5</span>
                                            @endif
                                            @if($user->level() >= 4)
                                                <span class="badge badge-info margin-half margin-left-0">4</span>
                                            @endif
                                            @if($user->level() >= 3)
                                                <span class="badge badge-success margin-half margin-left-0">3</span>
                                            @endif
                                            @if($user->level() >= 2)
                                                <span class="badge badge-warning margin-half margin-left-0">2</span>
                                            @endif
                                            @if($user->level() >= 1)
                                                <span class="badge badge-default margin-half margin-left-0">1</span>
                                            @endif
                                        </div>
                                    </div>
                                </li>
                            @endif
                            @if ($user->created_at)
                                <li class="list-group-item">
                                    <div class="row">
                                        <div class="col-4 col-sm-3">
                                            <strong>
                                                @lang('laravelusers::laravelusers.show-user.created')
                                            </strong>
                                        </div>
                                        <div class="col-8 col-sm-9">
                                            {{ $user->created_at }}
                                        </div>
                                    </div>
                                </li>
                            @endif
                            @if ($user->updated_at)
                                <li class="list-group-item">
                                    <div class="row">
                                        <div class="col-4 col-sm-3">
                                            <strong>
                                                @lang('laravelusers::laravelusers.show-user.updated')
                                            </strong>
                                        </div>
                                        <div class="col-8 col-sm-9">
                                            {{ $user->updated_at }}
                                        </div>
                                    </div>
                                </li>
                            @endif
                        </ul>
                    </div>
                </div>
            </div>
            <div class="col-md-7 col-sm-12">
                {!! $map['html'] !!}
            </div>
        </div>
    </div>
    @include('laravelusers::modals.modal-delete')
@endsection

@section('template_scripts')
    @include('laravelusers::scripts.delete-modal-script')
    @if(config('laravelusers.tooltipsEnabled'))
        @include('laravelusers::scripts.tooltips')
    @endif
@endsection
