@extends(config('laravelusers.laravelUsersBladeExtended'))

@section('template_title')
  @lang('laravelusers::laravelusers.editing-user', ['name' => $user->name])
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
            <div class="col-lg-10 offset-lg-1">
                <div class="card">
                    <div class="card-header">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            @lang('laravelusers::laravelusers.editing-user', ['name' => $user->name])
                            <div class="pull-right">
                                <a href="{{ route('users') }}" class="btn btn-light btn-sm float-right" data-toggle="tooltip" data-placement="top" title="@lang('laravelusers::laravelusers.tooltips.back-users')">
                                    @if(config('laravelusers.fontAwesomeEnabled'))
                                        <i class="fas fa-fw fa-reply-all" aria-hidden="true"></i>
                                    @endif
                                    @lang('laravelusers::laravelusers.buttons.back-to-users')
                                </a>
                                <a href="{{ url('/users/' . $user->id) }}" class="btn btn-light btn-sm float-right" data-toggle="tooltip" data-placement="left" title="@lang('laravelusers::laravelusers.tooltips.back-users')">
                                    @if(config('laravelusers.fontAwesomeEnabled'))
                                        <i class="fas fa-fw fa-reply" aria-hidden="true"></i>
                                    @endif
                                    @lang('laravelusers::laravelusers.buttons.back-to-user')
                                </a>
                            </div>
                        </div>
                    </div>
                    <div class="card-body">
                        {!! Form::open(array('route' => ['users.update', $user->id], 'method' => 'PUT', 'role' => 'form', 'class' => 'needs-validation')) !!}
                            {!! csrf_field() !!}
                            <div class="form-group has-feedback row {{ $errors->has('name') ? ' has-error ' : '' }}">
                                @if(config('laravelusers.fontAwesomeEnabled'))
                                    {!! Form::label('name', trans('laravelusers::forms.create_user_label_username'), array('class' => 'col-md-3 control-label')); !!}
                                @endif
                                <div class="col-md-9">
                                    <div class="input-group">
                                        {!! Form::text('name', $user->name, array('id' => 'name', 'class' => 'form-control', 'placeholder' => trans('laravelusers::forms.create_user_ph_username'))) !!}
                                        <div class="input-group-append">
                                            <label class="input-group-text" for="name">
                                                @if(config('laravelusers.fontAwesomeEnabled'))
                                                    <i class="fa fa-fw {{ trans('laravelusers::forms.create_user_icon_username') }}" aria-hidden="true"></i>
                                                @else
                                                    @lang('laravelusers::forms.create_user_label_username')
                                                @endif
                                            </label>
                                        </div>
                                    </div>
                                    @if ($errors->has('name'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('name') }}</strong>
                                        </span>
                                    @endif
                                </div>
                            </div>
                            <div class="form-group has-feedback row {{ $errors->has('email') ? ' has-error ' : '' }}">
                                @if(config('laravelusers.fontAwesomeEnabled'))
                                    {!! Form::label('email', trans('laravelusers::forms.create_user_label_email'), array('class' => 'col-md-3 control-label')); !!}
                                @endif
                                <div class="col-md-9">
                                    <div class="input-group">
                                        {!! Form::text('email', $user->email, array('id' => 'email', 'class' => 'form-control', 'placeholder' => trans('laravelusers::forms.create_user_ph_email'))) !!}
                                        <div class="input-group-append">
                                            <label for="email" class="input-group-text">
                                                @if(config('laravelusers.fontAwesomeEnabled'))
                                                    <i class="fa fa-fw {{ trans('laravelusers::forms.create_user_icon_email') }}" aria-hidden="true"></i>
                                                @else
                                                    @lang('laravelusers::forms.create_user_label_email')
                                                @endif
                                            </label>
                                        </div>
                                    </div>
                                    @if ($errors->has('email'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('email') }}</strong>
                                        </span>
                                    @endif
                                </div>
                            </div>
                                <div class="form-group has-feedback row {{ $errors->has('type') ? ' has-error ' : '' }}">
                                    @if(config('laravelusers.fontAwesomeEnabled'))
                                        {!! Form::label('role', trans('laravelusers::forms.create_user_label_role'), array('class' => 'col-md-3 control-label')); !!}
                                    @endif
                                    <div class="col-md-9">
                                    <div class="input-group">
                                        <select class="custom-select form-control" name="type" id="role">
                                            <option value="default" {{ $user->type == "default" ? 'selected="selected"' : '' }}>Normal</option>
                                            <option value="admin" {{ $user->type == "admin" ? 'selected="selected"' : '' }}>Administrator</option>
                                            <option value="super" {{ $user->type == "super" ? 'selected="selected"' : '' }}>Super Administrator</option>
                                        </select>
                                        <div class="input-group-append">
                                            <label class="input-group-text" for="role">
                                                @if(config('laravelusers.fontAwesomeEnabled'))
                                                    <i class="{{ trans('laravelusers::forms.create_user_icon_role') }}" aria-hidden="true"></i>
                                                @else
                                                    @lang('laravelusers::forms.create_user_label_username')
                                                @endif
                                            </label>
                                        </div>
                                    </div>
                                    @if ($errors->has('role'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('role') }}</strong>
                                        </span>
                                    @endif
                                    </div>
                                </div>
                            @if($rolesEnabled)
                                <div class="form-group has-feedback row {{ $errors->has('role') ? ' has-error ' : '' }}">
                                    @if(config('laravelusers.fontAwesomeEnabled'))
                                        {!! Form::label('role', trans('laravelusers::forms.create_user_label_role'), array('class' => 'col-md-3 control-label')); !!}
                                    @endif
                                    <div class="col-md-9">
                                    <div class="input-group">
                                        <select class="custom-select form-control" name="role" id="role">
                                            <option value="">{{ trans('laravelusers::forms.create_user_ph_role') }}</option>
                                            @if ($roles)
                                                @foreach($roles as $role)
                                                    <option value="{{ $role->id }}" {{ $currentRole->id == $role->id ? 'selected="selected"' : '' }}>{{ $role->name }}</option>
                                                @endforeach
                                            @endif
                                        </select>
                                        <div class="input-group-append">
                                            <label class="input-group-text" for="role">
                                                @if(config('laravelusers.fontAwesomeEnabled'))
                                                    <i class="{{ trans('laravelusers::forms.create_user_icon_role') }}" aria-hidden="true"></i>
                                                @else
                                                    @lang('laravelusers::forms.create_user_label_username')
                                                @endif
                                            </label>
                                        </div>
                                    </div>
                                    @if ($errors->has('role'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('role') }}</strong>
                                        </span>
                                    @endif
                                    </div>
                                </div>
                            @endif
                            <div class="pw-change-container">
                                <div class="form-group has-feedback row {{ $errors->has('password') ? ' has-error ' : '' }}">
                                    @if(config('laravelusers.fontAwesomeEnabled'))
                                        {!! Form::label('password', trans('laravelusers::forms.create_user_label_password'), array('class' => 'col-md-3 control-label')); !!}
                                    @endif
                                    <div class="col-md-9">
                                        <div class="input-group">
                                            {!! Form::password('password', array('id' => 'password', 'class' => 'form-control ', 'placeholder' => trans('laravelusers::forms.create_user_ph_password'))) !!}
                                            <div class="input-group-append">
                                                <label class="input-group-text" for="password">
                                                    @if(config('laravelusers.fontAwesomeEnabled'))
                                                        <i class="fa fa-fw {{ trans('laravelusers::forms.create_user_icon_password') }}" aria-hidden="true"></i>
                                                    @else
                                                        @lang('laravelusers::forms.create_user_label_password')
                                                    @endif
                                                </label>
                                            </div>
                                        </div>
                                        @if ($errors->has('password'))
                                            <span class="help-block">
                                                <strong>{{ $errors->first('password') }}</strong>
                                            </span>
                                        @endif
                                    </div>
                                </div>
                                <div class="form-group has-feedback row {{ $errors->has('password_confirmation') ? ' has-error ' : '' }}">
                                    @if(config('laravelusers.fontAwesomeEnabled'))
                                        {!! Form::label('password_confirmation', trans('laravelusers::forms.create_user_label_pw_confirmation'), array('class' => 'col-md-3 control-label')); !!}
                                    @endif
                                    <div class="col-md-9">
                                        <div class="input-group">
                                            {!! Form::password('password_confirmation', array('id' => 'password_confirmation', 'class' => 'form-control', 'placeholder' => trans('laravelusers::forms.create_user_ph_pw_confirmation'))) !!}
                                            <div class="input-group-append">
                                                <label class="input-group-text" for="password_confirmation">
                                                    @if(config('laravelusers.fontAwesomeEnabled'))
                                                        <i class="fa fa-fw {{ trans('laravelusers::forms.create_user_icon_pw_confirmation') }}" aria-hidden="true"></i>
                                                    @else
                                                        @lang('laravelusers::forms.create_user_label_pw_confirmation')
                                                    @endif
                                                </label>
                                            </div>
                                        </div>
                                        @if ($errors->has('password_confirmation'))
                                            <span class="help-block">
                                                <strong>{{ $errors->first('password_confirmation') }}</strong>
                                            </span>
                                        @endif
                                    </div>
                                </div>
                            </div>
                            

                            
                            <div class="form-group has-feedback row {{ $errors->has('phone') ? ' has-error ' : '' }}">
                                @if(config('laravelusers.fontAwesomeEnabled'))
                                    {!! Form::label('phone', 'phone', array('class' => 'col-md-3 control-label')); !!}
                                @endif
                                <div class="col-md-9">
                                    <div class="input-group">
                                        {!! Form::text('phone', $user->phone, array('id' => 'phone', 'class' => 'form-control', 'placeholder' =>'')) !!}
                                        <div class="input-group-append">
                                            <label class="input-group-text" for="phone"> 
                                                <i class="fa fa-fw fa-phone" aria-hidden="true"></i> 
                                            </label>
                                        </div>
                                    </div>
                                    @if ($errors->has('phone'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('phone') }}</strong>
                                        </span>
                                    @endif
                                </div>
                            </div>



                            
                            <div class="form-group has-feedback row {{ $errors->has('cin') ? ' has-error ' : '' }}">
                                @if(config('laravelusers.fontAwesomeEnabled'))
                                    {!! Form::label('cin', 'cin', array('class' => 'col-md-3 control-label')); !!}
                                @endif
                                <div class="col-md-9">
                                    <div class="input-group">
                                        {!! Form::text('cin', $user->cin, array('id' => 'cin', 'class' => 'form-control', 'placeholder' =>'')) !!}
                                        <div class="input-group-append">
                                            <label class="input-group-text" for="cin">
                                                <i class="fa fa-fw {{ trans('laravelusers::forms.create_user_icon_username') }}" aria-hidden="true"></i>
                                            </label>
                                        </div>
                                    </div>
                                    @if ($errors->has('cin'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('cin') }}</strong>
                                        </span>
                                    @endif
                                </div>
                            </div>


                            
                            <div class="form-group has-feedback row {{ $errors->has('permis') ? ' has-error ' : '' }}">
                                @if(config('laravelusers.fontAwesomeEnabled'))
                                    {!! Form::label('permis', 'permis', array('class' => 'col-md-3 control-label')); !!}
                                @endif
                                <div class="col-md-9">
                                    <div class="input-group">
                                        {!! Form::text('permis', $user->permis, array('id' => 'permis', 'class' => 'form-control', 'placeholder' =>'')) !!}
                                        <div class="input-group-append">
                                            <label class="input-group-text" for="permis">
                                                 <i class="fa fa-fw fa-car" aria-hidden="true"></i>
                                                
                                            </label>
                                        </div>
                                    </div>
                                    @if ($errors->has('permis'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('permis') }}</strong>
                                        </span>
                                    @endif
                                </div>
                            </div>


                            
                            <div class="form-group has-feedback row {{ $errors->has('adresse') ? ' has-error ' : '' }}">
                                @if(config('laravelusers.fontAwesomeEnabled'))
                                    {!! Form::label('adresse', 'adresse', array('class' => 'col-md-3 control-label')); !!}
                                @endif
                                <div class="col-md-9">
                                    <div class="input-group">
                                        {!! Form::text('adresse', $user->adresse, array('id' => 'adresse', 'class' => 'form-control', 'placeholder' =>'')) !!}
                                        <div class="input-group-append">
                                            <label class="input-group-text" for="adresse">
                                                  <i class="fa fa-fw fa-map-marker" aria-hidden="true"></i>
                                            </label>
                                        </div>
                                    </div>
                                    @if ($errors->has('adresse'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('adresse') }}</strong>
                                        </span>
                                    @endif
                                </div>
                            </div>


                            
                            <div class="form-group has-feedback row {{ $errors->has('ville') ? ' has-error ' : '' }}">
                                @if(config('laravelusers.fontAwesomeEnabled'))
                                    {!! Form::label('ville','ville', array('class' => 'col-md-3 control-label')); !!}
                                @endif
                                <div class="col-md-9">
                                    <div class="input-group">
                                        {!! Form::text('ville', $user->ville, array('id' => 'ville', 'class' => 'form-control', 'placeholder' =>'')) !!}
                                        <div class="input-group-append">
                                            <label class="input-group-text" for="ville">
                                                <i class="fa fa-fw fa-map-marker" aria-hidden="true"></i>
                                             
                                            </label>
                                        </div>
                                    </div>
                                    @if ($errors->has('ville'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('ville') }}</strong>
                                        </span>
                                    @endif
                                </div>
                            </div>


                            
                            <div class="form-group has-feedback row {{ $errors->has('date_naissance') ? ' has-error ' : '' }}">
                                @if(config('laravelusers.fontAwesomeEnabled'))
                                    {!! Form::label('date_naissance', 'date_naissance', array('class' => 'col-md-3 control-label')); !!}
                                @endif
                                <div class="col-md-9">
                                    <div class="input-group">
                                        {!! Form::date('date_naissance', $user->date_naissance, array('id' => 'date_naissance', 'class' => 'form-control', 'placeholder' => '')) !!}
                                        <div class="input-group-append">
                                            <label class="input-group-text" for="date_naissance">
                                                  <i class="fa fa-fw " aria-hidden="true"></i>
                                                
                                            </label>
                                        </div>
                                    </div>
                                    @if ($errors->has('date_naissance'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('date_naissance') }}</strong>
                                        </span>
                                    @endif
                                </div>
                            </div>
                            <div class="row">
                                <div class="col-12 col-sm-6 mb-2">
                                    <a href="#" class="btn btn-outline-secondary btn-block btn-change-pw mt-3" title="@lang('laravelusers::forms.change-pw')">
                                        <i class="fa fa-fw fa-lock" aria-hidden="true"></i>
                                        <span></span> @lang('laravelusers::forms.change-pw')
                                    </a>
                                </div>
                                <div class="col-12 col-sm-6">
                                    {!! Form::button(trans('laravelusers::forms.save-changes'), array('class' => 'btn btn-success btn-block margin-bottom-1 mt-3 mb-2 btn-save','type' => 'button', 'data-toggle' => 'modal', 'data-target' => '#confirmSave', 'data-title' => trans('laravelusers::modals.edit_user__modal_text_confirm_title'), 'data-message' => trans('laravelusers::modals.edit_user__modal_text_confirm_message'))) !!}
                                </div>
                            </div>
                        {!! Form::close() !!}
                    </div>
                </div>
            </div>
        </div>
    </div>

    @include('laravelusers::modals.modal-save')
    @include('laravelusers::modals.modal-delete')

@endsection

@section('template_scripts')
    @include('laravelusers::scripts.delete-modal-script')
    @include('laravelusers::scripts.save-modal-script')
    @include('laravelusers::scripts.check-changed')
    @if(config('laravelusers.tooltipsEnabled'))
        @include('laravelusers::scripts.tooltips')
    @endif
@endsection

