from django.http import HttpResponse
from django.shortcuts import render_to_response, render
from django.template import Context, RequestContext
from django.template.loader import render_to_string

from waffle import flag_is_active, flag_is_excluded, set_excluded
from waffle.decorators import waffle_flag, waffle_switch


def flag_in_view(request):
    if flag_is_active(request, 'myflag'):
        return HttpResponse('on')
    return HttpResponse('off')

def flag_excluded_in_view(request):
    if flag_is_excluded(request, 'myflag'):
        return HttpResponse('excluded')
    return HttpResponse('not excluded')

def exclude_user(request):
    set_excluded(request, 'myflag')
    return HttpResponse('user excluded')


def flag_in_jingo(request):
    return render(request, 'jingo/jingo.html')


def flag_in_django(request):
    c = RequestContext(request, {
        'flag_var': 'flag_var',
        'switch_var': 'switch_var',
        'sample_var': 'sample_var',
    })
    return render_to_response('django/django.html', context_instance=c)


def no_request_context(request):
    c = Context({})
    return render_to_string('django/django_email.html', context_instance=c)


@waffle_switch('foo')
def switched_view(request):
    return HttpResponse('foo')


@waffle_switch('!foo')
def switched_off_view(request):
    return HttpResponse('foo')


@waffle_flag('foo')
def flagged_view(request):
    return HttpResponse('foo')


@waffle_flag('!foo')
def flagged_off_view(request):
    return HttpResponse('foo')
