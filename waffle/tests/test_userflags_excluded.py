import random

from django.contrib.auth.models import AnonymousUser, Group, User
from django.test import RequestFactory
from django.test.utils import override_settings
import mock

from waffle import flag_is_active, flag_is_excluded
from test_app import views
from waffle.middleware import WaffleMiddleware
from waffle.models import Flag, UserFeatureFlags
from waffle.tests.base import TestCase


def get(**kw):
    request = RequestFactory().get('/foo', data=kw)
    request.user = AnonymousUser()
    return request


def process_request(request, view):
    response = view(request)
    return WaffleMiddleware().process_response(request, response)


class UserFeatureFlagExcludedTests(TestCase):

    def test_cookie_set_and_user_not_set(self):
        """Test that the excluded value for an authenticated user is set to the same value as the flag's cookie
        if the cookie exists and the excluded value has not yet been set for the user"""
        user = User.objects.create(username='foo')
        Flag.objects.create(name='myflag', percent=50.0)

        with self.assertRaises(UserFeatureFlags.DoesNotExist):
            UserFeatureFlags.objects.get(user=user)

        request = get()
        request.user = user
        request.COOKIES['dwfx_myflag'] = 'True'

        flag_is_excluded(request, 'myflag')
        info = UserFeatureFlags.objects.get(user=user)

        self.assertTrue(info.is_excluded)

    def test_user_set_and_cookie_not_set(self):
        """Test that the excluded cookie is set to match the user's excluded value
        if the cookie doesn't exist and the user's excluded value does."""
        user = User.objects.create(username='foo')
        flag = Flag.objects.create(name='myflag', percent=50.0)
        info = UserFeatureFlags.objects.create(user=user, flag=flag, is_excluded=True)

        request = get()
        request.user = user

        resp = process_request(request, views.flag_excluded_in_view)

        self.assertTrue('dwfx_myflag' in resp.cookies)
        self.assertEquals(resp.cookies['dwfx_myflag'].value, 'True')

    def test_user_and_cookie_set_to_different_values(self):
        """When the user is authenticated and has an excluded value set,
        and there is also a cookie with a different excluded value,
        the cookie value should override the value on the user."""
        user = User.objects.create(username='foo')
        flag = Flag.objects.create(name='myflag', percent=50.0)
        UserFeatureFlags.objects.create(user=user, flag=flag, is_excluded=False)

        request = get()
        request.user = user
        request.COOKIES['dwfx_myflag'] = 'True'

        resp = process_request(request, views.flag_excluded_in_view)

        self.assertTrue('dwfx_myflag' in resp.cookies)
        self.assertEquals(resp.cookies['dwfx_myflag'].value, 'True')

    def test_anonymous_user_and_cookie_set(self):
        """Test if a excluded cookie is set for an anonymous user's session, that value is persisted for the life of the cookie."""
        flag = Flag.objects.create(name='myflag', percent=50.0)

        for i in ['True', 'False']:
            request = get()
            request.user = AnonymousUser()
            request.COOKIES['dwfx_myflag'] = i

            resp = process_request(request, views.flag_excluded_in_view)

            self.assertTrue('dwfx_myflag' in resp.cookies)
            self.assertEquals(resp.cookies['dwfx_myflag'].value, i)


class UserFeatureFlagExcludedAndActiveTests(TestCase):
    def test_excluded_set_before_active(self):
        """???"""
        user = User.objects.create(username='foo')
        Flag.objects.create(name='myflag', percent=50.0)

        with self.assertRaises(UserFeatureFlags.DoesNotExist):
            UserFeatureFlags.objects.get(user=user)

        request = get()
        request.user = user

        resp = process_request(request, views.flag_excluded_in_view)
        self.assertTrue('dwfx_myflag' in resp.cookies)
        self.assertTrue('dwf_myflag' not in resp.cookies)

        info = UserFeatureFlags.objects.get(user=user)
        self.assertIsNone(info.is_active)

        resp = process_request(request, views.flag_in_view)
        self.assertTrue('dwfx_myflag' in resp.cookies)
        self.assertTrue('dwf_myflag' in resp.cookies)

        info = UserFeatureFlags.objects.get(user=user)
        self.assertIsNotNone(info.is_active)

    def test_active_set_before_excluded(self):
        """???"""
        user = User.objects.create(username='foo')
        Flag.objects.create(name='myflag', percent=50.0)

        with self.assertRaises(UserFeatureFlags.DoesNotExist):
            UserFeatureFlags.objects.get(user=user)

        request = get()
        request.user = user

        resp = process_request(request, views.flag_in_view)
        self.assertTrue('dwfx_myflag' not in resp.cookies)
        self.assertTrue('dwf_myflag' in resp.cookies)

        info = UserFeatureFlags.objects.get(user=user)
        self.assertFalse(info.is_excluded)
        self.assertIsNotNone(info.is_active)

        resp = process_request(request, views.flag_excluded_in_view)
        self.assertTrue('dwfx_myflag' in resp.cookies)
        self.assertTrue('dwf_myflag' in resp.cookies)

    #test a anonymous user can be set to excluded and it persists

    #test if a anonymous user is excluded, a user with no flag value will also become excluded

    #test if a user is not excluded, then an anonymous user gets excluded, then the user will be excluded
