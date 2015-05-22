from django.contrib.auth.models import AnonymousUser, User
from django.test import RequestFactory

from test_app import views

from waffle import flag_is_excluded, set_excluded
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

    def test_excluded_false_by_default(self):
        """Test that a flag is not excluded by default for a user."""
        user = User.objects.create(username='foo')
        Flag.objects.create(name='myflag', percent=50.0)

        with self.assertRaises(UserFeatureFlags.DoesNotExist):
            UserFeatureFlags.objects.get(user=user)

        request = get()
        request.user = user

        flag_is_excluded(request, 'myflag')
        info = UserFeatureFlags.objects.get(user=user)

        self.assertFalse(info.is_excluded)

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
        """Test that flag_is_excluded can be called before flag_is_active"""
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
        """Test that flag_is_active can be called before flag_is_excluded"""
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
        info = UserFeatureFlags.objects.get(user=user)
        self.assertFalse(info.is_excluded)
        self.assertIsNotNone(info.is_active)

    def test_anonymous_user_excluded(self):
        """Test an anonymous user can be set to excluded and it persists via cookies"""
        Flag.objects.create(name='myflag', percent=50.0)

        request = get()
        request.user = AnonymousUser()

        resp = process_request(request, views.flag_excluded_in_view)
        self.assertEqual(resp.content, "not excluded")
        self.assertTrue('dwfx_myflag' in resp.cookies)
        self.assertEqual('False', resp.cookies['dwfx_myflag'].value)

        request = get()
        request.user = AnonymousUser()
        for k in resp.cookies:
            request.COOKIES[k] = resp.cookies[k].value

        resp = process_request(request, views.exclude_user)
        self.assertTrue('dwfx_myflag' in resp.cookies)
        self.assertEqual('True', resp.cookies['dwfx_myflag'].value)

        request = get()
        request.user = AnonymousUser()
        for k in resp.cookies:
            request.COOKIES[k] = resp.cookies[k].value

        resp = process_request(request, views.flag_excluded_in_view)
        self.assertEqual(resp.content, "excluded")
        self.assertTrue('dwfx_myflag' in resp.cookies)
        self.assertEqual('True', resp.cookies['dwfx_myflag'].value)

    def test_excluded_anon_user_makes_logged_in_user_excluded(self):
        """Test if a anonymous user is excluded, a user with no excluded flag value will also become excluded"""
        Flag.objects.create(name='myflag', percent=50.0)

        request = get()
        request.user = AnonymousUser()

        resp = process_request(request, views.exclude_user)
        self.assertEqual('True', resp.cookies['dwfx_myflag'].value)

        user = User.objects.create(username='foo')
        request = get()
        request.user = user
        for k in resp.cookies:
            request.COOKIES[k] = resp.cookies[k].value

        resp = process_request(request, views.flag_excluded_in_view)
        self.assertEqual(resp.content, "excluded")
        self.assertTrue('dwfx_myflag' in resp.cookies)
        self.assertEqual('True', resp.cookies['dwfx_myflag'].value)
        self.assertTrue(UserFeatureFlags.objects.get(user=user).is_excluded)

    def test_user_gets_excluded_by_exclude_cookie(self):
        """Test if a user is not excluded, then an anonymous user gets excluded, then the user will become excluded"""
        user = User.objects.create(username='foo')
        Flag.objects.create(name='myflag', percent=50.0)

        request = get()
        request.user = user

        resp = process_request(request, views.flag_excluded_in_view)
        self.assertEqual(resp.content, "not excluded")

        request = get()
        request.user = AnonymousUser()
        for k in resp.cookies:
            request.COOKIES[k] = resp.cookies[k].value

        resp = process_request(request, views.exclude_user)

        request = get()
        request.user = user
        for k in resp.cookies:
            request.COOKIES[k] = resp.cookies[k].value

        resp = process_request(request, views.flag_excluded_in_view)
        self.assertEqual(resp.content, "excluded")

        request = get()
        request.user = user
        resp = process_request(request, views.flag_excluded_in_view)
        self.assertEqual(resp.content, "excluded")


class UserFeatureFlagSetExcludedTests(TestCase):

    def test_flag_excluded_false_when_flag_doesnt_exist(self):
        """Test calling flag_is_excluded() return false if a flag with that name does not exist."""
        request = get()
        request.user = User.objects.create(username='foo')
        self.assertFalse(flag_is_excluded(request, 'non_existent_flag'))

        request = get()
        request.user = AnonymousUser
        self.assertFalse(flag_is_excluded(request, 'non_existent_flag'))

    def test_excluded_false_by_default(self):
        """Test that calling set_excluded() on a non-existent flag will have no effect"""
        user = User.objects.create(username='foo')

        request = get()
        request.user = user

        set_excluded(request, 'myflag')

        response = process_request(request, views.flag_excluded_in_view)
        self.assertEqual(b'not excluded', response.content)
        self.assertFalse('dwfx_myflag' in response.cookies)

    def test_no_cookies_set_when_flag_doesnt_exist(self):
        """Test no cookies are made for a flag that doesn't exist."""
        user = User.objects.create(username='foo')

        request = get()
        request.user = user

        set_excluded(request, 'myflag')
        response = process_request(request, views.flag_excluded_in_view)
        self.assertEqual(0, len(response.cookies))

        response = process_request(request, views.flag_in_view)
        self.assertEqual(0, len(response.cookies))



