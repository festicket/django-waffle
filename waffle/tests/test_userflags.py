import random

from django.contrib.auth.models import AnonymousUser, Group, User
from django.test import RequestFactory
from django.test.utils import override_settings
import mock

from waffle import flag_is_active
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


class UserFeatureFlagTests(TestCase):

    def test_user_feature_flag_is_persistent(self):
        """Test that the flag value for an authenticated user doesn't change in multiple requests"""
        user = User.objects.create(username='foo')
        Flag.objects.create(name='myflag', percent=50.0)

        with self.assertRaises(UserFeatureFlags.DoesNotExist):
            UserFeatureFlags.objects.get(user=user)

        request = get()
        request.user = user
        response = process_request(request, views.flag_in_view)

        try:
            active = UserFeatureFlags.objects.get(user=user).is_active
        except UserFeatureFlags.DoesNotExist:
             self.fail("An entry for user didn't exist in UserFeatureFlags after calling flag_in_view")

        # Make sure that the flag value stays the same
        for x in xrange(100):
            self.assertEquals(
                response.content,
                process_request(request, views.flag_in_view).content,
                "Value of flag changed for user in subsequent request"
            )
            self.assertEqual(active, UserFeatureFlags.objects.get(user=user).is_active)

    @override_settings(WAFFLE_OVERRIDE=True)
    def test_flag_active_for_user_overridden_override(self):
        """Test the override setting overrides the flag value of a user"""
        flag = Flag.objects.create(name='myflag', everyone=False)  # Off for everyone.
        user = User.objects.create(username='foo')
        UserFeatureFlags.objects.create(user=user, flag=flag, is_active=False)  # Off for user

        request = get()
        request.user = user
        self.assertEqual(False, flag_is_active(request, 'myflag'))

        request = get(myflag='1')  # On for override
        request.user = user
        self.assertEqual(True, flag_is_active(request, 'myflag'))

    def test_flag_active_for_user_overridden_by_everyone(self):
        """Test the 'everyone' switch overrides the flag value of a user"""
        user = User.objects.create(username='foo')
        flag = Flag.objects.create(name='myflag', percent=50.0)
        info = UserFeatureFlags.objects.create(user=user, flag=flag)

        for flag_active_for_user in [True, False]:
            info.is_active = flag_active_for_user
            info.save()

            request = get()
            request.user = user
            self.assertEqual(flag_is_active(request, 'myflag'), flag_active_for_user)

            self.assertIsNone(flag.everyone)
            flag.everyone = not flag_active_for_user
            flag.save()
            self.assertEqual(flag_is_active(request, 'myflag'), not flag_active_for_user)

            flag.everyone = None
            flag.save()

    def test_flag_active_for_user_overridden_by_testing(self):
        """Test the 'testing' switch overrides the flag value of a user"""
        user = User.objects.create(username='foo')
        flag = Flag.objects.create(name='myflag', testing=True)
        UserFeatureFlags.objects.create(user=user, flag=flag, is_active=False)

        request = get()
        request.user = user
        self.assertEqual(False, flag_is_active(request, 'myflag'))

        request = get(dwft_myflag='1')
        request.user = user
        self.assertEqual(True, flag_is_active(request, 'myflag'))

    def test_flag_active_for_user_overridden_by_authenticated_user(self):
        """Test the 'authenticated' switch overrides the flag value of an authenticated user"""
        user = User.objects.create(username='foo')
        flag = Flag.objects.create(name='myflag')
        info = UserFeatureFlags.objects.create(user=user, flag=flag, is_active=False)

        request = get()
        request.user = user
        self.assertEqual(False, flag_is_active(request, 'myflag'))

        flag.authenticated = True
        flag.save()
        self.assertEqual(True, flag_is_active(request, 'myflag'))

    def test_flag_active_for_user_overridden_by_staff_user(self):
        """Test the 'staff' switch overrides the flag value of a staff user"""
        user = User.objects.create(username='foo', is_staff=True)
        flag = Flag.objects.create(name='myflag')
        UserFeatureFlags.objects.create(user=user, flag=flag, is_active=False)

        request = get()
        request.user = user
        self.assertEqual(False, flag_is_active(request, 'myflag'))

        flag.staff = True
        flag.save()
        self.assertEqual(True, flag_is_active(request, 'myflag'))

    def test_flag_active_for_user_overridden_by_superuser(self):
        """Test the 'superuser' switch overrides the flag value of a superuser"""
        user = User.objects.create(username='foo', is_superuser=True)
        flag = Flag.objects.create(name='myflag', superusers=False)
        info = UserFeatureFlags.objects.create(user=user, flag=flag, is_active=False)

        request = get()
        request.user = user
        self.assertEqual(False, flag_is_active(request, 'myflag'))

        flag.superusers = True
        flag.save()
        self.assertEqual(True, flag_is_active(request, 'myflag'))

    def test_flag_active_for_user_overridden_by_languages(self):
        """We have no plans to use this feature currently"""
        pass

    def test_flag_active_for_user_overridden_by_flag_users(self):
        """Test the 'users' switch overrides the flag value of a user,
        if a user has been added to the many-to-many relationship"""
        user = User.objects.create(username='foo')
        flag = Flag.objects.create(name='myflag')
        info = UserFeatureFlags.objects.create(user=user, flag=flag, is_active=False)

        request = get()
        request.user = user
        self.assertEqual(False, flag_is_active(request, 'myflag'))

        flag.users.add(user.pk)
        self.assertEqual(True, flag_is_active(request, 'myflag'))

    def test_flag_active_for_user_overridden_by_flag_groups(self):
        """Test the 'groups' switch overrides the flag value of a user in an added group"""
        user = User.objects.create(username='foo')
        flag = Flag.objects.create(name='myflag')
        info = UserFeatureFlags.objects.create(user=user, flag=flag, is_active=False)
        g = Group.objects.create(name='mygroup')
        g.user_set.add(user)

        request = get()
        request.user = user
        self.assertEqual(False, flag_is_active(request, 'myflag'))

        flag.groups.add(g.pk)
        self.assertEqual(True, flag_is_active(request, 'myflag'))


class UserFeatureFlagCookieTests(TestCase):

    def test_cookie_set_and_user_not_set(self):
        """Test that the flag_value for a user is set to the same value as the flag's cookie if the cookie exists
        and the flag value has not yet been set for an authenticated user"""
        user = User.objects.create(username='foo')
        Flag.objects.create(name='myflag', percent=50.0)

        with self.assertRaises(UserFeatureFlags.DoesNotExist):
            UserFeatureFlags.objects.get(user=user)

        request = get()
        request.user = user
        request.COOKIES['dwf_myflag'] = 'True'

        flag_is_active(request, 'myflag')
        info = UserFeatureFlags.objects.get(user=user)

        self.assertTrue(info.is_active)

    def test_user_set_and_cookie_not_set(self):
        """Test that the cookie is set to match the user's flag value if the cookie doesn't exist and the user's flag value does."""
        user = User.objects.create(username='foo')
        flag = Flag.objects.create(name='myflag', percent=50.0)
        info = UserFeatureFlags.objects.create(user=user, flag=flag, is_active=False)

        request = get()
        request.user = user

        resp = process_request(request, views.flag_in_view)

        self.assertTrue('dwf_myflag' in resp.cookies)
        self.assertEquals(resp.cookies['dwf_myflag'].value, 'False')

    def test_user_and_cookie_set_to_different_values(self):
        """When the user is authenticated and has a feature_flag value set,
        and there is also a cookie with a different feature_flag value,
        the cookie value should be overridden by the value on the user."""
        user = User.objects.create(username='foo')
        flag = Flag.objects.create(name='myflag', percent=50.0)
        info = UserFeatureFlags.objects.create(user=user, flag=flag, is_active=False)

        request = get()
        request.user = user
        request.COOKIES['dwf_myflag'] = 'True'

        resp = process_request(request, views.flag_in_view)

        self.assertTrue('dwf_myflag' in resp.cookies)
        self.assertEquals(resp.cookies['dwf_myflag'].value, 'False')

    def test_anonymous_user_and_cookie_set(self):
        """Test if a flag's cookie is set for an anonymous user's session, that value is persisted for the life of the cookie."""
        flag = Flag.objects.create(name='myflag', percent=50.0)

        for i in ['True', 'False']:
            request = get()
            request.user = AnonymousUser()
            request.COOKIES['dwf_myflag'] = i

            resp = process_request(request, views.flag_in_view)

            self.assertTrue('dwf_myflag' in resp.cookies)
            self.assertEquals(resp.cookies['dwf_myflag'].value, i)

    @mock.patch.object(random, 'uniform')
    def test_percentage_sets_correct_value(self, uniform):
        """Test if there is no cookie set, and the user has not had a value for the flag assigned,
        that a random active value will be assigned to the user for that flag."""
        Flag.objects.create(name='myflag', percent='50.0')
        user = User.objects.create(username='foo')
        with self.assertRaises(UserFeatureFlags.DoesNotExist):
            UserFeatureFlags.objects.get(user=user)
        # Make sure we're not really random.
        request = get()  # Create a clean request.
        request.user = user
        uniform.return_value = '10'  # < 50. Flag is True.
        flag_is_active(request, 'myflag')
        self.assertTrue(UserFeatureFlags.objects.get(user=user).is_active)

        UserFeatureFlags.objects.get(user=user).delete()

        request = get()  # Create a clean request.
        request.user = user
        uniform.return_value = '70'  # > 50. Flag is False.
        flag_is_active(request, 'myflag')
        self.assertFalse(UserFeatureFlags.objects.get(user=user).is_active)