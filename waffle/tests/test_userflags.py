import random

from django.contrib.auth.models import AnonymousUser, Group, User
from django.db import connection
from django.test import RequestFactory
from django.test.utils import override_settings

import mock

from waffle import flag_is_active
from test_app import views
from waffle.middleware import WaffleMiddleware
from waffle.models import Flag, Sample, Switch, UserFeatureFlags
from waffle.tests.base import TestCase


def get(**kw):
    request = RequestFactory().get('/admin/', data=kw)
    request.user = AnonymousUser()
    return request


def process_request(request, view):
    response = view(request)
    return WaffleMiddleware().process_response(request, response)


class UserFeatureFlagTests(TestCase):

    def test_user_feature_flag_is_persistent(self):
        """???"""
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
        """???"""
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
        """???"""
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
        """???"""
        user = User.objects.create(username='foo')
        flag = Flag.objects.create(name='myflag', testing=True)
        info = UserFeatureFlags.objects.create(user=user, flag=flag, is_active=False)

        request = get()
        request.user = user
        self.assertEqual(False, flag_is_active(request, 'myflag'))

        request = get(dwft_myflag='1')
        request.user = user
        self.assertEqual(True, flag_is_active(request, 'myflag'))

    def test_flag_active_for_user_overridden_by_authenticated_user(self):
        """???"""
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
        """???"""
        user = User.objects.create(username='foo', is_staff=True)
        flag = Flag.objects.create(name='myflag')
        info = UserFeatureFlags.objects.create(user=user, flag=flag, is_active=False)

        request = get()
        request.user = user
        self.assertEqual(False, flag_is_active(request, 'myflag'))

        flag.staff = True
        flag.save()
        self.assertEqual(True, flag_is_active(request, 'myflag'))

    def test_flag_active_for_user_overridden_by_superuser(self):
        """???"""
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
         pass

    def test_flag_active_for_user_overridden_by_flag_users(self):
        """???"""
        user = User.objects.create(username='foo')
        flag = Flag.objects.create(name='myflag')
        info = UserFeatureFlags.objects.create(user=user, flag=flag, is_active=False)

        request = get()
        request.user = user
        self.assertEqual(False, flag_is_active(request, 'myflag'))

        flag.users.add(user.pk)
        self.assertEqual(True, flag_is_active(request, 'myflag'))

    def test_flag_active_for_user_overridden_by_flag_groups(self):
        """???"""
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




