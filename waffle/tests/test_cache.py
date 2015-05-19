from django.core.urlresolvers import reverse
from waffle import keyfmt, get_setting
from waffle.compat import cache

from waffle.models import Flag, Sample, Switch
from waffle.tests.base import TestCase


class WaffleCacheTests(TestCase):

    def test_cache_all_flags(self):
        """Test the 'ALL_FLAGS' list caches correctly."""

        Flag.objects.create(name='myflag1', everyone=True)

        # cache is initially empty
        cached_flags = cache.get(keyfmt(get_setting('ALL_FLAGS_CACHE_KEY')))
        self.assertIsNone(cached_flags)

        # calling waffejs view causes cache to be set
        self.client.get(reverse('wafflejs'))
        cached_flags = cache.get(keyfmt(get_setting('ALL_FLAGS_CACHE_KEY')))
        self.assertIsNotNone(cached_flags)
        self.assertSequenceEqual(['myflag1'], cached_flags)

        # creating a new flag invalidates the cache
        Flag.objects.create(name='myflag2', everyone=True)
        cached_flags = cache.get(keyfmt(get_setting('ALL_FLAGS_CACHE_KEY')))
        self.assertIsNone(cached_flags)

        # calling waffejs view causes cache to be set for more than 2 flags
        self.client.get(reverse('wafflejs'))
        cached_flags = cache.get(keyfmt(get_setting('ALL_FLAGS_CACHE_KEY')))
        self.assertIsNotNone(cached_flags)
        self.assertSequenceEqual(['myflag1', 'myflag2'], cached_flags)

    def test_cache_all_switches(self):
        """Test the 'ALL_SWITCHES' list caches correctly."""

        Switch.objects.create(name='myswitch1', active=True)

        # cache is initially empty
        cached_switches = cache.get(keyfmt(get_setting('ALL_SWITCHES_CACHE_KEY')))
        self.assertIsNone(cached_switches)

        # calling waffejs view causes cache to be set
        self.client.get(reverse('wafflejs'))
        cached_switches = cache.get(keyfmt(get_setting('ALL_SWITCHES_CACHE_KEY')))
        self.assertIsNotNone(cached_switches)
        self.assertSequenceEqual([('myswitch1', True)], cached_switches)

        # creating a new flag invalidates the cache
        Switch.objects.create(name='myswitch2', active=True)
        cached_switches = cache.get(keyfmt(get_setting('ALL_SWITCHES_CACHE_KEY')))
        self.assertIsNone(cached_switches)

        # calling waffejs view causes cache to be set for more than 1 switch
        self.client.get(reverse('wafflejs'))
        cached_switches = cache.get(keyfmt(get_setting('ALL_SWITCHES_CACHE_KEY')))
        self.assertIsNotNone(cached_switches)
        self.assertSequenceEqual([('myswitch1', True), ('myswitch2', True)], cached_switches)
        
    def test_cache_all_samples(self):
        """Test the 'ALL_SAMPLES' list caches correctly."""

        Sample.objects.create(name='mysample1', percent='100.0')

        # cache is initially empty
        cached_samples = cache.get(keyfmt(get_setting('ALL_SAMPLES_CACHE_KEY')))
        self.assertIsNone(cached_samples)

        # calling waffejs view causes cache to be set
        self.client.get(reverse('wafflejs'))
        cached_samples = cache.get(keyfmt(get_setting('ALL_SAMPLES_CACHE_KEY')))
        self.assertIsNotNone(cached_samples)
        self.assertSequenceEqual(['mysample1'], cached_samples)

        # creating a new flag invalidates the cache
        Sample.objects.create(name='mysample2', percent='100.0')
        cached_samples = cache.get(keyfmt(get_setting('ALL_SAMPLES_CACHE_KEY')))
        self.assertIsNone(cached_samples)

        # calling waffejs view causes cache to be set for more than 1 switch
        self.client.get(reverse('wafflejs'))
        cached_samples = cache.get(keyfmt(get_setting('ALL_SAMPLES_CACHE_KEY')))
        self.assertIsNotNone(cached_samples)
        self.assertSequenceEqual(['mysample1', 'mysample2'], cached_samples)