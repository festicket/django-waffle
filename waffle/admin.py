from django.contrib import admin

from waffle.models import Flag, Sample, Switch, UserFeatureFlags


def enable_for_all(ma, request, qs):
    # Iterate over all objects to cause cache invalidation.
    for f in qs.all():
        f.everyone = True
        f.save()
enable_for_all.short_description = 'Enable selected flags for everyone.'


def disable_for_all(ma, request, qs):
    # Iterate over all objects to cause cache invalidation.
    for f in qs.all():
        f.everyone = False
        f.save()
disable_for_all.short_description = 'Disable selected flags for everyone.'


class FlagAdmin(admin.ModelAdmin):

    def get_queryset(self, request):
        return super(FlagAdmin, self).get_queryset(request)\
            .extra(select = {'active_user_count': '''SELECT count(*)
                                                     FROM waffle_userfeatureflags uff
                                                     WHERE uff.flag_id = id
                                                     AND uff.is_active = TRUE
                                                     AND uff.is_excluded = TRUE''',
                             'inactive_user_count': '''SELECT count(*)
                                                     FROM waffle_userfeatureflags uff
                                                     WHERE uff.flag_id = id
                                                     AND uff.is_active = FALSE
                                                     AND uff.is_excluded = TRUE''',
                             'excluded_user_count': '''SELECT count(*)
                                                     FROM waffle_userfeatureflags uff
                                                     WHERE uff.flag_id = id
                                                     AND uff.is_excluded = TRUE'''})

    def active_user_count(self, obj):
        return obj.active_user_count

    def inactive_user_count(self, obj):
        return obj.inactive_user_count

    def excluded_user_count(self, obj):
        return obj.excluded_user_count

    actions = [enable_for_all, disable_for_all]
    date_hierarchy = 'created'
    list_display = ('name', 'note', 'everyone', 'percent', 'superusers', 'staff', 'authenticated', 'languages',
                    'active_user_count', 'inactive_user_count', 'excluded_user_count')
    list_filter = ('everyone', 'superusers', 'staff', 'authenticated')
    raw_id_fields = ('users', 'groups')
    ordering = ('-id',)


class UserFeatureFlagsAdmin(admin.ModelAdmin):
    list_display = 'user', 'flag', 'is_active', 'is_excluded'
    raw_id_fields = ('user',)


def enable_switches(ma, request, qs):
    for switch in qs:
        switch.active = True
        switch.save()
enable_switches.short_description = 'Enable the selected switches.'


def disable_switches(ma, request, qs):
    for switch in qs:
        switch.active = False
        switch.save()
disable_switches.short_description = 'Disable the selected switches.'


class SwitchAdmin(admin.ModelAdmin):
    actions = [enable_switches, disable_switches]
    date_hierarchy = 'created'
    list_display = ('name', 'active', 'note', 'created', 'modified')
    list_filter = ('active',)
    ordering = ('-id',)


class SampleAdmin(admin.ModelAdmin):
    date_hierarchy = 'created'
    list_display = ('name', 'percent', 'note', 'created', 'modified')
    ordering = ('-id',)


admin.site.register(Flag, FlagAdmin)
admin.site.register(Sample, SampleAdmin)
admin.site.register(Switch, SwitchAdmin)
admin.site.register(UserFeatureFlags, UserFeatureFlagsAdmin)
