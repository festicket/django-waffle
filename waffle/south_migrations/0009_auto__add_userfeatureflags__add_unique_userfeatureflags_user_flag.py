# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'UserFeatureFlags'
        db.create_table(u'waffle_userfeatureflags', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['community.User'])),
            ('flag', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['waffle.Flag'])),
            ('is_active', self.gf('django.db.models.fields.BooleanField')()),
        ))
        db.send_create_signal(u'waffle', ['UserFeatureFlags'])

        # Adding unique constraint on 'UserFeatureFlags', fields ['user', 'flag']
        db.create_unique(u'waffle_userfeatureflags', ['user_id', 'flag_id'])


    def backwards(self, orm):
        # Removing unique constraint on 'UserFeatureFlags', fields ['user', 'flag']
        db.delete_unique(u'waffle_userfeatureflags', ['user_id', 'flag_id'])

        # Deleting model 'UserFeatureFlags'
        db.delete_table(u'waffle_userfeatureflags')


    models = {
        u'auth.group': {
            'Meta': {'object_name': 'Group'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'})
        },
        u'auth.permission': {
            'Meta': {'ordering': "(u'content_type__app_label', u'content_type__model', u'codename')", 'unique_together': "((u'content_type', u'codename'),)", 'object_name': 'Permission'},
            'codename': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'content_type': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['contenttypes.ContentType']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '50'})
        },
        u'community.user': {
            'Meta': {'ordering': "('id',)", 'object_name': 'User'},
            'address': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'author_title': ('django.db.models.fields.CharField', [], {'max_length': '100', 'blank': 'True'}),
            'avatar_large': ('util.models.BetterImageField', [], {'max_length': '100', 'blank': 'True'}),
            'avatar_small': ('util.models.BetterImageField', [], {'max_length': '100', 'blank': 'True'}),
            'birthdate': ('django.db.models.fields.DateField', [], {'null': 'True', 'blank': 'True'}),
            'city': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'country': ('countries.fields.CountryField', [], {'to': u"orm['countries.Country']", 'null': 'True', 'blank': 'True'}),
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'date_password_changed': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'email': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '200'}),
            'facebook_id': ('django.db.models.fields.CharField', [], {'max_length': '50', 'unique': 'True', 'null': 'True', 'blank': 'True'}),
            'favourite_memories': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'first_name': ('django.db.models.fields.CharField', [], {'max_length': '100', 'db_index': 'True'}),
            'followed_festivals': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "'followers'", 'blank': 'True', 'to': "orm['inventory.Festival']"}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "u'user_set'", 'blank': 'True', 'to': u"orm['auth.Group']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'last_name': ('django.db.models.fields.CharField', [], {'db_index': 'True', 'max_length': '100', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'phone': ('django.db.models.fields.CharField', [], {'max_length': '64', 'blank': 'True'}),
            'postcode': ('django.db.models.fields.CharField', [], {'max_length': '16', 'blank': 'True'}),
            'referral_campaign': ('django.db.models.fields.CharField', [], {'db_index': 'True', 'max_length': '100', 'blank': 'True'}),
            'referral_landing_page': ('django.db.models.fields.CharField', [], {'db_index': 'True', 'max_length': '200', 'blank': 'True'}),
            'referral_time_latest': ('django.db.models.fields.DateTimeField', [], {'db_index': 'True', 'null': 'True', 'blank': 'True'}),
            'referral_time_original': ('django.db.models.fields.DateTimeField', [], {'db_index': 'True', 'null': 'True', 'blank': 'True'}),
            'referrer': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'users'", 'null': 'True', 'on_delete': 'models.PROTECT', 'to': u"orm['partner.Partner']"}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "u'user_set'", 'blank': 'True', 'to': u"orm['auth.Permission']"})
        },
        u'contenttypes.contenttype': {
            'Meta': {'ordering': "('name',)", 'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        },
        u'countries.country': {
            'Meta': {'ordering': "('-sort_priority', 'name')", 'object_name': 'Country'},
            'iso': ('django.db.models.fields.CharField', [], {'max_length': '2', 'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'name_official': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'sort_priority': ('django.db.models.fields.PositiveIntegerField', [], {'default': '0'})
        },
        u'currency.currency': {
            'Meta': {'ordering': "('code',)", 'object_name': 'Currency'},
            'code': ('django.db.models.fields.CharField', [], {'max_length': '8', 'primary_key': 'True'}),
            'exchange_rate': ('django.db.models.fields.DecimalField', [], {'null': 'True', 'max_digits': '15', 'decimal_places': '8'}),
            'last_checked': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime(1900, 1, 1, 0, 0)', 'db_index': 'True'}),
            'rate_timestamp': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime(1900, 1, 1, 0, 0)', 'db_index': 'True'}),
            'symbol': ('django.db.models.fields.CharField', [], {'max_length': '8'})
        },
        'inventory.festival': {
            'Meta': {'ordering': "('name', 'start')", 'unique_together': "(('series', 'edition'),)", 'object_name': 'Festival'},
            'airport_code': ('django.db.models.fields.CharField', [], {'max_length': '3', 'blank': 'True'}),
            'alert_cta': ('django.db.models.fields.CharField', [], {'max_length': '50', 'blank': 'True'}),
            'alert_landing_page': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'alert_landing_page_for'", 'null': 'True', 'to': u"orm['website.PromoLandingPage']"}),
            'alert_target_url': ('django.db.models.fields.CharField', [], {'max_length': '200', 'blank': 'True'}),
            'alert_text': ('django.db.models.fields.CharField', [], {'max_length': '300', 'blank': 'True'}),
            'allow_no_accomodation': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'aw_commission_group_if_inclusive': ('django.db.models.fields.CharField', [], {'max_length': '100', 'blank': 'True'}),
            'aw_commission_group_if_ticket_only': ('django.db.models.fields.CharField', [], {'max_length': '100', 'blank': 'True'}),
            'background_picture': ('util.models.BetterImageField', [], {'max_length': '100', 'blank': 'True'}),
            'baseline': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'bizdev_rep': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'bizdev_rep_for'", 'null': 'True', 'on_delete': 'models.PROTECT', 'to': u"orm['community.User']"}),
            'capacity': ('django.db.models.fields.PositiveIntegerField', [], {'null': 'True', 'blank': 'True'}),
            'card_image': ('util.models.BetterImageField', [], {'max_length': '100', 'blank': 'True'}),
            'card_size': ('django.db.models.fields.IntegerField', [], {'default': '1'}),
            'checkin_date': ('django.db.models.fields.DateField', [], {'null': 'True', 'blank': 'True'}),
            'checkout_date': ('django.db.models.fields.DateField', [], {'null': 'True', 'blank': 'True'}),
            'content_rep': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'content_rep_for'", 'null': 'True', 'on_delete': 'models.PROTECT', 'to': u"orm['community.User']"}),
            'date_created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'db_index': 'True'}),
            'date_unconfirmed': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'description': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'edition': ('django.db.models.fields.CharField', [], {'db_index': 'True', 'max_length': '100', 'blank': 'True'}),
            'emergency_contact_email': ('django.db.models.fields.CharField', [], {'max_length': '200', 'blank': 'True'}),
            'emergency_contact_name': ('django.db.models.fields.CharField', [], {'max_length': '100', 'blank': 'True'}),
            'emergency_contact_phone': ('django.db.models.fields.CharField', [], {'max_length': '100', 'blank': 'True'}),
            'end': ('django.db.models.fields.DateField', [], {'db_index': 'True'}),
            'featured': ('django.db.models.fields.BooleanField', [], {'default': 'True', 'db_index': 'True'}),
            'from_price_pp': ('django.db.models.fields.DecimalField', [], {'null': 'True', 'max_digits': '9', 'decimal_places': '3'}),
            'go_euro_location_code': ('django.db.models.fields.CharField', [], {'max_length': '10', 'blank': 'True'}),
            'hotel_rep': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'hotel_rep_for'", 'null': 'True', 'on_delete': 'models.PROTECT', 'to': u"orm['community.User']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'initial_zoom': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'blank': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True', 'db_index': 'True'}),
            'listed': ('django.db.models.fields.BooleanField', [], {'default': 'True', 'db_index': 'True'}),
            'location': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "'festival'", 'null': 'True', 'on_delete': 'models.PROTECT', 'to': "orm['inventory.Location']", 'blank': 'True', 'unique': 'True'}),
            'logo': ('util.models.BetterImageField', [], {'max_length': '100', 'blank': 'True'}),
            'marketing_rep': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'marketing_rep_for'", 'null': 'True', 'on_delete': 'models.PROTECT', 'to': u"orm['community.User']"}),
            'max_people_offer': ('django.db.models.fields.IntegerField', [], {'default': '2'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100', 'db_index': 'True'}),
            'override_discount': ('django.db.models.fields.DecimalField', [], {'null': 'True', 'max_digits': '5', 'decimal_places': '2', 'blank': 'True'}),
            'product_rep': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'product_rep_for'", 'null': 'True', 'on_delete': 'models.PROTECT', 'to': u"orm['community.User']"}),
            'related': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "'related_from'", 'blank': 'True', 'through': "orm['inventory.RelatedFestival']", 'to': "orm['inventory.Festival']"}),
            'restricted_countries': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "'restricted_festivals'", 'blank': 'True', 'to': u"orm['countries.Country']"}),
            'send_post_festival_email': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'series': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'festivals'", 'null': 'True', 'on_delete': 'models.PROTECT', 'to': "orm['inventory.FestivalSeries']"}),
            'slug': ('django.db.models.fields.SlugField', [], {'unique': 'True', 'max_length': '50'}),
            'start': ('django.db.models.fields.DateField', [], {'db_index': 'True'}),
            'tags': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "'festivals'", 'blank': 'True', 'to': "orm['inventory.Tag']"}),
            'taxes': ('django.db.models.fields.DecimalField', [], {'null': 'True', 'max_digits': '8', 'decimal_places': '2', 'blank': 'True'}),
            'the_status': ('django.db.models.fields.CharField', [], {'max_length': '20', 'db_index': 'True'}),
            'thumb_large': ('util.models.BetterImageField', [], {'max_length': '100', 'blank': 'True'}),
            'use_fallback_html_lineup': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'visuals': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "'festivals'", 'blank': 'True', 'to': "orm['inventory.Visual']"}),
            'website': ('django.db.models.fields.CharField', [], {'max_length': '200', 'blank': 'True'})
        },
        'inventory.festivalseries': {
            'Meta': {'ordering': "('name',)", 'object_name': 'FestivalSeries'},
            'date_created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'db_index': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '255', 'db_index': 'True'})
        },
        'inventory.location': {
            'Meta': {'ordering': "('name',)", 'object_name': 'Location'},
            'address': ('django.db.models.fields.CharField', [], {'max_length': '100', 'blank': 'True'}),
            'city': ('django.db.models.fields.CharField', [], {'db_index': 'True', 'max_length': '50', 'blank': 'True'}),
            'country': ('countries.fields.CountryField', [], {'to': u"orm['countries.Country']", 'null': 'True', 'blank': 'True'}),
            'directions': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'info': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100', 'blank': 'True'}),
            'point': ('django.contrib.gis.db.models.fields.PointField', [], {'null': 'True', 'blank': 'True'}),
            'postcode': ('django.db.models.fields.CharField', [], {'db_index': 'True', 'max_length': '50', 'blank': 'True'})
        },
        'inventory.relatedfestival': {
            'Meta': {'ordering': "('position', 'festival')", 'object_name': 'RelatedFestival'},
            'description': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'festival': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'+'", 'on_delete': 'models.PROTECT', 'to': "orm['inventory.Festival']"}),
            'from_festival': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'related_festivals'", 'to': "orm['inventory.Festival']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'position': ('django.db.models.fields.PositiveIntegerField', [], {'db_index': 'True'})
        },
        'inventory.tag': {
            'Meta': {'ordering': "('name',)", 'object_name': 'Tag'},
            'active': ('django.db.models.fields.BooleanField', [], {'default': 'True', 'db_index': 'True'}),
            'date_created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'db_index': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'}),
            'slug': ('django.db.models.fields.SlugField', [], {'unique': 'True', 'max_length': '50'}),
            'type': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'tags'", 'on_delete': 'models.PROTECT', 'to': "orm['inventory.TagType']"})
        },
        'inventory.tagtype': {
            'Meta': {'ordering': "('name',)", 'object_name': 'TagType'},
            'date_created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'db_index': 'True'}),
            'icon': ('util.models.FontIconField', [], {'max_length': '100', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'}),
            'slug': ('django.db.models.fields.SlugField', [], {'unique': 'True', 'max_length': '50'})
        },
        'inventory.visual': {
            'Meta': {'ordering': "('position', 'name')", 'object_name': 'Visual'},
            'caption': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'date_created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'db_index': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'image': ('util.models.BetterImageField', [], {'max_length': '100'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '255', 'db_index': 'True'}),
            'position': ('django.db.models.fields.IntegerField', [], {'default': '10', 'db_index': 'True'}),
            'video': ('django.db.models.fields.CharField', [], {'max_length': '255'})
        },
        u'partner.partner': {
            'Meta': {'ordering': "('name',)", 'object_name': 'Partner'},
            'account_manager': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'account_manager_for'", 'null': 'True', 'on_delete': 'models.PROTECT', 'to': u"orm['community.User']"}),
            'active': ('django.db.models.fields.BooleanField', [], {'default': 'True', 'db_index': 'True'}),
            'additional_displayed_festivals': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "'additional_partners_displayed_to'", 'blank': 'True', 'to': "orm['inventory.Festival']"}),
            'affiliate_terms': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'code': ('django.db.models.fields.SlugField', [], {'unique': 'True', 'max_length': '200'}),
            'contact_email': ('django.db.models.fields.CharField', [], {'max_length': '200', 'blank': 'True'}),
            'contact_first_name': ('django.db.models.fields.CharField', [], {'max_length': '100', 'blank': 'True'}),
            'contact_last_name': ('django.db.models.fields.CharField', [], {'max_length': '100', 'blank': 'True'}),
            'date_created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'date_password_changed': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'default_currency': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'default_for_partners'", 'null': 'True', 'on_delete': 'models.SET_NULL', 'to': u"orm['currency.Currency']"}),
            'description': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'featured': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'db_index': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'null': 'True'}),
            'listed': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'db_index': 'True'}),
            'logo': ('util.models.BetterImageField', [], {'max_length': '100', 'blank': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '200', 'db_index': 'True'}),
            'notes': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'paid_affiliate': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'password': ('django.db.models.fields.CharField', [], {'default': "u'!3qqVmJBl4XzBKtad1BMnvs13sdlA55ixLZT0kPKu'", 'max_length': '128'}),
            'type': ('django.db.models.fields.CharField', [], {'db_index': 'True', 'max_length': '20', 'blank': 'True'}),
            'url': ('django.db.models.fields.CharField', [], {'max_length': '200', 'blank': 'True'})
        },
        'shop.discount': {
            'Meta': {'ordering': "('-start',)", 'object_name': 'Discount'},
            'allow_ticket_only': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'amount': ('django.db.models.fields.DecimalField', [], {'null': 'True', 'max_digits': '8', 'decimal_places': '2', 'blank': 'True'}),
            'barred_countries': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "'barred_discounts'", 'blank': 'True', 'to': u"orm['countries.Country']"}),
            'barred_festivals': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "'barred_discounts'", 'blank': 'True', 'to': "orm['inventory.Festival']"}),
            'currency': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['currency.Currency']", 'null': 'True', 'on_delete': 'models.PROTECT', 'blank': 'True'}),
            'date_created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'db_index': 'True'}),
            'end': ('django.db.models.fields.DateField', [], {'db_index': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True', 'db_index': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'one_time_use': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'packages': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "'discounts'", 'blank': 'True', 'to': "orm['shop.Package']"}),
            'percentage': ('django.db.models.fields.DecimalField', [], {'null': 'True', 'max_digits': '6', 'decimal_places': '3', 'blank': 'True'}),
            'start': ('django.db.models.fields.DateField', [], {'default': 'datetime.datetime.now', 'db_index': 'True'})
        },
        'shop.package': {
            'Meta': {'ordering': "('best_price_pp',)", 'unique_together': "(('slug', 'festival'),)", 'object_name': 'Package'},
            'additional_conditions': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'available': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'db_index': 'True'}),
            'begin_offer_override': ('django.db.models.fields.DateField', [], {'null': 'True', 'blank': 'True'}),
            'best_price_pp': ('django.db.models.fields.DecimalField', [], {'null': 'True', 'max_digits': '9', 'decimal_places': '3', 'db_index': 'True'}),
            'best_priced_pp': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "'best_priced_for'", 'unique': 'True', 'null': 'True', 'on_delete': 'models.SET_NULL', 'to': "orm['shop.SpecificPackage']"}),
            'currency': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'packages'", 'on_delete': 'models.PROTECT', 'to': u"orm['currency.Currency']"}),
            'custom': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'db_index': 'True'}),
            'description': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'end_offer_override': ('django.db.models.fields.DateField', [], {'null': 'True', 'blank': 'True'}),
            'festival': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'packages'", 'to': "orm['inventory.Festival']"}),
            'force_status': ('django.db.models.fields.CharField', [], {'max_length': '15', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'image': ('util.models.BetterImageField', [], {'max_length': '100', 'blank': 'True'}),
            'intro': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'listed_on_festicket': ('django.db.models.fields.BooleanField', [], {'default': 'True', 'db_index': 'True'}),
            'listed_on_whitelabel': ('django.db.models.fields.BooleanField', [], {'default': 'True', 'db_index': 'True'}),
            'max_nights': ('django.db.models.fields.PositiveSmallIntegerField', [], {'null': 'True'}),
            'max_people': ('django.db.models.fields.PositiveSmallIntegerField', [], {'db_index': 'True'}),
            'min_nights': ('django.db.models.fields.PositiveSmallIntegerField', [], {'null': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100', 'db_index': 'True'}),
            'position': ('django.db.models.fields.PositiveIntegerField', [], {'default': '10', 'db_index': 'True'}),
            'price_pp_varies': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'require_birthdays': ('django.db.models.fields.NullBooleanField', [], {'null': 'True', 'blank': 'True'}),
            'require_id_number': ('django.db.models.fields.NullBooleanField', [], {'null': 'True', 'blank': 'True'}),
            'require_phone': ('django.db.models.fields.NullBooleanField', [], {'null': 'True', 'blank': 'True'}),
            'ribbon': ('django.db.models.fields.CharField', [], {'max_length': '15', 'blank': 'True'}),
            'slug': ('django.db.models.fields.SlugField', [], {'max_length': '50'}),
            'the_status': ('django.db.models.fields.CharField', [], {'max_length': '20', 'db_index': 'True'}),
            'ticket_only': ('django.db.models.fields.BooleanField', [], {'default': 'False', 'db_index': 'True'})
        },
        'shop.specificpackage': {
            'Meta': {'ordering': "('num_people',)", 'object_name': 'SpecificPackage'},
            'current_price_base': ('django.db.models.fields.DecimalField', [], {'default': '0', 'max_digits': '9', 'decimal_places': '3', 'db_index': 'True'}),
            'current_price_pp_base': ('django.db.models.fields.DecimalField', [], {'default': '0', 'max_digits': '9', 'decimal_places': '3', 'db_index': 'True'}),
            'end': ('django.db.models.fields.DateField', [], {'null': 'True'}),
            'fee': ('django.db.models.fields.DecimalField', [], {'max_digits': '8', 'decimal_places': '2', 'db_index': 'True'}),
            'generated': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'max_nights': ('django.db.models.fields.PositiveSmallIntegerField', [], {'null': 'True'}),
            'min_nights': ('django.db.models.fields.PositiveSmallIntegerField', [], {'null': 'True'}),
            'nights': ('django.db.models.fields.PositiveSmallIntegerField', [], {'default': '0'}),
            'num_people': ('django.db.models.fields.PositiveSmallIntegerField', [], {'db_index': 'True'}),
            'package': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'specific_packages'", 'to': "orm['shop.Package']"}),
            'price': ('django.db.models.fields.DecimalField', [], {'max_digits': '8', 'decimal_places': '2', 'db_index': 'True'}),
            'start': ('django.db.models.fields.DateField', [], {'null': 'True'}),
            'the_status': ('django.db.models.fields.CharField', [], {'max_length': '20', 'db_index': 'True'})
        },
        u'waffle.flag': {
            'Meta': {'object_name': 'Flag'},
            'authenticated': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'db_index': 'True'}),
            'everyone': ('django.db.models.fields.NullBooleanField', [], {'null': 'True', 'blank': 'True'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Group']", 'symmetrical': 'False', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'languages': ('django.db.models.fields.TextField', [], {'default': "''", 'blank': 'True'}),
            'modified': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'}),
            'note': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'on_or_off_for_users': ('django.db.models.fields.related.ManyToManyField', [], {'related_name': "'on_or_off_for_users'", 'symmetrical': 'False', 'through': u"orm['waffle.UserFeatureFlags']", 'to': u"orm['community.User']"}),
            'percent': ('django.db.models.fields.DecimalField', [], {'null': 'True', 'max_digits': '3', 'decimal_places': '1', 'blank': 'True'}),
            'rollout': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'staff': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'superusers': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'testing': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'users': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['community.User']", 'symmetrical': 'False', 'blank': 'True'})
        },
        u'waffle.sample': {
            'Meta': {'object_name': 'Sample'},
            'created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'db_index': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'modified': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'}),
            'note': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'percent': ('django.db.models.fields.DecimalField', [], {'max_digits': '4', 'decimal_places': '1'})
        },
        u'waffle.switch': {
            'Meta': {'object_name': 'Switch'},
            'active': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'db_index': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'modified': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'}),
            'note': ('django.db.models.fields.TextField', [], {'blank': 'True'})
        },
        u'waffle.userfeatureflags': {
            'Meta': {'unique_together': "(('user', 'flag'),)", 'object_name': 'UserFeatureFlags'},
            'flag': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['waffle.Flag']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['community.User']"})
        },
        u'website.promolandingpage': {
            'Meta': {'ordering': "('title',)", 'object_name': 'PromoLandingPage'},
            'available': ('django.db.models.fields.BooleanField', [], {'default': 'True', 'db_index': 'True'}),
            'background': ('util.models.BetterImageField', [], {'max_length': '100', 'blank': 'True'}),
            'callout': ('django.db.models.fields.TextField', [], {}),
            'campaign': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'}),
            'discount': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['shop.Discount']", 'null': 'True', 'on_delete': 'models.PROTECT', 'blank': 'True'}),
            'festivals_displayed': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "'promo_landing_pages'", 'blank': 'True', 'to': "orm['inventory.Festival']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'mailchimp_list_id': ('django.db.models.fields.CharField', [], {'max_length': '200', 'blank': 'True'}),
            'new_customers_only': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'post_submit_copy': ('django.db.models.fields.CharField', [], {'max_length': '500'}),
            'post_submit_url': ('django.db.models.fields.CharField', [], {'max_length': '200'}),
            'slug': ('django.db.models.fields.SlugField', [], {'unique': 'True', 'max_length': '50'}),
            'text': ('django.db.models.fields.TextField', [], {}),
            'title': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        }
    }

    complete_apps = ['waffle']