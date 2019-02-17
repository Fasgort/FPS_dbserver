from django.db import models
from django.core.exceptions import ValidationError

def validate_maxusers(value):
    if value >= 200: # change to 3000 if using GT-521F52
        raise ValidationError(
            _('%(value)s is over the max users FPS limit.'),
            params={'value': value},
        )

class User(models.Model):
	ID_user = models.IntegerField(primary_key=True, validators=[validate_maxusers])
	user_name = models.CharField(max_length=200)
	group_user = models.IntegerField()
	fingerprint_data = models.BinaryField()
	fingerprint_hash = models.IntegerField()
	fingerprint_scan_date = models.DateTimeField('Date of last scan')
	
	class Meta:
		db_table = 'users'


class FPS(models.Model):
	ID_FPS = models.IntegerField(primary_key=True)
	signup_date = models.DateTimeField('Date of registration')
	location = models.CharField(max_length=200)
	group_access = models.IntegerField()
	
	class Meta:
		db_table = 'fps'


class Log(models.Model):
	ID_log = models.AutoField(primary_key=True)
	ID_user = models.ForeignKey(User, on_delete=models.CASCADE, db_column='ID_user')
	ID_FPS = models.ForeignKey(FPS, on_delete=models.CASCADE, db_column='ID_FPS')
	date = models.DateTimeField('Scan date')
	access_granted = models.IntegerField()

	class Meta:
		db_table = 'log'