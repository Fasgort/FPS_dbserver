from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone

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
	
	def __str__(self):
		return self.user_name + " (ID: " + str(self.ID_user) + ")"
	
	class Meta:
		db_table = 'users'


class FPS(models.Model):
	ID_FPS = models.IntegerField(primary_key=True)
	signup_date = models.DateTimeField('Date of registration')
	location = models.CharField(max_length=200)
	group_access = models.IntegerField()
	
	def __str__(self):
		return self.location + " (ID: " + str(self.ID_FPS) + ")"
	
	class Meta:
		db_table = 'fps'


class Log(models.Model):
	ID_log = models.AutoField(primary_key=True)
	ID_user = models.ForeignKey(User, on_delete=models.CASCADE, db_column='ID_user')
	ID_FPS = models.ForeignKey(FPS, on_delete=models.CASCADE, db_column='ID_FPS')
	date = models.DateTimeField('Scan date')
	access_granted = models.IntegerField()

	def __str__(self):
		if self.access_granted == 1:
			return "Log #" + str(self.ID_log) + ":  user ID " + str(self.ID_user.ID_user) + " accessed FPS #" + str(self.ID_FPS.ID_FPS) + " and was GRANTED access. Date: " + self.date.astimezone(tz=timezone.get_current_timezone()).ctime()
		else:
			return "Log #" + str(self.ID_log) + ":  user ID " + str(self.ID_user.ID_user) + " accessed FPS #" + str(self.ID_FPS.ID_FPS) + " and was DENIED access. Date: " + self.date.astimezone(tz=timezone.get_current_timezone()).ctime()

	class Meta:
		db_table = 'log'