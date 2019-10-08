from django.contrib import admin

from .models import User, FPS, Log

admin.site.register(User)
admin.site.register(FPS)
admin.site.register(Log)
