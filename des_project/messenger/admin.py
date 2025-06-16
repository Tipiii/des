
from django.contrib import admin
from .models import Message

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('sender', 'receiver', 'created_at', 'short_ciphertext')

    def short_ciphertext(self, obj):
        return obj.ciphertext[:30] + '...'
    short_ciphertext.short_description = 'Ciphertext'

    list_display = ('sender', 'receiver', 'created_at', 'short_ciphertext', 'display_des_key')

    def display_des_key(self, obj):
        return obj.des_key.hex()
    display_des_key.short_description = 'DES Key'

