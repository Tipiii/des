from django.db import models
from django.contrib.auth.models import User

class Message(models.Model):
    sender = models.ForeignKey(User, related_name='sent', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received', on_delete=models.CASCADE)
    plaintext = models.TextField(default="No plaintext")
    ciphertext = models.TextField()
    des_key = models.BinaryField()  # NEW: lưu khóa DES dạng bytes
    created_at = models.DateTimeField(auto_now_add=True)
    image_cipher = models.BinaryField(null=True, blank=True)  # Ảnh đã mã hóa
    
    def __str__(self):
        return f"Từ {self.sender} tới {self.receiver} - {self.created_at}"
